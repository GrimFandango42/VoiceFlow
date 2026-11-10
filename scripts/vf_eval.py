#!/usr/bin/env python
"""VF-17 scenario evaluation: a before/after table with measured numbers.

    python scripts/vf_eval.py                 # full run (needs Ollama for the reconstruction columns)
    python scripts/vf_eval.py --no-llm        # audio/ASR/text stages only
    python scripts/vf_eval.py --asr-model tiny.en --scenarios tail,noise
    make vf-eval ARGS="--no-llm"

Nothing here launches the app, touches a microphone, uses the GPU, or writes to
the live data directory. Speech comes from Windows SAPI (offline TTS) plus
synthetic noise; ASR is faster-whisper on CPU from the local model cache
(``local_files_only``); reconstruction goes to the local Ollama on CPU. The live
corpus is only READ, and only counts / scores are printed (never dictation text).

BEFORE vs AFTER
    before  = base behaviour: pause_compaction_tail_protect_ms=0, no tail pad,
              no reconstruction
    after   = this branch's defaults: tail protection on, plus the reconstruction
              pass (guards on) where an Ollama model is available. "after" for
              the reconstruction columns is the text the user ends up with if
              they swap the improved version in (the async path), or the pasted
              text when it finished inside the budget.

METRICS
    WER      word error rate vs the scripted reference (normalised: lower-case,
             punctuation stripped). Lower is better.
    tail     tail-word retention: share of utterances whose last reference word
             is the last hypothesis word.
    legible  proxy: share of sentences that start capitalised, end with terminal
             punctuation, do not end on a dangling function word, and contain no
             immediate word repeat. Not computed for the tail scenario, whose
             references deliberately trail off mid-clause.

LIMITATIONS (also in docs/FAITHFUL_DICTATION.md)
    * TTS speech is cleaner and more regular than Nithin's real voice/accent.
    * ASR here is small.en on CPU; the live app runs distil-large-v3 on CUDA.
    * The app's "retry on raw audio after heavy compaction" step is not replayed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import types
import wave
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

SR = 16000

# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

DANGLING = frozenset(
    "and or but the a an of to in on at for with that is are was were if so because by from as than then my your our "
    "their his her its this these those which who not no".split()
)


def norm_words(text: str) -> List[str]:
    return re.findall(r"[a-z0-9']+", text.lower().replace("-", " ").replace("’", "'"))


def wer(reference: str, hypothesis: str) -> float:
    ref, hyp = norm_words(reference), norm_words(hypothesis)
    if not ref:
        return 0.0 if not hyp else 1.0
    prev = list(range(len(hyp) + 1))
    for i, r in enumerate(ref, 1):
        cur = [i]
        for j, h in enumerate(hyp, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (r != h)))
        prev = cur
    return prev[-1] / float(len(ref))


def tail_kept(reference: str, hypothesis: str) -> bool:
    ref, hyp = norm_words(reference), norm_words(hypothesis)
    return bool(ref) and bool(hyp) and ref[-1] == hyp[-1]


#: A comma followed by one of these, after a clause of >= 4 words, is read as a comma splice
#: ("..., the vendor contract renews", "..., thanks everyone"): two sentences glued together.
CLAUSE_STARTERS = frozenset(
    "the a an we i you they he she it this that there these those my our your their his her its please thanks thank".split()
)
CONJUNCTIVE_ADVERBS = frozenset("otherwise however therefore instead meanwhile furthermore moreover finally".split())
RUN_ON_WORDS = 35


def is_run_on(sentence: str) -> bool:
    """Proxy for a run-on: one 'sentence' that is very long, or has a comma splice."""
    if len(norm_words(sentence)) > RUN_ON_WORDS:
        return True
    if ";" in sentence:
        return False  # a semicolon is a deliberate join, not a splice
    pieces = sentence.split(",")
    seen = 0
    for k, piece in enumerate(pieces):
        seen += len(norm_words(piece))
        nxt = norm_words(pieces[k + 1]) if k + 1 < len(pieces) else []
        if norm_words(piece)[-1:] and norm_words(piece)[-1] in CONJUNCTIVE_ADVERBS:
            continue  # "..., otherwise, we hold it" / "..., however, the team"
        if nxt and seen >= 4 and nxt[0] in CLAUSE_STARTERS and len(nxt) >= 3:
            # "if X, we ..." / "when X, the ..." is a normal subordinate clause, not a splice
            first = norm_words(pieces[0])[:1]
            if first and first[0] in {"if", "when", "while", "although", "though", "because", "since", "after", "before", "once", "unless", "as"} and k == 0:
                continue
            return True
    return False


def legibility(text: str) -> float:
    sentences = [s.strip() for s in re.findall(r"[^.!?]+[.!?]*", text or "") if s.strip()]
    if not sentences:
        return 0.0
    good = 0
    for s in sentences:
        words = norm_words(s)
        starts = s[0].isupper() or not s[0].isalpha()
        ends = s.rstrip()[-1:] in ".!?"
        dangling = bool(words) and words[-1] in DANGLING
        repeat = bool(re.search(r"\b(\w+)\s+\1\b", s, re.I))
        good += bool(starts and ends and not dangling and not repeat and not is_run_on(s))
    return good / float(len(sentences))


def pct(x: float) -> str:
    return f"{100.0 * x:5.1f}%"


# --------------------------------------------------------------------------- #
# Scenarios (scripted references; no digits so WER is not about number formatting)
# --------------------------------------------------------------------------- #

@dataclass
class Utterance:
    reference: str                       # full reference text
    parts: List[Tuple[str, float]]       # (text, gap_seconds_before)
    gain: List[float] = field(default_factory=list)  # per-part gain (default 1.0)
    rate: int = 0
    snr_db: Optional[float] = None


def _single(text: str, **kw: Any) -> Utterance:
    return Utterance(reference=text, parts=[(text, 0.0)], **kw)


def _paused(parts: Sequence[str], gaps: Sequence[float]) -> Utterance:
    seq = [(p, 0.0 if i == 0 else float(gaps[i - 1])) for i, p in enumerate(parts)]
    return Utterance(reference=" ".join(parts), parts=seq)


def _tail(head: str, tail: str, gain: float, gap: float = 5.0) -> Utterance:
    return Utterance(reference=f"{head} {tail}", parts=[(head, 0.0), (tail, gap)], gain=[1.0, gain])


SCENARIOS: Dict[str, Tuple[str, List[Utterance]]] = {
    "pauses": ("long dictation, 5-20 s pauses", [
        _paused(["Let me start with the budget review for the quarter.",
                 "The vendor contract renews in March and we should renegotiate the support tier.",
                 "I also want to move the planning meeting to Thursday afternoon so everyone can attend.",
                 "That is about all I have for now."], [6, 11, 16]),
        _paused(["First thing tomorrow I will send the draft to Maya and the rest of the team.",
                 "If the numbers look fine we can ship the release on Friday.",
                 "Otherwise we hold it until the next sprint and tell the customers why."], [8, 14]),
        _paused(["Quick reminder about the offsite logistics.",
                 "The shuttle leaves at nine and the lunch is catered on site.",
                 "Please confirm your dietary needs by the end of the week.",
                 "Thanks everyone and see you there."], [5, 9, 20]),
    ]),
    "fast": ("fast speech", [
        _single(t, rate=7) for t in (
            "I think we should move the review to Thursday and then send the notes to the whole team before lunch.",
            "The build finished early so I started the tests and they are all passing right now.",
            "Can you check the invoice from the vendor and let me know if the totals match the purchase order.",
            "We need to book the flights soon because the prices usually go up as the date gets closer.",
            "Please remind Maya that the budget draft is due on Friday and the slides are due on Monday.",
        )
    ]),
    "noise": ("background noise (SNR 6 dB)", [
        _single(t, snr_db=6.0) for t in (
            "Please send me the latest version of the report when you get a chance.",
            "The meeting has moved to the small conference room on the second floor.",
            "I will call the customer this afternoon and explain what happened with the order.",
            "We should check the settings again before we start the next test run.",
            "Let me know if you need anything else before the end of the day.",
        )
    ]),
    "technical": ("dense technical vocabulary", [
        _single(t) for t in (
            "We package the app with PyInstaller and run the model through Ollama on the CPU.",
            "The faster-whisper backend uses CTranslate2 and the Silero voice activity detector.",
            "Deploy the service to Kubernetes and keep the state in PostgreSQL.",
            "The TypeScript client talks to the FastAPI server over WebSocket.",
            "Open the GitHub issue and tag it for the Claude Code agent.",
        )
    ]),
    "tail": ("utterance ends in a short word", [
        _tail(head, tail, gain)
        for gain in (0.35, 0.18, 0.10)
        for head, tail in (
            ("Everything is on track for the launch next week", "and that"),
            ("We should wrap up the review by the end", "of the"),
            ("The numbers look fine to me", "is good"),
            ("I will send the notes tomorrow morning", "and then"),
            ("Please call the vendor about the invoice", "if you can"),
            ("The meeting went well and we agreed on the plan", "for now"),
        )
    ]),
}

#: Vocabulary the user would plausibly have curated; shared by Whisper's prompt
#: and the reconstruction pass, identical for before and after.
EVAL_VOCAB = [
    "PyInstaller", "Ollama", "faster-whisper", "CTranslate2", "Silero", "Kubernetes", "PostgreSQL",
    "TypeScript", "FastAPI", "WebSocket", "GitHub", "Claude Code", "Maya",
]

# --------------------------------------------------------------------------- #
# Speech + audio synthesis (offline)
# --------------------------------------------------------------------------- #

class Tts:
    def __init__(self, cache: Path) -> None:
        self.cache = cache
        self._voice = None

    def _sapi(self):
        import win32com.client  # type: ignore

        if self._voice is None:
            self._voice = win32com.client.Dispatch("SAPI.SpVoice")
        return win32com.client

    def say(self, text: str, rate: int = 0) -> np.ndarray:
        key = hashlib.sha1(f"{text}|{rate}".encode()).hexdigest()[:16]
        path = self.cache / f"tts_{key}.npy"
        if path.exists():
            return np.load(path)
        com = self._sapi()
        stream = com.Dispatch("SAPI.SpFileStream")
        fmt = com.Dispatch("SAPI.SpAudioFormat")
        fmt.Type = 22
        wav_path = self.cache / f"tts_{key}.wav"
        stream.Format = fmt
        stream.Open(str(wav_path), 3, False)
        self._voice.AudioOutputStream = stream
        self._voice.Rate = rate
        self._voice.Speak(text)
        stream.Close()
        with wave.open(str(wav_path), "rb") as w:
            raw, sr = w.readframes(w.getnframes()), w.getframerate()
        wav_path.unlink(missing_ok=True)
        a = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
        if sr != SR:
            a = np.interp(np.linspace(0, len(a) - 1, int(len(a) * SR / sr)), np.arange(len(a)), a).astype(np.float32)
        idx = np.where(np.abs(a) > 0.004)[0]
        a = a[: idx[-1] + 1] if len(idx) else a  # key released right at the word edge
        np.save(path, a)
        return a


def _noise(sec: float, sigma: float, rng: np.random.Generator) -> np.ndarray:
    return (rng.standard_normal(int(sec * SR)) * sigma).astype(np.float32)


def _pinkish(n: int, rng: np.random.Generator) -> np.ndarray:
    spec = np.fft.rfft(rng.standard_normal(n))
    freqs = np.fft.rfftfreq(n, 1 / SR)
    spec[1:] /= np.sqrt(freqs[1:] / 100.0 + 1.0)
    out = np.fft.irfft(spec, n)
    return (out / (np.std(out) + 1e-9)).astype(np.float32)


def build_audio(utt: Utterance, tts: Tts, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    floor = 0.0004
    pieces: List[np.ndarray] = [_noise(0.4, floor, rng)]
    for i, (text, gap) in enumerate(utt.parts):
        if gap > 0:
            pieces.append(_noise(gap, floor, rng))
        speech = tts.say(text, utt.rate)
        gain = utt.gain[i] if utt.gain else 1.0
        pieces.append(speech * gain + (rng.standard_normal(len(speech)) * floor).astype(np.float32))
    pieces.append(_noise(0.35, floor, rng))  # ptt_tail_buffer_seconds hangover
    audio = np.concatenate(pieces).astype(np.float32)
    if utt.snr_db is not None:
        speech_rms = float(np.sqrt(np.mean(audio[np.abs(audio) > 0.01] ** 2))) or 0.05
        sigma = speech_rms / (10 ** (utt.snr_db / 20.0))
        t = np.arange(len(audio)) / SR
        audio = audio + sigma * (0.8 * _pinkish(len(audio), rng) + 0.2 * np.sin(2 * np.pi * 120 * t).astype(np.float32))
    return np.clip(audio, -1.0, 1.0).astype(np.float32)


# --------------------------------------------------------------------------- #
# Pipeline stages (the same functions the app calls)
# --------------------------------------------------------------------------- #

def make_cfg(tail_protect_ms: int, tail_pad_ms: int = 0, tail_lift_db: float = 0.0):
    from voiceflow.core.config import Config

    cfg = Config()
    cfg.pause_compaction_tail_protect_ms = tail_protect_ms
    cfg.asr_tail_pad_ms = tail_pad_ms
    cfg.asr_tail_lift_db = tail_lift_db
    return cfg


def prepare_audio(audio: np.ndarray, cfg) -> Tuple[np.ndarray, float]:
    from voiceflow.core.audio_preprocessing import AudioPreprocessor
    from voiceflow.ui.cli_enhanced import EnhancedApp

    from voiceflow.core.asr_engine import lift_quiet_tail

    processed = AudioPreprocessor(cfg).process(audio)
    compacted = EnhancedApp._compact_pauses(types.SimpleNamespace(cfg=cfg), processed)
    reduction = 100.0 * (1.0 - len(compacted) / max(1, len(processed)))
    # ASREngine.transcribe applies the same leveler to whatever it is handed; the harness calls the model
    # directly, so it mirrors that step here (0 dB = off = base behaviour).
    return lift_quiet_tail(compacted, SR, max_gain_db=float(cfg.asr_tail_lift_db)), reduction


class Asr:
    def __init__(self, model_name: str, cache: Path) -> None:
        from faster_whisper import WhisperModel
        from voiceflow.core import vocab

        self.name = model_name
        self.model = WhisperModel(model_name, device="cpu", compute_type="int8", local_files_only=True)
        self.prompt = ", ".join(list(dict.fromkeys(EVAL_VOCAB + list(vocab.INITIAL_PROMPT_TERMS))))[:700]
        self.cache_path = cache / f"asr_{model_name.replace('/', '_')}.json"
        self.cache: Dict[str, str] = json.loads(self.cache_path.read_text()) if self.cache_path.exists() else {}

    def transcribe(self, audio: np.ndarray, pad_ms: int = 0) -> str:
        if pad_ms:
            audio = np.concatenate([audio, np.zeros(int(SR * pad_ms / 1000), np.float32)])
        key = hashlib.sha1(audio.tobytes() + self.prompt.encode()).hexdigest()
        if key in self.cache:
            return self.cache[key]
        beam = 2 if len(audio) / SR >= 12.0 else 1  # the app's long-form lift
        segs, _ = self.model.transcribe(
            audio, language="en", beam_size=beam, without_timestamps=True, vad_filter=False, initial_prompt=self.prompt
        )
        text = " ".join(s.text.strip() for s in segs).strip()
        self.cache[key] = text
        self.cache_path.write_text(json.dumps(self.cache))
        return text


def text_pipeline(raw: str, duration: float) -> str:
    """normalise -> format -> safe second pass: what the app does before the reconstruction stage."""
    from voiceflow.core import textproc

    text = textproc.normalize_context_terms(raw)
    text = textproc.format_transcript_for_destination(text, destination={}, audio_duration=duration)
    return textproc.apply_second_pass_cleanup(text, heavy=False)


# --------------------------------------------------------------------------- #
# Reconstruction (real Ollama, CPU only)
# --------------------------------------------------------------------------- #

class Recon:
    def __init__(self, cache: Path, model: str = "") -> None:
        from voiceflow.ai.reconstruction import Reconstructor
        from voiceflow.ai.llm_client import OllamaClient

        probe = OllamaClient()
        self.available = probe.is_available()
        self.model = ""
        if self.available:
            from voiceflow.ai.reconstruction import pick_reconstruction_model

            self.model = pick_reconstruction_model(probe.list_models(), model)
            self.available = bool(self.model)
        cfg = types.SimpleNamespace(reconstruction_enabled=True, reconstruction_mode="async", reconstruction_model=self.model,
                                    reconstruction_min_words=4, reconstruction_max_chars=2000, reconstruction_timeout_s=120.0,
                                    reconstruction_num_threads=0)
        self.reconstructor = Reconstructor(cfg, vocab_provider=lambda: list(EVAL_VOCAB))
        if self.available:
            probe.model = self.model
            self.reconstructor._client = probe
        self.cache_path = cache / "recon_v2.json"
        self.cache: Dict[str, Dict[str, Any]] = json.loads(self.cache_path.read_text()) if self.cache_path.exists() else {}
        self.latencies_ms: List[float] = []
        self.statuses: Dict[str, int] = {}

    def run(self, pre: str, raw: str) -> Tuple[str, Dict[str, Any]]:
        """Model replies are cached; the guards always run fresh, so guard changes are re-scored without new LLM calls."""
        from voiceflow.ai.reconstruction import SYSTEM_PROMPT, Proposal

        key = hashlib.sha1(f"{self.model}|{SYSTEM_PROMPT}|{pre}".encode()).hexdigest()
        rec = self.cache.get(key)
        if rec is None:
            prop = self.reconstructor.propose(pre)
            rec = {"status": prop.status, "candidate": prop.candidate, "latency_ms": prop.latency_ms, "error": prop.error}
            if prop.status == "ok":
                self.cache[key] = rec
                self.cache_path.write_text(json.dumps(self.cache))
        outcome = self.reconstructor.judge(
            pre, raw, Proposal(rec["status"], rec["candidate"], rec.get("error", ""), float(rec["latency_ms"]), self.model)
        )
        if outcome.status in {"accepted", "rejected", "unchanged"}:
            self.latencies_ms.append(outcome.latency_ms)
        label = outcome.status if outcome.status != "rejected" else f"rejected:{outcome.reason}"
        self.statuses[label] = self.statuses.get(label, 0) + 1
        info = {"status": outcome.status, "reason": outcome.reason, "text": outcome.text, "latency_ms": outcome.latency_ms}
        return (outcome.text if outcome.accepted else pre), info


# --------------------------------------------------------------------------- #
# Scenario runner
# --------------------------------------------------------------------------- #

def run_scenario(key: str, tts: Tts, asr: Asr, recon: Optional[Recon]) -> Dict[str, Any]:
    title, utterances = SCENARIOS[key]
    before_cfg, after_cfg, protect_cfg = make_cfg(0), make_cfg(1500, tail_lift_db=9.0), make_cfg(1500)
    rows: List[Dict[str, Any]] = []
    for n, utt in enumerate(utterances):
        audio = build_audio(utt, tts, seed=1000 + n)
        a_b, red_b = prepare_audio(audio, before_cfg)
        a_a, red_a = prepare_audio(audio, after_cfg)
        raw_b = asr.transcribe(a_b)
        raw_a = asr.transcribe(a_a) if len(a_a) != len(a_b) else raw_b
        pre_b = text_pipeline(raw_b, len(a_b) / SR)
        pre_a = text_pipeline(raw_a, len(a_a) / SR)
        row = {
            "dur_s": round(len(audio) / SR, 1),
            "compacted_before_s": round(len(a_b) / SR, 1),
            "compacted_after_s": round(len(a_a) / SR, 1),
            "wer_before": wer(utt.reference, pre_b),
            "wer_after_audio": wer(utt.reference, pre_a),
            "tail_before": tail_kept(utt.reference, pre_b),
            "tail_after_audio": tail_kept(utt.reference, pre_a),
            "legible_before": legibility(pre_b),
            "legible_after_audio": legibility(pre_a),
        }
        if key == "tail":  # ablations: protection without the lift; the pad=N knob that did not help
            a_p, _ = prepare_audio(audio, protect_cfg)
            prot = text_pipeline(asr.transcribe(a_p), len(a_p) / SR)
            row["wer_protect"], row["tail_protect"] = wer(utt.reference, prot), tail_kept(utt.reference, prot)
            padded = text_pipeline(asr.transcribe(a_b, pad_ms=400), len(a_b) / SR)
            row["wer_pad400"], row["tail_pad400"] = wer(utt.reference, padded), tail_kept(utt.reference, padded)
            both = text_pipeline(asr.transcribe(a_a, pad_ms=400), len(a_a) / SR)
            row["wer_both"], row["tail_both"] = wer(utt.reference, both), tail_kept(utt.reference, both)
        if recon is not None and recon.available:
            final, rec = recon.run(pre_a, raw_a)
            row.update(
                wer_after=wer(utt.reference, final), tail_after=tail_kept(utt.reference, final),
                legible_after=legibility(final), recon_status=rec["status"], recon_reason=rec["reason"],
                reference=utt.reference, pre_text=pre_a, final_text=final,  # synthetic text; safe to keep in the report
            )
        rows.append(row)

    def mean(field_name: str) -> Optional[float]:
        vals = [r[field_name] for r in rows if field_name in r]
        return float(np.mean(vals)) if vals else None

    return {"key": key, "title": title, "n": len(rows), "rows": rows, **{
        k: mean(k) for k in (
            "wer_before", "wer_after_audio", "wer_after", "wer_protect", "tail_protect", "wer_pad400", "tail_before", "tail_after_audio", "tail_after",
            "tail_pad400", "wer_both", "tail_both", "legible_before", "legible_after_audio", "legible_after",
        )}}


# --------------------------------------------------------------------------- #
# Window switch + real-corpus replay
# --------------------------------------------------------------------------- #

def run_window_switch() -> Dict[str, Any]:
    """Focus leaves the target mid-dictation: the text must not be lost, and replace-last-paste must refuse."""
    from voiceflow.core.config import Config
    from voiceflow.integrations import inject as inject_mod

    clipboard: List[str] = []
    sent: List[str] = []
    inject_mod.keyboard.send = lambda seq: sent.append(seq)  # type: ignore[assignment]
    inject_mod.keyboard.write = lambda text, delay=0: sent.append("WRITE:" + text)  # type: ignore[assignment]
    inject_mod.pyperclip.copy = lambda s: clipboard.append(s)  # type: ignore[assignment]
    inject_mod.pyperclip.paste = lambda: ""  # type: ignore[assignment]

    cfg = Config(paste_injection=True, restore_clipboard=False, inject_refocus_attempts=1, inject_refocus_delay_ms=0,
                 min_inject_interval_ms=0)
    inj = inject_mod.ClipboardInjector(cfg)
    inj._target_hwnd = 100
    fg = {"hwnd": 200}
    inj._foreground_window = lambda: fg["hwnd"]  # type: ignore[method-assign]
    text = "Please send the notes to the team after the meeting."

    ok = inj.inject(text)  # focus is on another window
    preserved = (not ok) and bool(inj.copy_text_to_clipboard(text)) and clipboard[-1].strip() == text

    # A paste that did land, then the user switches windows before asking for the improved version.
    fg["hwnd"] = 100
    inj._key_counter_live = True
    sent.clear()
    inj.inject(text)
    fg["hwnd"] = 300
    verdict = inj.replace_last_paste(text, text + " (improved)")
    refused = verdict == "clipboard:window_changed" and "backspace" not in sent
    return {"text_preserved": bool(preserved), "replace_refused_after_switch": bool(refused), "verdict": verdict}


def _live_dir() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "VoiceFlow"


def run_corpus(recon: Optional[Recon], limit: int) -> Dict[str, Any]:
    """Replay over the real captured corpus. READ-ONLY; prints counts and scores, never text."""
    from voiceflow.ai import hotword_promotion
    from voiceflow.ai.adaptive_memory import extract_learning_pairs
    from voiceflow.core import vocab

    live = _live_dir()
    out: Dict[str, Any] = {"live_dir_present": live.exists()}
    audit = live / "adaptive_audit.jsonl"
    rows: List[Dict[str, Any]] = []
    if audit.exists():
        for line in audit.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    with_text = [r for r in rows if r.get("raw_text") and r.get("final_text")]
    truncated = [r for r in with_text if int(r.get("raw_chars", 0)) > len(r.get("raw_text", ""))]
    differing = [r for r in with_text if r.get("raw_hash") != r.get("final_hash")]
    pair_count = sum(len(extract_learning_pairs(r["raw_text"], r["final_text"])) for r in differing)
    out["audit"] = {
        "rows": len(rows), "with_text": len(with_text), "truncated_at_200": len(truncated),
        "raw_ne_final": len(differing), "learned_pairs_recorded": sum(len(r.get("learned_pairs", [])) for r in rows),
        "learnable_word_pairs_in_raw_ne_final": pair_count,
    }

    # Hotword yield over what the corpus really contains (no reconstruction data exists yet in the live log).
    pseudo = [{"id": str(i), "raw_text": r["raw_text"], "final_text": r["final_text"]} for i, r in enumerate(with_text)]
    report, _ = hotword_promotion.analyse(pseudo, vocab_terms=vocab.known_terms(500), min_count=3)
    out["hotword_yield_audit_only"] = report.as_dict()

    tuning = live / "tuning_log.jsonl"
    if tuning.exists():
        from voiceflow.ai.tuning_log import TuningLog

        utts = TuningLog(tuning).load_utterances()
        rep, _ = hotword_promotion.analyse(utts, vocab_terms=vocab.known_terms(500), min_count=3)
        out["hotword_yield_tuning_log"] = rep.as_dict()
    else:
        out["hotword_yield_tuning_log"] = "no tuning_log.jsonl yet (written by the app once this branch runs)"

    hist = live / "recent_history_events.jsonl"
    texts: List[str] = []
    if hist.exists():
        for line in hist.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                t = str(json.loads(line).get("full_text", "") or "").strip()
            except Exception:
                continue
            if len(norm_words(t)) >= 4:
                texts.append(t)
    out["history"] = {"events_with_text": len(texts), "legible_mean": float(np.mean([legibility(t) for t in texts])) if texts else None}

    if recon is not None and recon.available and texts:
        sample = texts[-limit:]
        before, after, statuses = [], [], {}
        for t in sample:
            final, rec = recon.run(t, t)
            before.append(legibility(t)); after.append(legibility(final))
            label = rec["status"] if rec["status"] != "rejected" else f"rejected:{rec['reason']}"
            statuses[label] = statuses.get(label, 0) + 1
        out["replay"] = {
            "sampled": len(sample), "legible_before": float(np.mean(before)), "legible_after": float(np.mean(after)),
            "accepted": statuses.get("accepted", 0), "statuses": statuses,
        }
    return out


# --------------------------------------------------------------------------- #
# Latency of the two paths
# --------------------------------------------------------------------------- #

def measure_paths(recon: Recon, samples: List[str]) -> Dict[str, Any]:
    from voiceflow.ai.reconstruction import percentile
    from voiceflow.ai.reconstruction_runtime import ReconstructionCoordinator

    cfg = types.SimpleNamespace(reconstruction_enabled=True, reconstruction_mode="auto", reconstruction_budget_ms=800,
                                reconstruction_timeout_s=120.0, reconstruction_min_words=4, reconstruction_max_chars=2000)
    coord = ReconstructionCoordinator(cfg, recon.reconstructor)
    async_added: List[float] = []
    for text in samples:
        t0 = time.perf_counter()
        job = coord.begin(text, text)
        wait = coord.sync_wait_s()
        if job is not None:
            job.wait(wait)  # auto mode: wait == 0 until the model proves it fits
        async_added.append((time.perf_counter() - t0) * 1000.0)
        if job is not None:
            job.future.result(timeout=180)  # let it finish before the next dictation, as a user would
    sync_ms = coord.latency.snapshot()  # fresh model calls made just above, not cached ones
    return {
        "samples": len(samples),
        "model": recon.model,
        "sync_path_added_ms": {"p50": percentile(sync_ms, 0.5), "p95": percentile(sync_ms, 0.95)},
        "async_path_added_ms": {"p50": percentile(async_added, 0.5), "p95": percentile(async_added, 0.95)},
        "auto_mode_sync_wait_after_run_s": coord.sync_wait_s(),
        "budget_ms": 800,
    }


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def fmt(v: Optional[float], pct_mode: bool = True) -> str:
    if v is None:
        return "   n/a"
    return pct(v) if pct_mode else f"{v:.3f}"


def print_table(results: List[Dict[str, Any]], have_llm: bool) -> str:
    lines: List[str] = []
    head = "| scenario | n | WER before | WER after | tail before | tail after | legible before | legible after |"
    lines += [head, "|---|---|---|---|---|---|---|---|"]
    for r in results:
        wer_after = r["wer_after"] if (have_llm and r.get("wer_after") is not None) else r["wer_after_audio"]
        tail_after = r["tail_after"] if (have_llm and r.get("tail_after") is not None) else r["tail_after_audio"]
        leg_after = r["legible_after"] if (have_llm and r.get("legible_after") is not None) else r["legible_after_audio"]
        leg_b = "  n/a" if r["key"] == "tail" else fmt(r["legible_before"])
        leg_a = "  n/a" if r["key"] == "tail" else fmt(leg_after)
        lines.append(
            f"| {r['title']} | {r['n']} | {fmt(r['wer_before'])} | {fmt(wer_after)} | {fmt(r['tail_before'])} | "
            f"{fmt(tail_after)} | {leg_b} | {leg_a} |"
        )
    return "\n".join(lines)


WINDOW_CHECKS = ("text_preserved", "replace_refused_after_switch")


def window_failures(window: Optional[Dict[str, Any]]) -> List[str]:
    """The window-switch scenario is a gate too: a missing or false result is a failure, never a silent pass."""
    window = window or {}
    if window.get("error"):
        return [f"window switch: scenario crashed ({window['error']})"]
    return [f"window switch: {name} is {window.get(name)!r}, expected True" for name in WINDOW_CHECKS if window.get(name) is not True]


def acceptance_failures(results: List[Dict[str, Any]], have_llm: bool, window: Optional[Dict[str, Any]] = None,
                        check_window: bool = False) -> List[str]:
    """VF-17 acceptance gates over the per-fixture rows. Empty list = pass.

    - no fixture may get a worse WER, lose a tail word it used to keep, or become less legible;
    - the "utterance ends in a short word" scenario must retain 100 % of its tail words;
    - no scenario's mean WER may rise;
    - when ``check_window`` is set (main() always sets it), the window-switch scenario must have kept the text and refused
      replace-last-paste after the switch.
    "After" is the full pipeline when the reconstruction columns were measured, else the audio side only.
    """
    fails: List[str] = window_failures(window) if check_window else []
    eps = 1e-9
    for r in results:
        full = bool(have_llm and r["rows"] and "wer_after" in r["rows"][0])
        if full:
            wer_f, tail_f, leg_f = "wer_after", "tail_after", "legible_after"
        else:
            wer_f, tail_f, leg_f = "wer_after_audio", "tail_after_audio", "legible_after_audio"

        def mean(field_name: str) -> float:
            return float(np.mean([row[field_name] for row in r["rows"]])) if r["rows"] else 0.0

        for i, row in enumerate(r["rows"]):
            tag = f"{r['key']}[{i}]"
            if row[wer_f] > row["wer_before"] + eps:
                fails.append(f"{tag}: WER regressed {pct(row['wer_before'])} -> {pct(row[wer_f])}")
            if row["tail_before"] and not row[tail_f]:
                fails.append(f"{tag}: tail word lost that the base kept")
            if r["key"] != "tail" and row[leg_f] < row["legible_before"] - eps:
                fails.append(f"{tag}: legibility regressed {pct(row['legible_before'])} -> {pct(row[leg_f])}")
        if r["key"] == "tail" and mean(tail_f) < 1.0 - eps:
            fails.append(f"tail: retention {pct(mean(tail_f))} < 100.0%")
        if mean(wer_f) > mean("wer_before") + eps:
            fails.append(f"{r['key']}: mean WER rose {pct(mean('wer_before'))} -> {pct(mean(wer_f))}")
    return fails


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenarios", default="pauses,fast,noise,technical,tail", help="comma list of: " + ",".join(SCENARIOS))
    ap.add_argument("--asr-model", default="small.en", help="faster-whisper model from the local cache (default small.en)")
    ap.add_argument("--no-llm", action="store_true", help="skip the reconstruction columns (no Ollama needed)")
    ap.add_argument("--llm-model", default="", help="Ollama model (default: auto-pick a small instruct model)")
    ap.add_argument("--corpus-limit", type=int, default=12, help="real-history utterances to run reconstruction on")
    ap.add_argument("--no-gate", action="store_true", help="print the acceptance verdict but always exit 0")
    ap.add_argument("--no-corpus", action="store_true", help="skip the real-corpus replay")
    ap.add_argument("--cache-dir", default=str(Path(tempfile.gettempdir()) / "voiceflow_vf_eval"))
    ap.add_argument("--out", default="", help="write the full JSON result here")
    args = ap.parse_args(argv)

    cache = Path(args.cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    # Isolate from the machine's own vocabulary file so results are reproducible.
    empty_vocab = cache / "empty_vocab.txt"
    empty_vocab.write_text("", encoding="utf-8")
    os.environ["VOICEFLOW_VOCABULARY_PATH"] = str(empty_vocab)

    started = time.time()
    tts, asr = Tts(cache), Asr(args.asr_model, cache)
    recon = None if args.no_llm else Recon(cache, args.llm_model)
    if recon is not None and not recon.available:
        print("[vf_eval] Ollama / a suitable model is not available: reconstruction columns skipped", file=sys.stderr)
    have_llm = bool(recon and recon.available)

    results: List[Dict[str, Any]] = []
    for key in [k.strip() for k in args.scenarios.split(",") if k.strip()]:
        if key not in SCENARIOS:
            print(f"unknown scenario {key!r}", file=sys.stderr)
            return 2
        print(f"[vf_eval] {key} ...", file=sys.stderr, flush=True)
        results.append(run_scenario(key, tts, asr, recon if have_llm else None))

    try:
        window = run_window_switch()
    except Exception as exc:  # a crashed scenario must fail the gate, not the report
        window = {"error": f"{type(exc).__name__}: {exc}"}
    corpus = None if args.no_corpus else run_corpus(recon if have_llm else None, args.corpus_limit)
    paths = None
    if have_llm:
        samples = [r_text for r_text in (
            "so i think we need to move the review to thursday and then send the notes to the team after lunch",
            "we build it with pie installer and run all llama on the cpu so the gpu stays free for the robot",
            "can you check the invoice from the vendor and let me know if the totals match the purchase order",
            "the meeting went well and we agreed to ship on friday if the tests are green",
            "please remind maya that the budget draft is due and the slides are due the day after",
            "i will call the customer this afternoon and explain what happened with the order",
        )]
        paths = measure_paths(recon, samples)  # type: ignore[arg-type]

    table = print_table(results, have_llm)
    print("\n## VF-17 scenario evaluation\n")
    print(f"ASR: faster-whisper {args.asr_model} (CPU, int8, local cache)   |   reconstruction: "
          f"{recon.model if have_llm else 'not run'} via Ollama (CPU)\n")
    print(table)
    if have_llm:
        print("\nreconstruction outcomes:", json.dumps(recon.statuses))  # type: ignore[union-attr]
    tail = next((r for r in results if r["key"] == "tail"), None)
    if tail:
        print("\ntail scenario, the four audio-side configurations (ASR only, no reconstruction):")
        print("| config | WER | tail retention |\n|---|---|---|")
        for label, w, t in (
            ("base (no protection, no pad)", "wer_before", "tail_before"),
            ("tail protection only (compaction keeps the last 1.5 s)", "wer_protect", "tail_protect"),
            ("tail protection + quiet-tail lift (this branch)", "wer_after_audio", "tail_after_audio"),
            ("pad 400 ms only", "wer_pad400", "tail_pad400"),
            ("protection + lift + pad 400 ms", "wer_both", "tail_both"),
        ):
            print(f"| {label} | {fmt(tail.get(w))} | {fmt(tail.get(t))} |")
    print("\nwindow switch:", json.dumps(window))
    if corpus:
        print("\nreal corpus (counts only):", json.dumps(corpus, indent=2, default=str))
    if paths:
        print("\nadded latency, reconstruction paths:", json.dumps(paths, indent=2))
    print(f"\n(elapsed {time.time() - started:.0f}s)")
    failures = acceptance_failures(results, have_llm, window, check_window=True)
    if failures:
        print("\nACCEPTANCE: FAIL")
        for f in failures:
            print(f"  - {f}")
    else:
        print("\nACCEPTANCE: PASS (no fixture regressed; tail retention 100% where measured; window-switch safeguards held)")

    if args.out:
        Path(args.out).write_text(json.dumps({"results": results, "window": window, "corpus": corpus, "paths": paths,
                                              "table": table, "acceptance_failures": failures}, indent=2, default=str), encoding="utf-8")
    return 0 if (args.no_gate or not failures) else 1


if __name__ == "__main__":
    raise SystemExit(main())
