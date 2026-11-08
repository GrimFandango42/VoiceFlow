"""Pause-based segmentation for long dictations, plus decode-time right context.

Why this exists (VF-12)
-----------------------
A 3-5 minute recording with long thinking pauses used to go to Whisper as ONE
call. Inside that call faster-whisper slides 30 s windows over the audio, and:

* ``initial_prompt`` (the user's vocabulary) is only part of the *first* window's
  prompt when ``condition_on_previous_text`` is off (it is, past 30 s), so every
  later window decodes with less vocabulary bias than the first;
* a window that is mostly silence is where "Thank you." and repeat loops come
  from;
* the last window gets no look-ahead, so the final word of the utterance is the
  least reliable one.

This module cuts the recording at its own pauses instead, so each decode call
gets (a) real speech only, (b) the same prompt and hotwords, and (c) a little
room-tone either side of the words. Nothing here loads a model.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# (start_sample, end_sample), end exclusive
Region = Tuple[int, int]


@dataclass
class SegmentPlan:
    """One slice of the recording to decode on its own."""

    start: int
    end: int
    #: Seconds of silence between the previous segment's speech and this one's.
    gap_before_s: float = 0.0


@dataclass
class SegmentPiece:
    text: str
    gap_before_s: float
    start_s: float
    end_s: float
    suppressed: str = ""  # non-empty = decoded text was dropped, with the reason


@dataclass
class SegmentedTranscript:
    text: str
    pieces: List[SegmentPiece] = field(default_factory=list)
    #: Non-empty when segmentation was not trusted and the whole recording was decoded in
    #: one call instead ("no_speech_found" / "too_little_speech").
    fallback_reason: str = ""

    @property
    def segment_count(self) -> int:
        return len(self.pieces)

    @property
    def suppressed_count(self) -> int:
        return sum(1 for p in self.pieces if p.suppressed)


# --------------------------------------------------------------------------
# Speech detection (energy based; the same idea as EnhancedApp._compact_pauses
# but reusable and returning regions instead of a rebuilt buffer)
# --------------------------------------------------------------------------

def _frame_rms(audio: np.ndarray, frame_len: int) -> np.ndarray:
    usable = (len(audio) // frame_len) * frame_len
    if usable <= 0:
        return np.zeros(0, dtype=np.float64)
    framed = audio[:usable].astype(np.float64).reshape(-1, frame_len)
    return np.sqrt(np.mean(framed * framed, axis=1))


def _speech_threshold(rms: np.ndarray, base_threshold: float) -> float:
    noise_floor = float(np.percentile(rms, 20))
    loud = float(np.percentile(rms, 95))
    return max(base_threshold * 1.6, noise_floor * 2.6, loud * 0.06)


def find_speech_regions(
    audio: np.ndarray,
    sample_rate: int,
    *,
    frame_ms: int = 30,
    min_speech_ms: int = 120,
    merge_gap_ms: int = 300,
    base_threshold: float = 5e-4,
) -> List[Region]:
    """Return speech regions in samples.

    Runs shorter than ``min_speech_ms`` (clicks, chair creaks) are dropped; runs
    separated by less than ``merge_gap_ms`` (breaths, between-word gaps) are merged
    so a sentence stays in one piece.
    """
    if audio is None or len(audio) == 0:
        return []
    frame_len = max(1, int(sample_rate * frame_ms / 1000.0))
    rms = _frame_rms(audio, frame_len)
    if rms.size == 0:
        return []
    thr = _speech_threshold(rms, base_threshold)
    speech = rms >= thr
    if not np.any(speech):
        return []

    runs: List[List[int]] = []
    i, n = 0, len(speech)
    while i < n:
        if speech[i]:
            j = i
            while j < n and speech[j]:
                j += 1
            runs.append([i, j])
            i = j
        else:
            i += 1

    merge_gap = max(1, int(merge_gap_ms / frame_ms))
    merged: List[List[int]] = []
    for run in runs:
        if merged and run[0] - merged[-1][1] <= merge_gap:
            merged[-1][1] = run[1]
        else:
            merged.append(run)

    min_frames = max(1, int(min_speech_ms / frame_ms))
    regions: List[Region] = []
    for a, b in merged:
        if (b - a) >= min_frames:
            regions.append((a * frame_len, min(len(audio), b * frame_len)))
    return regions


def _split_overlong(
    region: Region, audio: np.ndarray, sample_rate: int, max_samples: int, frame_len: int
) -> List[Region]:
    """Cut a continuous run of speech longer than ``max_samples`` at its quietest points."""
    start, end = region
    out: List[Region] = []
    while end - start > max_samples:
        lo = start + int(max_samples * 0.7)
        hi = start + max_samples
        window = audio[lo:hi]
        rms = _frame_rms(window, frame_len)
        if rms.size:
            cut = lo + int(np.argmin(rms)) * frame_len + frame_len // 2
        else:
            cut = hi
        out.append((start, cut))
        start = cut
    out.append((start, end))
    return out


def plan_segments(
    audio: np.ndarray,
    sample_rate: int,
    *,
    max_segment_seconds: float = 25.0,
    split_gap_seconds: float = 2.0,
    pad_ms: int = 350,
    frame_ms: int = 30,
    min_speech_ms: int = 120,
    merge_gap_ms: int = 300,
    base_threshold: float = 5e-4,
) -> List[SegmentPlan]:
    """Cut ``audio`` into decode segments at pauses.

    Segments hold whole speech regions only, are at most ``max_segment_seconds``
    of speech, and carry ``pad_ms`` of surrounding audio (never reaching into the
    neighbouring segment's speech) so words keep their right and left context.
    Silence between segments is dropped, which is what stops the decoder from
    inventing text there.
    """
    regions = find_speech_regions(
        audio,
        sample_rate,
        frame_ms=frame_ms,
        min_speech_ms=min_speech_ms,
        merge_gap_ms=merge_gap_ms,
        base_threshold=base_threshold,
    )
    return plan_from_regions(
        regions,
        audio,
        sample_rate,
        max_segment_seconds=max_segment_seconds,
        split_gap_seconds=split_gap_seconds,
        pad_ms=pad_ms,
        frame_ms=frame_ms,
    )


def plan_from_regions(
    regions: Sequence[Region],
    audio: np.ndarray,
    sample_rate: int,
    *,
    max_segment_seconds: float = 25.0,
    split_gap_seconds: float = 2.0,
    pad_ms: int = 350,
    frame_ms: int = 30,
) -> List[SegmentPlan]:
    """Group already-detected speech ``regions`` into padded decode segments."""
    if not regions:
        return []

    max_samples = max(sample_rate, int(max_segment_seconds * sample_rate))
    frame_len = max(1, int(sample_rate * frame_ms / 1000.0))
    pieces: List[Region] = []
    for region in regions:
        pieces.extend(_split_overlong(region, audio, sample_rate, max_samples, frame_len))

    # Greedy grouping: keep adding speech regions while the segment stays under the cap
    # AND the silence between them is short. A long pause always starts a new segment,
    # otherwise that silence would be handed to the decoder inside the segment.
    split_gap = int(max(0.0, split_gap_seconds) * sample_rate)
    groups: List[List[int]] = []
    for start, end in pieces:
        if groups and (end - groups[-1][0]) <= max_samples and (start - groups[-1][1]) <= split_gap:
            groups[-1][1] = end
        else:
            groups.append([start, end])

    pad = int(sample_rate * pad_ms / 1000.0)
    total = len(audio)
    plans: List[SegmentPlan] = []
    for idx, (start, end) in enumerate(groups):
        prev_end = groups[idx - 1][1] if idx > 0 else None
        next_start = groups[idx + 1][0] if idx + 1 < len(groups) else None
        left = max(0, start - pad)
        if prev_end is not None:
            left = max(left, prev_end + (start - prev_end) // 2)
        right = min(total, end + pad)
        if next_start is not None:
            right = min(right, end + (next_start - end) // 2)
        gap = 0.0 if prev_end is None else max(0.0, (start - prev_end) / float(sample_rate))
        plans.append(SegmentPlan(start=int(left), end=int(right), gap_before_s=gap))
    return plans


# --------------------------------------------------------------------------
# Speech evidence from a real VAD (Silero, bundled with faster-whisper)
# --------------------------------------------------------------------------

_vad_warned = False


def vad_speech_regions(audio: np.ndarray, sample_rate: int, cfg=None) -> Optional[List[Region]]:
    """Speech regions (samples) found by Silero VAD, or ``None`` when VAD cannot run.

    ``None`` means "no evidence either way" and callers fall back to the energy detector;
    an empty list means "VAD ran and heard no speech". Whisper's own ``no_speech_prob`` is not
    a substitute: on stationary noise it reports about 0.04 while still emitting "I think.
    Thank you." (VF-12 review finding 1), so the decode of audio VAD calls speechless is
    never trusted.
    """
    global _vad_warned
    if not bool(getattr(cfg, "silence_vad_gate_enabled", True)):
        return None
    if audio is None or len(audio) == 0:
        return []
    if int(sample_rate) != 16000:          # Silero is trained for 16 kHz only
        return None
    try:
        from faster_whisper.vad import VadOptions, get_speech_timestamps

        opts = VadOptions(
            threshold=float(getattr(cfg, "silence_vad_threshold", 0.5)),
            min_speech_duration_ms=int(getattr(cfg, "silence_vad_min_chunk_ms", 100)),
            min_silence_duration_ms=300,
            speech_pad_ms=100,
        )
        stamps = get_speech_timestamps(np.asarray(audio, dtype=np.float32), opts, sampling_rate=16000)
    except Exception as exc:  # missing onnxruntime / asset, bad build: degrade, but say so once
        if not _vad_warned:
            _vad_warned = True
            logger.warning("silence_vad_unavailable error=%s: using energy detection only", exc)
        return None
    n = len(audio)
    return [(max(0, int(t["start"])), min(n, int(t["end"]))) for t in stamps if int(t["end"]) > int(t["start"])]


def _overlap_samples(regions: Sequence[Region], start: int, end: int) -> int:
    return sum(max(0, min(end, b) - max(start, a)) for a, b in regions)


# --------------------------------------------------------------------------
# Right context
# --------------------------------------------------------------------------

def room_tone(audio: np.ndarray, sample_rate: int, seconds: float, *, seed: int = 0) -> np.ndarray:
    """Low-level noise matching the quietest part of ``audio``.

    Not digital zero: exact silence is itself a hallucination trigger for Whisper.
    Deterministic for a given seed so results are reproducible.
    """
    n = int(max(0.0, seconds) * sample_rate)
    if n <= 0:
        return np.zeros(0, dtype=np.float32)
    level = 1e-4
    if audio is not None and len(audio) >= int(0.1 * sample_rate):
        rms = _frame_rms(audio, max(1, int(0.02 * sample_rate)))
        if rms.size:
            level = float(np.clip(np.percentile(rms, 10) * 0.8, 1e-4, 0.01))
    rng = np.random.default_rng(seed)
    return (rng.standard_normal(n) * level).astype(np.float32)


def pad_right_context(audio: np.ndarray, sample_rate: int, seconds: float) -> np.ndarray:
    """Append ``seconds`` of room tone so the last word is not the last thing heard."""
    if audio is None or len(audio) == 0 or seconds <= 0:
        return audio
    tone = room_tone(audio, sample_rate, seconds)
    return np.concatenate((np.asarray(audio, dtype=np.float32), tone))


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------

#: decode(audio) -> text. ``no_speech_prob`` is read from the engine afterwards.
DecodeFn = Callable[[np.ndarray], str]


def _result_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(getattr(value, "text", "") or "")


def decode_audio(engine, audio: np.ndarray, cfg=None) -> str:
    """Decode ``audio`` with ``engine`` after adding right context.

    The single funnel every final decode goes through, so the right-context padding
    cannot be forgotten at one call site.
    """
    sample_rate = int(getattr(cfg, "sample_rate", 16000) or 16000)
    seconds = float(getattr(cfg, "decode_right_context_seconds", 0.4) or 0.0)
    padded = pad_right_context(audio, sample_rate, seconds)
    return _result_text(engine.transcribe(padded))


def should_segment(duration_s: float, cfg=None) -> bool:
    if not bool(getattr(cfg, "segmented_transcription_enabled", True)):
        return False
    return duration_s >= float(getattr(cfg, "segmented_min_audio_seconds", 20.0))


def transcribe_segmented(
    engine,
    audio: np.ndarray,
    cfg=None,
    *,
    log: Optional[logging.Logger] = None,
) -> SegmentedTranscript:
    """Decode ``audio`` pause by pause with one engine and join the pieces.

    Pauses of ``paragraph_pause_seconds`` or more become a blank line between
    pieces. Pieces the silence-artifact classifier rejects ("Thank you." with a
    high ``no_speech_prob``, repeat loops) are dropped and recorded.
    """
    from voiceflow.core.silence_artifacts import classify

    log = log or logger
    sample_rate = int(getattr(cfg, "sample_rate", 16000) or 16000)
    plans = plan_segments(
        audio,
        sample_rate,
        max_segment_seconds=float(getattr(cfg, "segment_max_seconds", 25.0)),
        split_gap_seconds=float(getattr(cfg, "segment_split_gap_seconds", 2.0)),
        pad_ms=int(getattr(cfg, "segment_pad_ms", 350)),
        base_threshold=float(getattr(cfg, "min_rms_amplitude", 5e-4)),
    )
    # Guardrail: an energy detector can be fooled (loud room tone, very quiet speaker). If it
    # finds nothing, or implausibly little, quietly dropping the "silence" would drop words;
    # decode the whole recording in one call instead, as before segmentation existed.
    covered = sum(p.end - p.start for p in plans)
    min_fraction = float(getattr(cfg, "segment_min_speech_fraction", 0.05))
    vad_regions = vad_speech_regions(audio, sample_rate, cfg)
    min_vad_s = float(getattr(cfg, "silence_vad_min_speech_seconds", 0.25))
    if not plans or covered < min_fraction * max(1, len(audio)):
        reason = "no_speech_found" if not plans else "too_little_speech"
        log.info("segmentation_fallback reason=%s covered_s=%.1f total_s=%.1f", reason,
                 covered / float(sample_rate), len(audio) / float(sample_rate))
        if vad_regions is not None:
            vad_s = sum(b - a for a, b in vad_regions) / float(sample_rate)
            if vad_s < min_vad_s:
                # Real VAD heard no speech: nothing here is worth decoding, and decoding stationary
                # noise is exactly what produces "I think. Thank you." with a low no_speech_prob.
                log.info("segmentation_fallback_vad_no_speech vad_speech_s=%.2f", vad_s)
                return SegmentedTranscript(text="", fallback_reason="no_speech_vad")
            # VAD found speech the energy detector missed (quiet speaker, loud room): decode just
            # those regions, not the whole recording of noise around them.
            plans = plan_from_regions(
                vad_regions,
                audio,
                sample_rate,
                max_segment_seconds=float(getattr(cfg, "segment_max_seconds", 25.0)),
                split_gap_seconds=float(getattr(cfg, "segment_split_gap_seconds", 2.0)),
                pad_ms=int(getattr(cfg, "segment_pad_ms", 350)),
            )
            log.info("segmentation_fallback_vad_regions pieces=%d vad_speech_s=%.2f", len(plans), vad_s)
            result = _decode_plans(engine, audio, plans, cfg, log, vad_regions=vad_regions,
                                   min_vad_s=min_vad_s)
            result.fallback_reason = reason
            return result
        text = decode_audio(engine, audio, cfg).strip()
        # The whole-recording decode must not bypass the silence-artifact guard: a recording
        # that really is silence otherwise comes back as "Thank you." (review finding 3).
        no_speech = float(getattr(engine, "last_no_speech_prob", 0.0) or 0.0)
        suppress, why = classify(text, no_speech_prob=no_speech)
        if suppress:
            if why != "empty":
                log.info("segmentation_fallback_suppressed reason=%s", why)
            text = ""
        return SegmentedTranscript(text=text, fallback_reason=reason)

    return _decode_plans(engine, audio, plans, cfg, log, vad_regions=vad_regions, min_vad_s=min_vad_s)


def _decode_plans(
    engine,
    audio: np.ndarray,
    plans: Sequence[SegmentPlan],
    cfg,
    log: logging.Logger,
    *,
    vad_regions: Optional[Sequence[Region]],
    min_vad_s: float,
) -> SegmentedTranscript:
    """Decode each planned piece and join them (paragraph break at long pauses)."""
    from voiceflow.core.silence_artifacts import classify

    sample_rate = int(getattr(cfg, "sample_rate", 16000) or 16000)
    paragraph_gap = float(getattr(cfg, "paragraph_pause_seconds", 2.5))
    right_context = float(getattr(cfg, "decode_right_context_seconds", 0.4))

    pieces: List[SegmentPiece] = []
    for plan in plans:
        start_s = plan.start / float(sample_rate)
        end_s = plan.end / float(sample_rate)
        overlap = _overlap_samples(vad_regions, plan.start, plan.end) if vad_regions is not None else None
        if overlap == 0:
            # Energy found a "segment" but VAD heard no speech anywhere in it (a clatter, a cough,
            # a fan surge). Whisper invents text for such audio and its no_speech_prob does not
            # reliably say so, so the piece is not decoded at all.
            log.info("segment_suppressed reason=vad_no_speech start=%.1f end=%.1f", start_s, end_s)
            pieces.append(SegmentPiece(text="", gap_before_s=plan.gap_before_s, start_s=start_s,
                                       end_s=end_s, suppressed="vad_no_speech"))
            continue
        chunk = audio[plan.start:plan.end]
        text = _result_text(engine.transcribe(pad_right_context(chunk, sample_rate, right_context))).strip()
        no_speech = float(getattr(engine, "last_no_speech_prob", 0.0) or 0.0)
        suspected = overlap is not None and overlap < min_vad_s * sample_rate
        suppress, reason = classify(text, no_speech_prob=no_speech, non_speech_suspected=suspected)
        piece = SegmentPiece(
            text="" if suppress else text,
            gap_before_s=plan.gap_before_s,
            start_s=start_s,
            end_s=end_s,
            suppressed=reason if suppress else "",
        )
        if suppress and reason != "empty":
            log.info("segment_suppressed reason=%s start=%.1f end=%.1f", reason, piece.start_s, piece.end_s)
        pieces.append(piece)

    out: List[str] = []
    pending_gap = 0.0
    for piece in pieces:
        pending_gap += piece.gap_before_s
        if not piece.text:
            continue
        if out:
            out.append("\n\n" if pending_gap >= paragraph_gap else " ")
        out.append(piece.text)
        pending_gap = 0.0
    return SegmentedTranscript(text="".join(out).strip(), pieces=list(pieces))


def decode_for_duration(engine, audio: np.ndarray, cfg=None, log: Optional[logging.Logger] = None) -> str:
    """Final-decode entry point: segmented for long recordings, padded single call otherwise."""
    sample_rate = int(getattr(cfg, "sample_rate", 16000) or 16000)
    duration = len(audio) / float(sample_rate) if audio is not None else 0.0
    if should_segment(duration, cfg):
        result = transcribe_segmented(engine, audio, cfg, log=log)
        (log or logger).info(
            "segmented_decode duration=%.1f segments=%d suppressed=%d fallback=%s",
            duration,
            result.segment_count,
            result.suppressed_count,
            result.fallback_reason or "none",
        )
        return result.text
    return decode_audio(engine, audio, cfg)


__all__: Sequence[str] = (
    "SegmentPlan",
    "SegmentPiece",
    "SegmentedTranscript",
    "find_speech_regions",
    "plan_segments",
    "plan_from_regions",
    "vad_speech_regions",
    "room_tone",
    "pad_right_context",
    "decode_audio",
    "decode_for_duration",
    "should_segment",
    "transcribe_segmented",
)
