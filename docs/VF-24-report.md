# VF-24 report: the learning loop gets an input, and the daily names get a shipped seed

Measured 2026-11-27 on the dev machine, CPU only, from the `claude/vf-24-learning-loop` branch. No app was launched and the live data folder was not read: the sweep points `%LOCALAPPDATA%`, the vocabulary file and the engineering-terms file at its own cache folder.

## 1. Why configured hotwords did not prevent "cloud" for Claude

Traced in the code the frozen bundle runs (`voiceflow.ai` and `voiceflow.core` are collected whole by `scripts/setup/build_windows_exe.ps1`):

| Path | Hotwords (seeds + `asr_hotwords` + learned) | Vocabulary prompt (`custom_vocabulary.txt` + built-ins) |
|---|---|---|
| Main pass (`ModernWhisperASR.transcribe(audio)`) | reached the decoder | reached the decoder |
| Long recordings (segmenter: `transcribe(chunk)` per piece) | reached the decoder | reached the decoder |
| Live caption, first decode (empty running text) | reached the decoder | reached the decoder |
| Live caption, later decodes (running text as `initial_prompt`) | reached the decoder | **dropped**: the running text replaced it |

What was broken: only the last row, and it's fixed. `vocab.compose_prompt` puts the vocabulary first and the running text last, inside the same 700-character budget. The caption text is a preview; the pasted text comes from the main pass. Tests: `tests/runtime/test_vf24_hotword_path.py`.

Why the main pass still writes "cloud": the cause is the method, not the wiring. In faster-whisper, hotwords and `initial_prompt` both go into the decoder's "previous text" slot as a soft bias. That bias helps rare spellings (VoiceFlow, GLaDOS). It loses to the acoustics on a common English word that sounds the same as the name, which fits a miss that comes and goes (33 correct "Claude" in the same history). So the fix is deterministic phrase rules (section 3) plus logged corrections (section 4). More biasing would not help.

## 2. How many hotwords fit

`python scripts/vf_eval.py --no-llm --no-corpus --hotwords-sweep 10,19,24,32`. Every decode is fresh: the sweep never uses the ASR cache, and the cache key now includes model, hotwords and harness version. The model is warmed up first. The N=0 baseline runs first and last, and the gap between those two runs is the noise band, fixed before any N is judged. A count passes when raw WER rises at most 0.5 points, median decode time rises no more than the noise band (minimum 3%), and the real-cloud controls gain no "Claude".

faster-whisper 1.2.0, Python 3.13.5, `small.en` int8 on CPU. Vocabulary prompt 488 chars / 164 tokens. 33 utterances: fast, noisy and technical speech (scored for WER), the 13 name sentences, and 5 real-cloud controls. Baseline median 1872 ms; noise 0.4%, so the tolerance is 3%.

| hotwords | chars | tokens | raw WER | median ms | delta | names raw | names after text pass | false "Claude" raw/post | passes |
|---|---|---|---|---|---|---|---|---|---|
| 0 | 0 | 0 | 1.5% | 1876 | (base) | 13/13 | 13/13 | 0/0 | base |
| 10 (old seed count) | 96 | 28 | 1.5% | 1909 | +37 ms, +2.0% | 13/13 | 13/13 | 0/0 | yes |
| 19 | 168 | 57 | 1.5% | 1914 | +43 ms, +2.3% | 13/13 | 13/13 | 0/0 | yes |
| 24 | 217 | 73 | 1.5% | 2087 | +215 ms, +11.5% | 13/13 | 13/13 | 0/0 | no |
| 32 | 294 | 96 | 2.2% | 2121 | +250 ms, +13.3% | 13/13 | 13/13 | 0/0 | no |
| 0 | 0 | 0 | 1.5% | 1867 | (base) | 13/13 | 13/13 | 0/0 | base |

An earlier run that overlapped with test runs on the same CPU showed the same shape: no WER change through 48 terms, but decode time rose steeply above about 20 terms.

Decision: `MAX_HOTWORD_TERMS = 19`, enforced in `effective_hotwords`. The shipped seeds are the 13 required names (`core/vocab.NAME_SEED_TERMS`) plus VoiceFlow, 14 in all, which leaves about a quarter of the ceiling free. Up to 5 slots are reserved for learned (twice-corrected) terms, so the default `asr_hotwords` cannot crowd them out. Wispr, Atlas, LIMS, Veeva and Madison are no longer seeds. They stay in the default `asr_hotwords` (and so in any saved config that kept the default) and in the vocabulary prompt.

Cost per dictation compared with today: the hotword string grows from 10 to 14 terms and its prefix from 28 to about 45 tokens, which adds about 6 ms per decode on this CPU model (+37 ms at 10 terms, +43 ms at 19). Nothing was measured on the CUDA model the app uses.

Limits: SAPI speech is cleaner than Nithin's voice, and SAPI gets all 13 names right even with no hotwords. So this measures cost and safety (WER, time, false "Claude"), not whether the seeds fix his real misses. The live check is the separate manual order.

## 3. "cloud" only inside phrases

- Rewritten to Claude everywhere, by built-in rules: `cloud code`, `cloud desktop`, `cloud max` (also `CloudMax`) and `cloud duet`.
- Removed: the sentence-wide `cloud -> Claude` rewrite, which turned "I use Claude Code to deploy to the cloud" into "... deploy to the Claude". Also removed: the aggressive-only `anthropic's cloud -> Anthropic's Claude` rewrite.
- `core/rewrite_policy.py`: `cloud`, `clouds`, `cloud's` and `do it` never become a whole-word rewrite rule on any route. That covers learned adaptive rules (new ones, and ones already on disk), `custom_vocabulary.txt` lines, `engineering_terms.json` exact entries, review-queue approvals and VF-17 promotions. An explicit `do it -> Duet` correction still counts toward the "Duet" hotword.
- Tests (`tests/runtime/test_vf24_cloud_rules.py`): "Google Cloud", "cloud-based", "in the cloud", "the cloud side" and "deploy to the cloud" keep their cloud, with aggressive mode on and off.

## 4. The learner's input

```
python -m voiceflow.ai.corrections add --heard "Jamelan" --meant "Gemini"
python -m voiceflow.ai.corrections list
```

Each call appends a `manual_correction` row to `transcription_corrections.jsonl`, the file the nightly job already reads. The next run processes it. Two rows for the same pair make an active rule through the existing learner (`adaptive_user_correction_min_count`), and the corrected term also counts toward a learned hotword. Run the command from `src\` or any folder other than the repo root, where the `voiceflow.py` launcher shadows the package. The same is already true of every `python -m voiceflow.*` command.

## 5. The daily report

The report already counted corrections (`stats.correction_items_total` / `correction_items_used`). It now also carries a `correction_input` block. `self_learning_insights.json` tracks consecutive target dates with zero corrections. A date is counted once even when the morning run and the startup catch-up both process it, and a gap of skipped days restarts the count. On the seventh day it writes one line: `no correction input for 7 days; ...`. A day with a correction clears it. Dry runs leave the insights file alone.

## 6. Hot-path cost (median, same machine, base commit `f2ca47f` vs this branch)

| Step | Base | Branch | Delta |
|---|---|---|---|
| `normalize_context_terms`, ~200-word dictation, default | 10.44 ms | 10.30 ms | -0.14 ms |
| same, aggressive cleanup | 12.66 ms | 11.94 ms | -0.72 ms |
| vocabulary prompt build (cached) | 108 µs | 120 µs | +0.01 ms |
| hotword decode prefix (CPU small.en) | 10 terms | 14 terms | about +6 ms |

Live caption decodes after the first now carry the vocabulary prompt. They cost what the caption's first decode always cost, but more than the later caption decodes did before this change. That cost was not measured on CUDA.
