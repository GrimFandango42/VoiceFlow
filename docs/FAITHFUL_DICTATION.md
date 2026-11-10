# Faithful dictation (VF-17)

Goal: the pasted text is the most plausible *legible* rendering of what was said, not a literal
transcript of what Whisper heard, and the last word(s) of an utterance are never lost. Speed stays
as it was: nothing here makes the paste wait for a language model.

## How this relates to VF-12 item 4

VF-12 item 4 said the text pipeline must **never rewrite meaning**. VF-17 deliberately relaxes that to:

> **Never change meaning, but do repair form.**

"Form" means capitalisation, punctuation, run-ons and broken conjunctions, a small dropped word
(a, the, to, of, and), stutters/fillers, and a word that is a mis-hearing of a vocabulary term or of a
term used earlier in the same dictation. "Meaning" is enforced **in code** (below), not in the prompt, so
the two orders do not contradict each other: anything VF-12 would call a rewrite is still rejected.

## What changed

| Item | Change | Where |
|---|---|---|
| 1 Tail loss | Pause compaction's "blip" filter (runs < 120 ms are zeroed) deleted a soft last word that followed a pause. The last 1500 ms now bypass it (`pause_compaction_tail_protect_ms`; `0` = old behaviour). A trailing-silence pad (`asr_tail_pad_ms`) was measured and did **not** help, so it ships off. | `core/asr_engine.py`, `core/config.py` |
| 2 Tuning log | `tuning_log.jsonl` in `%LOCALAPPDATA%\VoiceFlow`: untruncated (cap 8000 chars) raw / pasted / reconstructed / user-edited text plus metadata. Local only, never uploaded (VF-03). Rotates at 2000 entries or 30 days into one previous generation. | `ai/tuning_log.py` |
| 3 Reconstruction | A local Ollama model (CPU only: `num_gpu=0`, half the cores; the GPU belongs to Reachy, OPS-07) proposes a repaired version after the normal text pipeline. | `ai/reconstruction.py`, `ai/reconstruction_runtime.py` |
| 4 Guards | `check_candidate` is the only gate between the model and the paste. Any failure, timeout or Ollama error pastes the pre-reconstruction text unchanged and is logged. | `ai/reconstruction.py` |
| 5 Speed | Paste first; the improvement is offered afterwards (async) unless measured p95 fits the budget. | `ai/reconstruction_runtime.py`, `integrations/inject.py`, tray |
| 6 Learning | Repeated phonetic misses become hotwords in `custom_vocabulary.txt`. | `ai/hotword_promotion.py`, `ai/adaptive_memory.py`, `ai/daily_learning.py` |
| 8 Evaluation | `scripts/vf_eval.py` / `make vf-eval`. | |

## The guards (item 4)

A candidate is accepted only if **all** of these hold, checked on the text the user would otherwise get:

1. Every number, URL, file path and code-ish token (CamelCase, snake_case, extensions, dotted names)
   in the input is still there, verbatim, the same number of times.
2. Every capitalised proper noun in the input is still there; none appears that was not in the input
   or the vocabulary (sentence-initial function words excepted).
3. Word count stays within 0.8x-1.4x.
4. A word-level diff against the input only contains repairs of form: insert/delete function words and
   fillers, delete an immediate stutter, respell a word or phrase into a close spelling or a vocabulary
   term (`pie installer` -> `PyInstaller`, `that is` -> `that's`). Deleting, inserting or swapping a
   content word, reordering, inflection changes (`note` -> `notes`) and swapping one small word for
   another (`is good` -> `they're good`, found in the first evaluation run) are rejected.
5. The final word is never changed (unless it was a filler or was respelled into a vocabulary term):
   losing the tail is the defect this order exists to fix.
6. Cap on the share of inserted small words (max(2, 15 % of the words)).

`tests/runtime/test_vf17_reconstruction_guards.py` feeds hallucinating candidates (changed number,
invented name, dropped URL, new sentence, reordering, trailing-off word altered...) and also runs an
end-to-end fake-Ollama test proving the raw text is what gets pasted.

## No speed regression (item 5)

`reconstruction_mode: auto` (default) pastes the pre-reconstruction text immediately and goes
synchronous only after at least 5 timed runs have p95 <= `reconstruction_budget_ms` (800). Otherwise an
accepted result becomes a *pending improvement*: overlay note, tray entry **Replace last paste with
improved version**, and `Ctrl+Alt+R` (`replace_last_paste_hotkey`). The swap is refused, and the improved
text goes to the clipboard instead, unless the same window is still focused, nothing was typed since,
and the paste is recent (`replace_last_paste_max_age_s`), single-line and unchanged.

On this machine a CPU-only 8B model is ~6 s per call, far over 800 ms, so in practice **this is the async
path**: the paste is never slower than before. A small model (<= 3B) may make the sync path eligible; the
mode then switches itself based on measured latency, not on a guess.

## Hotword promotion (item 6)

A term is promoted to `custom_vocabulary.txt` only if the same phonetic miss was seen in >= 3 distinct
utterances (or 2 explicit user edits) and the mapping is not ambiguous. The nightly learning report says
how many were promoted, or why none were. Promotion is additive and reversible (edit the file).

## Evaluation (item 8)

`make vf-eval` (or `python scripts/vf_eval.py [--no-llm] [--scenarios pauses,fast,noise,technical,tail]`)
synthesises speech with offline Windows SAPI TTS plus synthetic noise, runs faster-whisper on CPU from the
local model cache and the reconstruction pass on the local Ollama, and prints the before/after table.
It never launches the app, uses a microphone or the GPU, and only *reads* the live corpus (counts and
scores only, never dictation text).

- **before** = base behaviour: `pause_compaction_tail_protect_ms=0`, no reconstruction.
- **after** = this branch's defaults, plus the reconstruction text a user ends up with after accepting the
  improvement.
- Metrics: WER vs the scripted reference (punctuation and case stripped); tail-word retention; legibility
  proxy = share of sentences that start capitalised, end with terminal punctuation, do not end on a dangling
  function word, contain no immediate repeat, and are not a run-on (>35 words or a comma splice such as
  `..., the vendor contract renews`). The tail scenario is excluded from legibility on purpose, its
  references trail off mid-clause.

### Measured results (2026-11-10, `small.en` CPU + `llama3.1:8b` on CPU, TTS speech)

| scenario | n | WER before | WER after | tail before | tail after | legible before | legible after |
|---|---|---|---|---|---|---|---|
| long dictation, 5-20 s pauses | 3 | 2.9% | 2.9% | 100.0% | 100.0% | 55.6% | 66.7% |
| fast speech | 5 | 4.6% | 4.6% | 100.0% | 100.0% | 100.0% | 100.0% |
| background noise (SNR 6 dB) | 5 | 0.0% | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| dense technical vocabulary | 5 | 0.0% | 2.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| utterance ends in a short word | 18 | 4.1% | 2.7% | 77.8% | 88.9% | n/a | n/a |

Read it honestly:

- **Tail words** are the clear win (77.8 % -> 88.9 %; WER 4.1 % -> 2.7 %). The remaining misses are the
  -20 dB-below-the-sentence fixtures, which small.en cannot decode with or without this change.
- **Legibility** improves where there are run-ons (55.6 % -> 66.7 %: one of three long dictations had its comma
  splices fixed; the other was returned unchanged by the model). It saturates at 100 % elsewhere because
  Whisper already punctuates clean TTS speech.
- **WER does not improve** from reconstruction, as expected, and **one fixture regresses**: the model inserted
  "a" in "over WebSocket" -> "over a WebSocket" (1 word of 10). Inserting a missing small word is an explicitly
  allowed repair and it is grammatical, but it is not what was said. The earlier `Is good.` -> `They're good.`
  regression was caught by this table and is now rejected by the guard.
- **Real captured corpus replay** (12 utterances sampled from `recent_history_events.jsonl`, counts only): 1
  accepted, 2 unchanged by the model, 9 rejected by the guards (`rewritten` 4, `proper_noun_lost` 3,
  `protected_token_lost` 1, `inflection_changed` 1). Mean legibility did not move (59.7 % -> 59.7 %). The
  guards are conservative: on real, messier text the pass currently changes little, and that is the safe failure.
- **Added latency** (6 timed runs, `llama3.1:8b`, CPU): sync path p50 5.4 s / p95 6.0 s, i.e. far over the
  800 ms budget, so `auto` mode stays async. Async path: p50 0.05 ms / p95 0.39 ms added to the paste. With
  6 samples the p95 is the slowest run, not a stable estimate.
- **Hotwords from the real corpus: 0.** The audit log has 36 rows, 16 with raw != final, but none has an accepted
  reconstruction or a user edit and `learned_pairs` is empty in every row; the only raw/final differences are
  casing/punctuation, which are not learnable word pairs (2 candidate word pairs, below the 3-utterance
  threshold). The tuning log did not exist yet (it is written once this branch runs), so the real triples that
  feed promotion have not accumulated. Fixture tests prove the mechanism; they are not evidence of yield.

### Limitations

- TTS speech is cleaner and more regular than a real voice and accent; it does not reproduce the accent,
  noise and fast-speech failures that motivated the order. Treat the numbers as a regression gate, not as
  a forecast of real-world accuracy.
- The evaluation ASR is `small.en` on CPU; the app uses `distil-large-v3` on CUDA.
- WER cannot improve through reconstruction by construction (guards forbid content changes); the pass is
  expected to move *legibility*, and to move WER only through vocabulary repairs.
- The app's "retry on raw audio after heavy compaction" step is not replayed.

## Live preview (item 7): findings only, no behaviour change

Reading of the brief: "the live preview on the display is really no good anymore, it only fills in at the end."
**Needs Nithin's confirmation before anything user-visible changes.** What the code does today:

- Two separate mechanisms exist. (a) `core/streaming.py` `StreamingTranscriber`: every 0.85 s it
  re-transcribes the *trailing 8 s* (`streaming_partial_max_audio_seconds`) of the recording with the fast ASR
  engine, and the overlay then shows only the **last 6 words** (`live_caption_words`, `ui/cli_enhanced.py`
  `_on_streaming_preview`). It does not start until 1.8 s into the recording (`live_caption_start_delay_seconds`),
  so short utterances never show one. (b) "Live checkpoints" (`live_checkpoint_*`): every ~10 s of audio, a chunk
  is transcribed and (with `live_checkpoint_inject`) injected as it is spoken.
- Consequences that match the symptom: a long dictation shows a rolling 6-word window of the last 8 s, never the
  sentence so far; partials are re-decoded from scratch with no stability marking, so text flickers; on a loaded
  machine each decode takes longer than the 0.85 s cadence, so the display lags and only catches up when
  speech stops.
- `recent_history_events.jsonl` `preview` is the *tail of `full_text`* (taken from the final result), not a log
  of streamed partials, which is consistent with the reading but is not proof either way.
- Until VF-10 the packaged build did not bundle the Silero VAD asset, so every preview pass raised and fell
  back to VAD-less decoding (fixed; see CHANGELOG). Not re-verified in a packaged run here (the app was not
  launched).
- Options for the follow-up, once confirmed: (1) show a growing, committed transcript (commit words that
  have been stable across two passes, grey the unstable tail); (2) keep the 6-word caption but start at 0.8 s;
  (3) remove the preview. Option 1 is the one that matches "fully faithful reproduction of a conversation".
