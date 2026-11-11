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
| 1 Tail loss | (a) Pause compaction's "blip" filter (runs < 120 ms are zeroed) deleted a soft last word that followed a pause: the last 1500 ms now bypass it (`pause_compaction_tail_protect_ms`; `0` = old behaviour). (b) A speaker who lets the last word fade ("...of the", "...for now") is levelled before ASR: speech that trails the last full-level speech and is > 6 dB under the clip's speech level is lifted toward it by at most 9 dB (`asr_tail_lift_db`; `0` = off), never touching a sample outside the lifted frames. A trailing-silence pad (`asr_tail_pad_ms`) was measured and did **not** help, so it ships off. | `core/asr_engine.py`, `core/config.py` |
| 2 Tuning log | `tuning_log.jsonl` in `%LOCALAPPDATA%\VoiceFlow`: untruncated (cap 8000 chars) raw / pasted / reconstructed / user-edited text plus metadata. Local only, never uploaded (VF-03). Rotates at 2000 entries or 30 days into one previous generation. | `ai/tuning_log.py` |
| 3 Reconstruction | A local Ollama model (CPU only: `num_gpu=0`, half the cores; the GPU belongs to Reachy, OPS-07) proposes a repaired version after the normal text pipeline. | `ai/reconstruction.py`, `ai/reconstruction_runtime.py` |
| 4 Guards | `check_candidate` is the only gate between the model and the paste. Any failure, timeout or Ollama error pastes the pre-reconstruction text unchanged and is logged. | `ai/reconstruction.py` |
| 5 Speed | Paste first; the improvement is offered afterwards (async) unless measured p95 fits the budget. | `ai/reconstruction_runtime.py`, `integrations/inject.py`, tray |
| 6 Learning | Repeated phonetic misses become hotwords in `custom_vocabulary.txt`. | `ai/hotword_promotion.py`, `ai/adaptive_memory.py`, `ai/daily_learning.py` |
| 8 Evaluation | `scripts/vf_eval.py` / `make vf-eval`. | |

## The guards (item 4)

A candidate is accepted only if **all** of these hold, checked on the text the user would otherwise get:

1. Every number, URL, file path and code-ish token (CamelCase, snake_case, extensions, dotted names)
   in the input is still there, verbatim, the same number of times. **The raw ASR text is checked too**, as
   multisets: every number, protected token and name in the raw must be in the candidate as many times as it was
   said, even if text processing had already lost it. Numbers are compared by value, spoken or typed (`nine` ==
   `9`, `forty two` == `42`, `two thousand twenty six` == `2026`), so a spelled number cannot vanish and a
   repeated `7` cannot collapse to one `7`.
2. Every capitalised proper noun in the input is still there, **including a name that opens a sentence**
   ("Alice sent..." -> "Alicia sent..." is rejected; only function words are exempt from this); none appears
   that was not in the input or the vocabulary. A sentence-initial word is excused only when it was folded into
   a vocabulary term the candidate introduces ("Pie installer is slow" -> "PyInstaller is slow").
3. Word count stays within 0.8x-1.4x.
4. A word-level diff against the input only contains repairs of form: insert one of exactly three neutral connectors
   (`and`, `to`, `of`; never `a`/`an`/`the`, never beside a name, number, protected token or vocabulary term, and
   never `not`, `maybe`, `always`, `because`, `should`, `never`, `but`, `so` or any other word that carries polarity,
   certainty, frequency, causality, modality, contrast or consequence - a vocabulary entry does not license them
   either: `I will ship today` -> `I will not ship today` is `meaning_word_inserted`/`novel_content`), delete a filler
   sound or an immediate stutter, respell a word or phrase into a vocabulary term or a **name or identifier** the
   speaker already used in the same dictation (a protected token, a capitalised proper noun or a sentence-initial
   name: `pie installer` -> `PyInstaller`, `cubernetes` -> `Kubernetes` after `Kubernetes`), or contract/expand or
   swap a homophone (`that is` -> `that's`, `there` -> `their`). A close spelling alone is never enough, and neither
   is an ordinary word that merely occurs elsewhere: `the cat is here` -> `the car is here`, and `The cat and car are
   here. The cat is red.` -> `... The car is red.`, and `he` -> `she` are rejected (`unsourced_replacement` /
   `rewritten`) because the new word is not a vocabulary term, not a name the speaker used, and not the same spoken
   word. Deleting any other word (including `and`: "thanks everyone and see you
   there" -> "thanks everyone, see you there"), inserting or swapping a content word, reordering, inflection
   changes (`note` -> `notes`), inserting a determiner (`over WebSocket` -> `over a WebSocket`) and swapping one
   small word for another (`is good` -> `they're good`) are rejected. Each of those was seen in an evaluation run
   or a review probe.
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
improved version**, and `Ctrl+Alt+R` (`replace_last_paste_hotkey`).

The in-place swap deletes characters, so it happens only when the app can *prove* the caret is where the paste left
it, and otherwise copies the improved text to the clipboard instead (`clipboard:<reason>`):

- same foreground window, **same focused control and same caret position** (`GetGUIThreadInfo`, snapshotted ~0.4 s
  after the paste once the target has handled it; apps with no system caret, such as Chromium or Electron, fall back
  to the focus handle plus the two counters below);
- no key press since the paste (global key counter) and **no mouse click since the paste** (system-wide low-level
  mouse hook, `_MouseClickTracker`; if the hook is unavailable the swap is refused);
- the paste is recent, single-line, unchanged, was not followed by Enter, and the app is in paste mode (typing mode
  cannot stage a replacement, so it never swaps in place);
- **the replacement is staged on the clipboard first and every condition is re-checked before the first backspace**:
  a click during the staging delay, or a clipboard that cannot be written, deletes nothing.

The tray entry is a mouse click away from the document, so in practice it takes the clipboard path; the hotkey is the
in-place path. Not exercised against real applications here: see the report's "Not tested" list.

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

`python scripts/vf_eval.py` exits non-zero when any fixture regresses (WER up, a tail word the base kept is lost, or
legibility down), when a scenario's mean WER rises, or when the tail scenario is below 100 % retention. The run below
printed `ACCEPTANCE: PASS`.

| scenario | n | WER before | WER after | tail before | tail after | legible before | legible after |
|---|---|---|---|---|---|---|---|
| long dictation, 5-20 s pauses | 3 | 2.9% | 2.9% | 100.0% | 100.0% | 55.6% | 66.7% |
| fast speech | 5 | 4.6% | 4.6% | 100.0% | 100.0% | 100.0% | 100.0% |
| background noise (SNR 6 dB) | 5 | 0.0% | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| dense technical vocabulary | 5 | 0.0% | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| utterance ends in a short word | 18 | 4.1% | 0.6% | 77.8% | 100.0% | n/a | n/a |

Tail scenario, audio side only (no reconstruction):

| config | WER | tail retention |
|---|---|---|
| base (no protection, no pad) | 4.1% | 77.8% |
| compaction keeps the last 1.5 s | 2.7% | 88.9% |
| + quiet-tail lift, 9 dB (this branch) | 0.6% | 100.0% |
| pad 400 ms only | 3.9% | 83.3% |
| protection + lift + pad 400 ms | 1.2% | 100.0% |

Read it honestly:

- **Tail words**: 77.8 % -> 100 % on 18 fixtures (the last word "and that", "of the", "is good", "and then", "if you
  can", "for now", with the tail spoken 9, 15 and 20 dB below the sentence after a 5 s pause). The compaction fix alone
  reached 88.9 %; the remaining fixtures were the 20 dB ones, where small.en either dropped the word or hallucinated a
  continuation ("of the video"). **The 9 dB figure was chosen on this same fixture set**, so 100 % here is a fit to the
  set, not a forecast: a gain sweep gave 3 dB -> 16/18, 6-12 dB -> 18/18 with no regression, 15-18 dB -> 18/18 but one
  unrelated clip's head decoded differently ("the notes" -> "a notes", WER 0 % -> 11 %). 9 dB sits in the middle of the
  plateau. Real accents and microphones are not in this set.
- **Legibility** improves where there are run-ons (55.6 % -> 66.7 %: one of three long dictations had its comma splices
  fixed, the others were returned unchanged or rejected). It saturates at 100 % elsewhere because Whisper already
  punctuates clean TTS speech.
- **WER does not rise anywhere.** Two earlier fixture regressions were caught by this table and are now rejected in
  code: `over WebSocket` -> `over a WebSocket` (determiner insertion) and `thanks everyone and see you there` ->
  `thanks everyone, see you there` (conjunction deleted). Reconstruction itself cannot lower WER (the guards forbid
  content changes); its job is legibility.
- **Reconstruction outcomes** over the 36 model calls: 9 accepted, 22 unchanged, 5 rejected `rewritten`, 2
  `determiner_inserted`, 2 `inflection_changed`, 2 `novel_content`, 1 `content_deleted`, 4 `proper_noun_lost`, 1
  `protected_token_lost`. Every rejection pasted the pre-reconstruction text.
- **Real captured corpus replay** (12 utterances sampled from `recent_history_events.jsonl`, counts only): 1
  accepted, 1 unchanged, 10 rejected by the guards. Mean legibility did not move (59.7 % -> 59.7 %). The guards are
  conservative: on real, messier text the pass currently changes little, and that is the safe failure.
- **Added latency** (6 timed runs, `llama3.1:8b`, CPU): sync path p50 5.7 s / p95 7.0 s, far over the 800 ms budget,
  so `auto` mode stays async. Async path: p50 0.06 ms / p95 0.45 ms added to the paste. With 6 samples the p95 is the
  slowest run, not a stable estimate.
- **Hotwords from the real corpus: 0.** The audit log has 36 rows, 16 with raw != final, but none has an accepted
  reconstruction or a user edit and `learned_pairs` is empty in every row; the only raw/final differences are
  casing/punctuation, which are not learnable word pairs (2 candidate word pairs, below the 3-utterance
  threshold). The tuning log did not exist yet (it is written once this branch runs), so the real triples that
  feed promotion have not accumulated. Fixture tests prove the mechanism; they are not evidence of yield.

### Limitations

- TTS speech is cleaner and more regular than a real voice and accent; it does not reproduce the accent,
  noise and fast-speech failures that motivated the order. Treat the numbers as a regression gate, not as
  a forecast of real-world accuracy.
- The evaluation ASR is `small.en` on CPU; the app uses `distil-large-v3` on CUDA. The quiet-tail lift was tuned
  against `small.en` decodes; it has not been measured with the app's model.
- The evaluator's `before` is the base behaviour reproduced by config (`pause_compaction_tail_protect_ms=0`, no lift,
  no reconstruction), not a second checkout of the base commit.
- WER cannot improve through reconstruction by construction (guards forbid content changes); the pass is
  expected to move *legibility*, and to move WER only through vocabulary repairs.
- The app's "retry on raw audio after heavy compaction" step is not replayed.

## Live preview (item 7): findings only, no behaviour change

Reading of the brief: "the live preview on the display is really no good anymore, it only fills in at the end."
**Needs Nithin's confirmation before anything user-visible changes.** `core/streaming.py` is unchanged by this order.
What the code does today (re-checked against source and the live `config.json`; an earlier draft of this section
had the numbers below wrong):

- **Streaming partials.** `StreamingTranscriber` (`core/streaming.py`) is started with `chunk_duration=0.85` s and
  `partial_max_audio_seconds=8.0` (`ui/cli_enhanced.py` `_start_streaming_preview`): roughly every 0.85 s it
  re-transcribes the *trailing 8 s* of the recording with the fast ASR engine and emits that as the "partial". Each
  partial is an independent decode of the window; `streaming.py` has no stability marking or word commit.
- **What reaches the display.** `_on_streaming_preview` console-prints the last `live_caption_words` words
  (source default 8, `core/config.py`) capped at `live_caption_max_chars` (150), but that truncation is for the
  `[PREVIEW]` console line only. The **overlay receives the full partial** (`visual_show_preview(preview_text)`) and
  applies its own trim in `ui/visual_indicators.py` `_update_preview`: last `live_caption_words` words, capped at
  `live_caption_max_chars`. The overlay reads its own settings, with defaults 20 words / 380 chars. The live
  `config.json` has `live_caption_words = 20`, `live_caption_start_delay_seconds = 0.6`. So the overlay shows at most the
  last ~20 words of the **trailing 8 s window**: for a long dictation it can never show "the sentence so far".
- **Start delay.** `live_caption_start_delay_seconds` is 0.6 s (source default and live config), not 1.8 s.
- **Interim checkpoints are dormant.** `live_checkpoint_enabled` is true and `live_checkpoint_seconds` is 10, but
  `_queue_checkpoint_preview` returns immediately unless `live_flush_during_hold` is true, and that is false in the
  source default and in the live config. `live_checkpoint_inject` is false as well. So the "growing transcript every
  ~10 s" mechanism is not running; nothing beyond the 8 s partials is shown while the key is held.
- `recent_history_events.jsonl` `preview` is the tail of `full_text` from the final result, not a log of streamed
  partials: consistent with the reading, not proof of it.
- Not established, and not measured here (the app was not launched): whether partials are slow enough on this machine
  to lag behind speech, and whether the packaged build's Silero VAD asset (bundled since VF-09/VF-10) now makes the
  partials appear where they previously fell back to VAD-less decoding.
- Options once confirmed: (1) show a growing, committed transcript (commit words that were stable across two
  passes, grey the unstable tail), which needs `streaming.py` changes; (2) turn the dormant checkpoints on
  (`live_flush_during_hold`), which is a behaviour and stability trade-off the config comment calls out; (3) remove the
  preview. Option 1 best matches "fully faithful reproduction of a conversation".
