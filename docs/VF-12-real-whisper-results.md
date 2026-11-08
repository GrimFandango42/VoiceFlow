# VF-12 real-Whisper comparison: 15be897 (old) vs candidate

Answers review findings 2 of `VF-12-review-codex-20261107-190306` and 1 and 5 of
`VF-12-review-codex-20261108-001509`. Reproduce with:

```
python scripts/vf12_make_tts_clips.py                                     # SAPI speech clips -> build/vf12-real/clips
git archive --format=tar -o build/vf12-real/old.tar 15be897 src            # extract to build/vf12-real/old
python scripts/vf12_real_whisper_eval.py --src build/vf12-real/old/src --label old
python scripts/vf12_real_whisper_eval.py --src src --label new
python scripts/vf12_real_whisper_eval.py --compare old new
# any subset: --only ending,general,silence,long
```

Each tree runs its own code: its `Config`, its routing and its decode entry point, with the real
`ModernWhisperASR` (primary `distil-large-v3` on CUDA, tiny tier `tiny.en`). **The harness now
mirrors `EnhancedApp.stop_recording`** (review finding 5): route tiny/primary by raw duration; a
recording `should_segment` accepts (>= 20 s) is handed to the decoder **raw** because the segmenter
replaces pause compaction; anything shorter is pause-compacted first. The old tree has no segmenter,
so it always compacts and does one `transcribe` call, which is what it did. LOCALAPPDATA is
redirected to a scratch folder; nothing outside `build/` is read or written.
`tests/runtime/test_vf12_eval_harness_routing.py` pins that routing without loading a model.

## Results (final code, one deterministic run, same audio for both trees)

Review `VF-12-review-codex-20261108-052303` (finding 3) found that `--compare old new` read stale
files, because earlier partial re-runs had been saved under other labels (`old-r2`, `new-r2`,
`new-r2b`). The whole table below was therefore regenerated in a single pass with exactly the three
commands above (all scenarios, labels `old` and `new`; `build/` is git-ignored, so the JSON stays
local). Every row matches the earlier figures except decode time (the primary model was warm).

| scenario | metric | old 15be897 | candidate |
|---|---|---|---|
| Long dictation, 251 s, 16 sentences, 5-20 s pauses (236 words) | WER | 2.97 % | **1.27 %** |
| | deleted / inserted words | 3 / 1 | **0** / 1 |
| | decode time (GPU) | 0.6 s | 1.9 s (16 pieces + VAD pass) |
| 5 sentences separated by 12 s pauses (26 words) | WER | 34.6 % (repeats: "What time? What time does the meeting?", "Who is this the right file? Who is going to...") | **0 %** (paragraph breaks at the pauses) |
| Speech + 20 s trailing silence | WER | 0 % | 0 % |
| Digital silence 30 s | output | "" | "" |
| Stationary noise 30 s (std 0.002) | hallucinated words | 2 ("I think") | **0** (`""`) |
| Stationary noise 30 s, louder (std 0.01, fan-like) | hallucinated words | 3 ("I think of") | **0** (`""`) |
| **Spoken "Thank you." inside 30 s of noise** | output | "Thank you. Thank you." (2 inserted words) | **"Thank you."** (kept, WER 0 %) |
| 25 endings (questions, short final words), quiet room, tail 0 / 0.2 / 0.7 s | word errors | 0 / 0 / 0 | 0 / 0 / 0 |
| Same, noise std 0.03 | word errors | 0 / 0 / 0 | 0 / 0 / 0 |
| Same, noise std 0.06 (about 12 dB SNR) | word errors | 5 / 4 / 4 of 129 | **1 / 1 / 2** |
| | last-word errors | 2 / 3 / 2 of 25 | **1 / 1 / 0** |
| | utterances sent to the tiny model | 25 / 20 / 2 | 0 / 0 / 0 |
| 12 general sentences (150 words) | WER | 2.0 % | 2.0 % (same three proper-noun misses: modules, "Olamer", "Viva") |

Reading it:

* Long paused dictation and pause-induced repetition are clearly better. No segment was dropped.
* **Noise no longer becomes text (review finding 1).** Before this fix the candidate turned 30 s
  of stationary noise into "I think. Thank you." because Whisper's `no_speech_prob` was about 0.04
  and the artifact classifier cannot match a four-word phrase. The gate is now text-independent:
  Silero VAD (bundled with faster-whisper, offline) hears no speech, so nothing is decoded. A real
  spoken "Thank you." in the same noise is kept, and only its region is decoded.
* VAD sanity check on the same clips (`build/vf12_vad_probe.py`, not committed): all 48 SAPI
  clips at three noise levels (std 0.002 / 0.03 / 0.06) had at least 0.25 s of VAD speech (0
  misses of 144), with both the v5 model (faster-whisper 1.2.0, system Python) and the v6 model
  the bundle ships (1.2.1, `.venv-test`); 30 s noise-only recordings at four levels had none.
* End-of-utterance: on clean synthetic speech neither tree makes an ending error, so those
  clips cannot show the user-reported "when will that happen" failure. In noise the old path
  sent 20 of 25 short utterances to the tiny model and made more ending errors; the candidate
  routes them to the primary model (tiny cap 3.0 s -> 1.2 s). That is the measured evidence for
  the tiny-model change. Right-context padding and the tail window are not separated here.
* General accuracy did not drop (identical misses). The candidate's segment pieces decode at
  beam 1, the known trade-off; the long-dictation WER improved regardless.
* Cost: a 251 s dictation takes about 1.3 s longer to decode than the old single call on this GPU
  (16 separate decodes plus about 0.9 s of CPU VAD per 5 minutes of audio). Dictations under 20 s
  are unchanged.

## Limits

* Speech is Windows SAPI TTS (David/Zira), resampled to 16 kHz, with added Gaussian noise. It is
  not Nithin's voice, a real microphone, keyboard clatter, a cough or a TV in the background. VAD
  was checked against synthetic noise only; whether Silero ever calls a very quiet real speaker
  speechless (it would then decode nothing for a recording the energy detector also missed) is
  untested on real recordings. `silence_vad_gate_enabled=false` restores the old behaviour.
* 25 endings and 12 sentences is a small sample; differences of 1-2 words are not statistically
  meaningful.
* The post-key-up microphone tail (hotkey listener + recorder drain, about 0.7 s) is not
  exercised; tail length is a parameter (0 / 0.2 / 0.7 s).
* One run each; CUDA decode is deterministic at temperature 0 but was not repeated.
* The harness runs under system Python313 (faster-whisper 1.2.0); the shipped bundle uses the
  `.venv-test` packages (1.2.1). The VAD probe above covered both; the Whisper decode itself was
  not repeated under 1.2.1.
* Real-voice retest is still required (see the retest list in the VF-12 report).
