# VF-12 real-Whisper comparison: 15be897 (old) vs candidate

Answers review finding 2 of `VF-12-review-codex-20261107-190306`. Reproduce with:

```
python scripts/vf12_make_tts_clips.py                                     # SAPI speech clips -> build/vf12-real/clips
git archive --format=tar -o build/vf12-real/old.tar 15be897 src            # extract to build/vf12-real/old
python scripts/vf12_real_whisper_eval.py --src build/vf12-real/old/src --label old
python scripts/vf12_real_whisper_eval.py --src src --label new
python scripts/vf12_real_whisper_eval.py --compare old new
```

Each tree runs its own code: its `Config`, pause compaction, model routing (tiny vs primary by
clip length) and decode entry point (old: one `transcribe` call; new: `decode_for_duration`),
with the real `ModernWhisperASR` (primary `distil-large-v3` on CUDA, tiny tier `tiny.en`).
LOCALAPPDATA is redirected to a scratch folder; nothing outside `build/` is read or written.

## Results (one deterministic run, same audio for both trees)

| scenario | metric | old 15be897 | candidate |
|---|---|---|---|
| Long dictation, 251 s, 16 sentences, 5-20 s pauses (236 words) | WER | 2.97 % | **1.27 %** |
| | deleted / inserted words | 3 / 1 | **0** / 1 |
| 5 sentences separated by 12 s pauses (26 words) | WER | 34.6 % (repeats: "What time? What time does the meeting?", "Who is this the right file? Who is going to...") | **0 %** (paragraph breaks at the pauses) |
| Speech + 20 s trailing silence | WER | 0 % | 0 % |
| Digital silence 30 s | output | "" | "" |
| Stationary white noise 30 s / 30 s louder | hallucinated words | 2 / 3 ("I think", "I think of") | **4 / 5** ("I think. Thank you.", "I think of Thank you.") |
| 25 endings (questions, short final words), quiet room, tail 0 / 0.2 / 0.7 s | word errors | 0 / 0 / 0 | 0 / 0 / 0 |
| Same, noise std 0.03 | word errors | 0 / 0 / 0 | 0 / 0 / 0 |
| Same, noise std 0.06 (about 12 dB SNR) | word errors | 5 / 4 / 4 of 129 | **1 / 1 / 2** |
| | last-word errors | 2 / 3 / 2 of 25 | **1 / 1 / 0** |
| | utterances sent to the tiny model | 25 / 20 / 2 | 0 / 0 / 0 |
| 12 general sentences (150 words) | WER | 2.0 % | 2.0 % (same three proper-noun misses: modules, "Olamer", "Viva") |

Reading it:

* Long paused dictation and pause-induced repetition are clearly better. No segment was dropped.
* End-of-utterance: on clean synthetic speech neither tree makes an ending error, so those
  clips cannot show the user-reported "when will that happen" failure. In noise the old path
  sent 20 of 25 short utterances to the tiny model and made more ending errors; the candidate
  routes them to the primary model (tiny cap 3.0 s -> 1.2 s). That is the measured evidence for
  the tiny-model change. Right-context padding and the tail window are not separated here.
* General accuracy did not drop (identical misses). The candidate's segment pieces decode at
  beam 1, the known trade-off; the long-dictation WER improved regardless.
* **Regression to know about:** on 30 s of stationary synthetic noise (no speech) the
  candidate adds a trailing "Thank you." to Whisper's "I think". The decoder reports
  `no_speech_prob` about 0.04 for that audio, so the artifact guard (which needs silence
  evidence) does not fire. Pure digital silence is clean (test-covered). In the app, noise-only
  recordings are normally stopped earlier by the RMS/non-speech guards, which this harness does
  not run.

## Limits

* Speech is Windows SAPI TTS (David/Zira), resampled 22.05 -> 16 kHz, with added Gaussian
  noise. It is not Nithin's voice or a real microphone. 25 endings and 12 sentences is a small
  sample; differences of 1-2 words are not statistically meaningful.
* The post-key-up microphone tail (hotkey listener + recorder drain, about 0.7 s) is not
  exercised; tail length is a parameter (0 / 0.2 / 0.7 s).
* One run each; CUDA decode is deterministic at temperature 0 but was not repeated.
* Real-voice retest is still required (see the retest list in the VF-12 report).
