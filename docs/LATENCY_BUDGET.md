# Dictation latency budget (VF-11)

What happens between letting go of the hotkey and text appearing, step by step.
"Before" figures come from the VF-10 log analysis (57 recordings: release-to-text median
388 ms, p90 775 ms, paste step median 192 ms) and from reading the code. "After" figures
are **expected, not measured** - nothing here was run against a microphone or a live app.
Re-measure with `python scripts/dev/log_latency.py <voiceflow.log>` after a few days of use.

**The 388 ms the log reports is only the last two rows.** `transcription_timing` starts after
`recorder.stop()` returns, so rows 1-4 (about 0.6 s of fixed waiting) are invisible to it.

| # | Step | Before | After (expected) | Config knob | Visible in log |
|---|------|--------|------------------|-------------|----------------|
| 1 | Release detected and confirmed | ~120 ms confirm + 0-30 ms poll jitter | ~125 ms (timer; no longer needs a later key event) | 0.12 s default, read from `ptt_release_confirm_seconds` only if present on the config object (not a `Config` field) | no |
| 2 | Tail buffer (keeps recording after release; clips >= 0.35 s) | 350 ms | 350 ms | `ptt_tail_buffer_seconds` (0.35) | no |
| 3 | Stop drain | up to 250 ms - in practice the full 250 ms, see note | 250 ms | `stop_drain_seconds` (0.25) | no |
| 4 | Stream stop/close | one `stop()`+`close()` of the recording stream (ms to tens of ms) | none (shared stream stays open) | `audio_single_stream` | no |
| 5 | Idle warm-up, first dictation after >= 20 min idle (11 of 57) | +329-439 ms | ~0 (runs at key press) unless the hold is shorter than the warm-up | `idle_resume_warmup_enabled` | `warmup_ms` |
| 6 | ASR decode + cleanup (`total_ms`) | ~195 ms median | unchanged | - | `total_ms` |
| 7 | Paste (`inject_ms`) | 192 ms median (30 ms settle + keystroke + 150 ms restore wait) | ~45 ms (settle + keystroke; restore on a timer) | `clipboard_restore_delay_ms` (150, now off the critical path) | `inject_ms` |

**Expected effect on the logged figure (rows 6 + 7):** median 388 ms -> about 240 ms,
p90 775 ms -> about 480-630 ms (the 11 idle-resume outliers lose their 330-440 ms; every paste
loses about 145 ms). **Expected key-release-to-text for a typical dictation:** about 1.1 s ->
about 0.95 s, of which about 0.72 s is rows 1-3 (0.125 + 0.35 + 0.25 s). *Correction (VF-14):
this page first assumed a 0.25 s tail; the shipped default `ptt_tail_buffer_seconds` is 0.35 s,
so rows 1-3 cost about 0.72 s, not 0.62 s.*

## Log fields added in VF-19

Rows 3-4 and the wait behind a previous dictation were invisible; they are logged now
(see [the VF-19 report](VF-19-report.md)):

| Field | Line | What it is |
|-------|------|------------|
| `queue_ms` | `recording_start_timing` | key press detected -> `start_recording` ran (it shares one ordered callback thread with the previous stop) |
| `stop_wait_ms` | `transcription_timing` | the same wait for the stop callback |
| `stop_ms` | `transcription_timing` | `stop_recording()`: caption stop, stop drain (row 3), preprocessing -> job submitted |
| `queue_ms` | `transcription_timing` | job submitted -> job running. One worker, so a dictation released while the previous one is still decoding waits here; `transcription_finished seconds=` never included it |
| `stop_to_text_ms` | `transcription_timing` | `stop_wait_ms` + `stop_recording()` entry -> text pasted. Add rows 1-2 (~0.47 s, fixed) for the full key-release-to-text |
| `inject_timing` | own line | the paste step split: `throttle_ms target_ms snapshot_ms copy_ms settle_ms send_ms total_ms` |
| `process_priority` | own line, once per launch | CPU priority class before/after, memory priority, power throttling |

`python scripts/dev/log_latency.py <log> --causes --date YYYY-MM-DD` prints the slow
recordings of a day with their cause and the latency per minute of audio.

## Note on row 3

`_drain_pending_audio` returns early only once the audio callbacks go quiet, but the input
stream stays open during the drain, so callbacks keep arriving every 32 ms and the loop runs
to its 250 ms cap on essentially every recording (inferred from the code; not yet confirmed from a log - the next analysis should record the drain time). The tail buffer (row 2) already keeps
recording for 350 ms after release, so most of this drain is redundant with it. It was left
alone in VF-11 because shortening it risks clipping the last word and cannot be validated
without a microphone.

## Levers worth trying next (config only, one at a time)

| Setting | Now | Try | Saves | Risk |
|---------|-----|-----|-------|------|
| `stop_drain_seconds` | 0.25 | 0.10 | ~150 ms | last word clipped if the driver holds more than ~100 ms |
| `ptt_release_confirm_seconds` (only if added to the config; the code default is 0.12) | 0.12 | 0.06 | ~60 ms | a synthetic key event could end a recording early; the release check now asks Windows directly, which makes this safer than before |
| `ptt_tail_buffer_seconds` | 0.35 | 0.25 | ~100 ms | trailing word cut off (VF-12 judged this tail necessary; see the CHANGELOG before shortening it) |

## What was measured in tests (not in the field)

* Paste returns in well under the restore delay while the restore still happens (`test_paste_async_restore.py`).
* Warm-up cost on the release path drops from the full warm-up (~300 ms in the fake) to under 50 ms with a press-time pre-warm (`test_idle_prewarm.py`).
* The hook path alone completes a release; without the release timer the same test fails (`test_hotkey_release_reliability.py`).
* Pre-roll hand-over on the shared stream has no gap or duplicate under a concurrent producer (`test_single_stream_recorder.py`).
