# VF-19 report: the slow tail (release-to-text p90) and the pauses at trigger and paste

Order: VF-19, branch `claude/vf-19-latency` (base `7645011`). Evidence is the 2026-11-10 log
(`%LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log`, `watchdog.log`, `boot_breadcrumb.log`), read
only, numbers only: no transcript text was read into or stored by this work. Nothing was
launched; the effect of this branch is measured by the next health run after the app is
rebuilt.

Reproduce every number below with:

```
python scripts/dev/log_latency.py %LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log --causes --date 2026-11-10
```

## Summary

* The p90 of 11.2 s came from **6 slow recordings** out of 27: two on a CPU-fallback model in the
  morning (already fixed in HEAD by VF-18), four on the GPU in the evening while the machine was
  busy with other work (other sessions rebuilding/testing VoiceFlow, and VoiceFlow's own
  reconstruction pass running a local 8B model on the CPU). Three more recordings were
  over 1.2 s only because they were long (84-92 s of audio at about 1 s per minute of audio).
* Code cause fixed here: **the app never set its own CPU priority.** Task Scheduler starts the
  watchdog, and so the app, at BelowNormal; only one copy of the watchdog script put it back.
  A BelowNormal process only gets a core when no Normal thread wants it, which fits a 5.8 s
  GPU decode taking 21.5 s while builds ran. The app now raises itself to Normal (and memory
  priority to normal, and opts out of power throttling) and logs what it found.
* The two moments Nithin notices: the **trigger** pause is the first press after a launch or
  an idle spell (mic open 35-236 ms vs ~1 ms warm; overlay 17-31 ms vs ~3-12 ms). The
  **paste** step is ~50 ms normally (30 ms of it a fixed clipboard settle) and 180-300 ms under
  contention or on the CPU build. New log fields make both, and the hidden queue wait,
  visible.
* `voiceflow-health` should judge p90 per minute of audio as well as wall time. Implemented and
  tested in `scripts/dev/log_latency.py`; the matching change to `_relay\bin\voiceflow-health.ps1`
  is below as a patch, **not applied** (that file is outside this worktree).

## 1. Slow recordings by cause (2026-11-10)

Latency is `transcription_finished seconds=` (what the health run uses). Per audio minute =
latency / minutes of audio, clips under 10 s counted as 10 s. Normal GPU dictation that day:
0.7-4.6 s per audio minute.

| Time | Audio s | Latency s | s / audio min | Device | Cause | Evidence |
|------|--------:|----------:|--------------:|--------|-------|----------|
| 09:46:25 | 44.70 | 11.630 | 15.6 | cpu | **CPU fallback** | 05:30 launch: `asr_cuda_init_failed error=type object 'disabled_tqdm' has no attribute '_lock' fallback=cpu_int8 model=Systran/faster-distil-whisper-large-v3` (two models preloading at once). `asr_ms=11534.7` on CPU int8. |
| 10:10:09 | 14.58 | 11.196 | 46.1 | cpu | **CPU fallback + first after idle** | Same CPU model; `transcription_idle_resume_guard gap_seconds=1412.4`, warm-up 6044.6 ms on CPU, then `asr_ms=4951.0`. This is the day's p90 value. |
| 21:06:27 | 88.06 | 1.429 | 1.0 | cuda | long dictation (expected) | 4 segments, `asr_ms=1362.8` |
| 21:13:40 | 28.32 | 8.167 | 17.3 | cuda | **contention, not VoiceFlow work** | `asr_ms=8039.2` (normal ~0.3 s for this length). No reconstruction in flight (last ended 21:09:09). The process was gone 4 min later (watchdog restart 21:17:05) and the next model load took 56 s against 15 s on 11-11: the machine was busy. |
| 21:20:51 | 84.29 | 1.467 | 1.0 | cuda | long dictation (expected) | |
| 21:23:23 | 92.13 | 1.422 | 0.9 | cuda | long dictation (expected) | |
| 21:35:19 | 5.82 | 21.559 | 129.4 | cuda | **contention, not VoiceFlow work** | `asr_ms=21524.0` for 5.8 s (~0.3 s normal, ~70x). No reconstruction running (one ended 21:34:35, the next began 21:35:19). Restart at 21:46:46; that model load took 157 s. |
| 21:35:24 | 5.76 | 3.908 | 23.4 | cuda | **queued + reconstruction** | Released 21:35:14, job started 21:35:20: a **6 s wait behind the previous dictation that the logged 3.9 s does not include** (real release-to-text ~10 s). Reconstruction (local 8B, all cores) ran 21:35:19-21:35:32. |
| 21:35:52 | 14.40 | 4.225 | 17.6 | cuda | **reconstruction running** | Reconstruction ran 21:35:32-21:36:01. The live caption during this recording also slowed (`max_decode_ms=1645`; 146-525 on the evening's other recordings). |

Categories the order asked about with no slow recording that day: **model reload after a
restart** (no dictation started before its model was ready; the first dictation after each
evening restart took 0.18-1.47 s) and **paste/clipboard wait** (`inject_ms` max 302 ms, never
the reason a recording was slow). **First-run after idle** on the GPU build is handled:
23:30:22, after 43 min idle, the press-time pre-warm took 349 ms and the dictation 0.242 s.

### Restarts (11 starts, 10 restarts)

| Start | Started by | Note |
|-------|------------|------|
| 04:45, 05:30 | watchdog | old two-model build; both lost the `disabled_tqdm` race (04:45 tiny.en, 05:30 the main model -> CPU all morning) |
| 12:14, 12:19 | not the watchdog (manual/dev launch) | 12:19 lost the race again (tiny.en) |
| 12:24 | watchdog | |
| 19:15, 19:42 | watchdog | 19:42 is the first launch with `startup_selfcheck`, i.e. a new build |
| 21:17, 21:33, 21:46 | watchdog, each after the process had disappeared | coincide with the VF-18/VF-19/VF-20 integration builds (commits 21:24, 21:40, 21:45, 21:49); model loads took 56 s, 23 s, 157 s |
| 23:43 | watchdog | model load 78 s |

The app writes no exit line, so from its own logs a rebuild kill cannot be told from a crash
(the health run counted 0 crashes). The 32 idle-stream overflows are the always-on pre-buffer
stream overflowing while no recording was active; recordings had 0 overflows. Not a latency
cause; not pursued here.

## 2. Trigger and paste, from the existing lines

`recording_start_timing` (logged from the 21:33 build on; 20 presses on 11-10/11):

| Press | overlay ms | mic ms | target ms |
|-------|-----------:|-------:|----------:|
| warm presses (15) | 2.4-12.8 | 0.7-4.4 | 0.1-0.5 |
| 22:47:01, first after 1 h idle | 31.3 | **236.3** | 16.0 |
| 10:54:05 (11-11), first after 24 min | 23.9 | 72.1 | 0.4 |
| 09:05:15 (11-11), first of the day | 17.2 | 39.9 | 1.2 |
| 23:57:22, first after 14 min | 19.8 | 35.1 | 0.2 |

So the trigger pause is the first press after idle: opening the mic path and drawing the
overlay take up to ~0.28 s where a warm press takes ~5 ms. Idle RSS falls to about 30-75 MB between
dictations (`Health Report ... Memory`), i.e. the working set is trimmed and the first press
pages code and buffers back in. What was **not** logged: the time between the key going down
and `start_recording` running (it shares one ordered callback thread with the previous stop).

Paste (`inject_ms` in `transcription_timing`): 48-110 ms on the GPU build (most ~50 ms, of
which 30 ms is the fixed clipboard settle), 182-199 ms during the 21:35 contention window,
217-302 ms on the morning CPU build. Not split further in the log before this change.

## 3. Fixes

### Already in HEAD (verified in the code, not changed here)

| Cause | Fix | Where |
|-------|-----|-------|
| `disabled_tqdm` race demotes the main model to CPU | one process-wide model-construction lock, cache-first load, one CUDA retry on a non-CUDA error, CPU fallback announced and retried | `core/asr_engine.py` `_MODEL_INIT_LOCK`, `_create_model`, `retry_cuda_if_fallen_back` (VF-18) |
| Two models preloading at once | one Whisper model on GPU setups (the 2026-11-10 decision; kept) | VF-18 single-model migration |
| Reconstruction pass (local 8B on every core) slowing dictations | off by default; migration turns it off once | `config.reconstruction_enabled=False`, `_apply_vf19_migration` |
| First dictation after idle | warm-up at key press | `_maybe_prewarm_on_press` |

### In this branch

1. **The app sets its own scheduling** (`utils/process_priority.py`, called once in `main()`):
   raises a BelowNormal/Idle priority class to Normal (never lowers; never above AboveNormal),
   raises a memory priority below normal to normal (5), opts out of power throttling
   (EcoQoS), and logs
   `process_priority before=... after=... raised=... memory_priority_before=... memory_priority_after=... power_throttling=...`.
   `process_priority_minimum` in the config (`"normal"` default, `"off"` to leave the launcher's
   choice). Whether 11-10's slow GPU decodes ran at BelowNormal cannot be proven from that
   day's log (the app did not log its priority, and which copy of the watchdog script the
   scheduled task ran is not recorded); this line answers it from the next launch on.
2. **Missing log fields added** (names in `docs/LATENCY_BUDGET.md`):
   * `recording_start_timing ... queue_ms=` - key press detected -> `start_recording` ran.
   * `transcription_timing ... stop_wait_ms= stop_ms= queue_ms= stop_to_text_ms=` - the stop
     path, the wait behind a previous dictation (the 6 s at 21:35:14 that `seconds=` hid), and
     stop -> text pasted.
   * `inject_timing method= total_ms= throttle_ms= target_ms= snapshot_ms= copy_ms= settle_ms= send_ms=`.
   All appended at the end of existing lines, so existing parsers (the health script's
   `transcription_finished` regex, `log_latency.py`) keep working.
3. **`scripts/dev/log_latency.py`**: `--causes --date` prints the table in section 1;
   `latency_per_audio_minute` (10 s floor); the summary adds stop/queue time on new logs.

Not changed, with reasons: the 30 ms clipboard settle (apps that read the clipboard
asynchronously need it; not testable without a live app); the first-press page-in (the memory
priority fix and the new `queue_ms` should show whether more is needed before adding a
keep-warm); `max_concurrent_jobs=1` (one GPU model; a second concurrent decode would contend
with the first).

Tests: `tests/runtime/test_vf19_latency.py` (27 tests; the existing `test_log_latency.py` still passes): priority raised/never lowered/capped/
failure honest/unavailable no-op; startup hook honours `off` and never raises; listener queue
wait; `pre_job_timing`; `inject_timing` on success and refusal (numbers only); per-minute
floor; the cause table reproduces section 1 from synthetic lines; model-loading cause; logged
`queue_ms` preferred over timestamps; long dictations alone are not a per-minute regression;
real slowness still is.

## 4. Before / after (from the logs)

| Window | n | median s | p90 s (wall) | p90 s per audio min |
|--------|--:|---------:|-------------:|--------------------:|
| 2026-11-09 (baseline) | 28 | 0.374 | 0.852 | 2.83 |
| 2026-11-10, whole day (health run) | 27 | 0.534 | **11.196** | 23.45 |
| 11-10 morning, two-model build on CPU fallback | 2 | 11.196 | 11.630 | 46.07 |
| 11-10 evening, one-model GPU build (19:42 on) | 25 | 0.499 | 4.225 | 17.60 |
| 11-10 evening without the 4 contention recordings | 21 | 0.364 | 1.422 | **2.49** |
| 2026-11-11 so far (VF-18 + reconstruction off) | 5 | 0.207 | 0.445 | 2.67 |

The evening-without-contention row is the case item 4 is about: wall p90 1.42 s (over the
1.2 s limit) from long dictations alone, while per audio minute it is 2.49 s, in line with the
baseline. This branch's own effect (priority, new fields) is not in any row: the running app
predates it. Tomorrow's health run after a rebuild should show `process_priority` lines and the
new fields.

## 5. voiceflow-health: p90 per minute of audio (patch, not applied)

`_relay\bin\voiceflow-health.ps1` is outside this worktree, so it is not edited. The change,
mirroring `log_latency.py` (apply with `git apply --recount` or by hand):

```diff
--- a/bin/voiceflow-health.ps1
+++ b/bin/voiceflow-health.ps1
@@ -28 +28,3 @@
 $P90_LIMIT_S = 1.2; $LONG_REC_S = 30; $SHORT_WORDS = 1
+# VF-19: latency per minute of audio. Clips under 10 s count as 10 s. Limit 6 s/min (10% of real time).
+$PER_MIN_FLOOR_S = 10.0; $PER_MIN_LIMIT_S = 6.0
@@ -40 +42 @@
-function D($k){ if(-not $day.ContainsKey($k)){ $day[$k] = [pscustomobject]@{ date=$k; rec=0; words=0; lat=New-Object System.Collections.Generic.List[double]; overflow=0; idleOverflow=0; overflowLong=0; longRec=0; hang=0; shortEmpty=0; crashes=0; starts=0; corrections=0 } }; $day[$k] }
+function D($k){ if(-not $day.ContainsKey($k)){ $day[$k] = [pscustomobject]@{ date=$k; rec=0; words=0; lat=New-Object System.Collections.Generic.List[double]; perMin=New-Object System.Collections.Generic.List[double]; overflow=0; idleOverflow=0; overflowLong=0; longRec=0; hang=0; shortEmpty=0; crashes=0; starts=0; corrections=0 } }; $day[$k] }
@@ -65 +67,2 @@
         $d.rec++; $d.words += $w; $d.lat.Add($sec); $d.overflow += $n
+        $d.perMin.Add($sec * 60.0 / [math]::Max($dur, $PER_MIN_FLOOR_S))
@@ -83 +86 @@
-  date=$_.date; recordings=$_.rec; words=$_.words; releaseToTextMedianS=(Med $_.lat); releaseToTextP90S=(Pct $_.lat 0.9)
+  date=$_.date; recordings=$_.rec; words=$_.words; releaseToTextMedianS=(Med $_.lat); releaseToTextP90S=(Pct $_.lat 0.9); latencyPerAudioMinuteP90S=(Pct $_.perMin 0.9)
@@ -90 +93 @@
-$baseline = [ordered]@{ days=$base.Count; recordingsMedian=(Med ($base | % recordings)); p90Median=(Med ($base | % releaseToTextP90S)); medianOfMedians=(Med ($base | % releaseToTextMedianS)); overflowMedian=(Med ($base | % audioInputOverflow)); shortMedian=(Med ($base | % emptyOrShortTranscripts)) }
+$baseline = [ordered]@{ days=$base.Count; recordingsMedian=(Med ($base | % recordings)); p90Median=(Med ($base | % releaseToTextP90S)); perMinP90Median=(Med ($base | % latencyPerAudioMinuteP90S)); medianOfMedians=(Med ($base | % releaseToTextMedianS)); overflowMedian=(Med ($base | % audioInputOverflow)); shortMedian=(Med ($base | % emptyOrShortTranscripts)) }
@@ -94 +97,2 @@
-  if($today.releaseToTextP90S -gt $P90_LIMIT_S){ $regressions += [ordered]@{ metric='releaseToTextP90S'; value=$today.releaseToTextP90S; limit=$P90_LIMIT_S; note="p90 above ${P90_LIMIT_S}s (7-day median p90: $(if($baseline.p90Median -ne $null){ $baseline.p90Median } else { 'n/a' }))" } }
+  # A long dictation takes longer in wall time; only a day that is also slow per minute of audio is a regression.
+  if($today.releaseToTextP90S -gt $P90_LIMIT_S -and $today.latencyPerAudioMinuteP90S -gt $PER_MIN_LIMIT_S){ $regressions += [ordered]@{ metric='releaseToTextP90S'; value=$today.releaseToTextP90S; limit=$P90_LIMIT_S; perAudioMinuteP90S=$today.latencyPerAudioMinuteP90S; perAudioMinuteLimit=$PER_MIN_LIMIT_S; note="p90 above ${P90_LIMIT_S}s and $($today.latencyPerAudioMinuteP90S) s per audio minute above ${PER_MIN_LIMIT_S} (7-day median p90: $(if($baseline.p90Median -ne $null){ $baseline.p90Median } else { 'n/a' }))" } }
@@ -102,2 +106,2 @@
-  $r = if($regressions.Count){ 'Regression: ' + (($regressions | % { "$($_.metric)=$($_.value)" }) -join ', ') + '.' } else { 'No regressions vs limits (overflow on long recordings 0, p90 <= 1.2 s, no crashes).' }
-  @("VoiceFlow $($todayKey): $($today.recordings) recordings, $($today.words) words.","Release-to-text median $($today.releaseToTextMedianS) s, p90 $($today.releaseToTextP90S) s; overflow $($today.audioInputOverflow); hang/watchdog $($today.hangWatchdogWarnings); short/empty $($today.emptyOrShortTranscripts); restarts $($today.restarts).",$r) }
+  $r = if($regressions.Count){ 'Regression: ' + (($regressions | % { "$($_.metric)=$($_.value)" }) -join ', ') + '.' } else { "No regressions vs limits (overflow on long recordings 0, p90 <= 1.2 s or <= $PER_MIN_LIMIT_S s per audio minute, no crashes)." }
+  @("VoiceFlow $($todayKey): $($today.recordings) recordings, $($today.words) words.","Release-to-text median $($today.releaseToTextMedianS) s, p90 $($today.releaseToTextP90S) s ($($today.latencyPerAudioMinuteP90S) s per audio minute); overflow $($today.audioInputOverflow); hang/watchdog $($today.hangWatchdogWarnings); short/empty $($today.emptyOrShortTranscripts); restarts $($today.restarts).",$r) }
@@ -118 +122 @@
-  limits=[ordered]@{ p90S=$P90_LIMIT_S; longRecordingS=$LONG_REC_S; shortWordsMax=$SHORT_WORDS }
+  limits=[ordered]@{ p90S=$P90_LIMIT_S; perAudioMinuteP90S=$PER_MIN_LIMIT_S; perAudioMinuteFloorS=$PER_MIN_FLOOR_S; longRecordingS=$LONG_REC_S; shortWordsMax=$SHORT_WORDS }
```

Checked against the logs with the Python twin: 2026-11-10 stays a regression (per audio minute
p90 23.45 > 6), 2026-11-09 and 11-11 stay clean, and the 11-10 evening without the contention
recordings (wall p90 1.42 s) would no longer raise one. A follow-up worth making once the new
build is running: add `transcription_timing queue_ms` to the per-recording latency, since
`transcription_finished seconds=` does not include a queue wait.
