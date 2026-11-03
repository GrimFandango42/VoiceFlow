# Changelog

All notable changes to VoiceFlow are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Changed
- **Cloud transcript analysis is now opt-in (VF-03)** — `adaptive_ai_analysis_enabled` defaults to `false`. The nightly learning pass no longer sends transcripts to Anthropic/Gemini unless you turn on **Setup & Defaults → "Send a daily sample of transcripts to Claude"**. Existing configs that carried the old `true` default are reset to off once (`cloud_learning_consent_version`); the wizard records your choice from then on.
- **Claude CLI call is locked down** — the learning batch invokes `claude --print --safe-mode --tools "" --strict-mcp-config --permission-mode dontAsk --no-session-persistence` with the prompt on stdin, so transcript text never appears in argv and the subprocess cannot reach MCP servers, shell tools, or user/project hooks (managed-policy hooks are the documented exception and are handled by the refusal below).
- **Managed-policy hooks are refused, not bypassed** — `--safe-mode` does not suppress hooks installed by a managed (enterprise) Claude Code policy. Before spawning the CLI, VoiceFlow checks the platform managed-settings files (on Windows both `%ProgramFiles%\ClaudeCode\managed-settings.json` and `%ProgramData%\ClaudeCode\managed-settings.json`, plus any `managed-settings.d\*.json` fragments; the standard macOS/Linux paths). If any declares `hooks` or holds malformed JSON, the step fails closed (`managed_hooks_present`); if a candidate file or a `managed-settings.d` directory exists but cannot be read or listed (e.g. a permission error — only a genuine "not found" counts as absent), it fails closed (`managed_policy_unreadable`). On Windows, if the `SOFTWARE\Policies\ClaudeCode` registry key exists at all under `HKLM` or `HKCU` it fails closed (`managed_policy_present`) without inspecting its contents. In every case transcript text is never sent. On an organization-managed Claude account, server-delivered policy hooks could observe this prompt; this feature is intended for personal accounts.
- **Cloud disclosure names the full payload** — the setup toggle help and README now list every category that leaves the machine (verbatim transcripts, correction pairs, replacement pairs, instruction themes, and the learned-rule snapshot) and note the "up to 8 by default (configurable)" limit, instead of naming transcripts alone.

### Changed (VF-11 - snappier dictation)
- **Paste returns as soon as the keystroke is sent** - the 150 ms clipboard-restore wait moved to a timer (it was most of the ~190 ms median paste step). The restore is never dropped: a second dictation inside the delay inherits the still-pending original instead of snapshotting the first dictation, and a pending restore is flushed at shutdown. `press_enter_after_paste` keeps the old inline wait.
- **Idle warm-up is hidden** - after a long idle the ASR runtime is warmed in the background when the hotkey goes down, not inside the release-to-text path (329-439 ms, 11 of 57 dictations in the VF-10 log).
- **Key release no longer depends on the poller** - the hook path used to record the first key-up and wait for *another* key event to finish; after the last key-up none comes, so the 30 ms poller completed every release. A one-shot timer now finishes it, the "physical" check asks Windows (`GetAsyncKeyState`) instead of the keyboard library's own hook-fed table, and `on_start`/`on_stop` no longer run under the listener lock on the hook thread. Polling backup kept.
- **One shared microphone stream** - recording no longer opens a second `sounddevice` stream next to the pre-roll stream; the capture worker switches routing from the pre-roll buffer to the recording ring in one locked step. `audio_single_stream=False` restores the old behaviour. Overflows are now explained in the log (`audio_overflow_detail`: when, queue depth, longest callback gap).
- **Custom vocabulary via hotwords** - `asr_hotwords` (VoiceFlow, Wispr, Claude, Codex, Atlas, LIMS, Veeva) is passed to faster-whisper on every decode window (`initial_prompt` only conditions the first 30 s window). A transcript that is only the hotword list read back is discarded. The misheard app name ("voice flona") is repaired by a built-in rule that reaches existing installs.
- **Overlay** - the dock shows the build's last-updated date (from the bundle stamp) instead of the version string, the "History"/"Last x -> y" detail text is gone, and the overlay's static "Ctrl+Shift" hint is a live recording timer (`7s`, then `1:05` from 60 s). Animation and start beep unchanged.
- **Nightly learning no longer reports "CUDA unavailable"** - source/venv processes also probe `<checkout>\dist\VoiceFlow\_internal\torch\lib` (and `VOICEFLOW_CUDA_DLL_DIR`) for the CUDA runtime the packaged app already ships. `VOICEFLOW_CUDA_PROBE_BUNDLE=0` disables it (the test suite does).

### Fixed
- **Live preview had no VAD in the packaged build (VF-09/VF-10)** — the Silero model `faster_whisper/assets/silero_vad_v6.onnx` was never bundled (`--collect-data faster_whisper` added), so every session logged `[ONNXRuntimeError] NO_SUCHFILE` and fell back to VAD-less previews.
- **Builds can no longer ship broken (VF-09/VF-10)** — `build_windows_exe.ps1` now runs `scripts/setup/verify_bundle.py` after PyInstaller and exits non-zero if the VAD asset, onnxruntime/ctranslate2 natives, the CUDA runtime DLLs (checked by loading them) or the app's modules are missing. A missing CUDA runtime fails the build unless `-AllowCpuOnly` is passed; `-SkipCudaRuntime` alone is now an error. The build also runs the frozen EXE's `--self-check` (one-dir and `-OneFile` alike) in a sandboxed environment and fails if it exits non-zero: in-bundle module imports, Silero VAD run through the bundled onnxruntime, and the bundled CUDA DLLs loaded from the bundle only. The self-check returns before tray, hotkey or microphone setup.
- **Dropped audio frames (`input overflow`) (VF-10)** — the PortAudio callbacks ran the logging validation guard twice per 32 ms block, logged from the audio thread and printed every 200 blocks; they also took the ring-buffer lock, so a slow reader (streaming preview) could stall the audio thread for 100 ms+. Callbacks now only copy the block, put it on a lock-free queue (`queue.SimpleQueue`) and count status flags; a capture worker thread moves blocks into the ring. `stop()` waits (bounded) for the queue to drain before reading the audio, and blocks from a previous recording can never leak into the next. The queue is bounded (`audio_queue_max_seconds`, default 4 s): if the worker falls that far behind, blocks are dropped and counted rather than growing memory. Overflows and drops are reported once per recording at stop (`audio_input_overflow …`, `audio_queue_saturated …`) and cumulatively in `longrun_health` (`audio_overflow_recording`, `audio_overflow_continuous`, `audio_status_other`, `audio_callback_errors`, `ring_wraps`, `audio_queue_dropped_recording`, `audio_queue_dropped_continuous`, `audio_queue_high_water`, `capture_worker_alive`). Stream latency is explicit (`audio_input_latency`, default `high`).
- **False "Hang detected" on long dictations (VF-05/VF-10)** — the watchdog flagged any hold past 120 s. A recording is now healthy while audio blocks keep arriving; it is flagged only if the stream stalls for 15 s or the hold passes 30 minutes (stuck key). Processing/injection timeouts are unchanged.
- **Long holds no longer lose audio silently** — memory stays fixed at the ring-buffer capacity (`max_recording_seconds`, default 300 s); a longer hold keeps the latest audio and logs `recording_ring_wrapped lost_seconds=…`.
- Gemini API key is sent in the `x-goog-api-key` header instead of the URL query string.
- `OllamaClient.refresh_availability()` reset the wrong attribute (`_availability` → `_available`).

### Added
- `scripts/dev/log_latency.py` — release-through-injection latency (`total_ms + inject_ms`) from a log's `transcription_timing` lines, reading numeric fields only (never transcript text). `total_ms` alone is processing time and excludes injection.

### Documentation
- README now states exactly what leaves the machine, when, and how to verify it from the nightly report.

---

## [3.2.1] — 2026-04-06

### Added
- **Spring physics waveform** — each of 28 bars has individual stiffness/damping; burst energy injected on speech onset with random velocity kicks
- **Sympathetic vibration** — neighboring bars mutually influence targets each frame, creating traveling ripple propagation
- **Spark particle system** — pool of 28 sparks spawned on burst onset and dripped continuously during speech; outward arcs from edge bars with drag and hangtime
- **Streaming preview quality** — filler words (uh/um/er) stripped in real-time; safe cleanup applied to live preview so it reads like final output
- **Corrected text during COMPLETE** — final cleaned text visible in preview overlay during the 2-second completion window
- **Focus hardening** — overlay re-lifts every 300 ms during active recording to survive UAC dialogs and notification banners

### Fixed
- **Launcher crash** — `_app_entry.py` bypasses false-positive single-instance detection caused by py.exe shim spawning real Python child with identical cmdline; `VoiceFlow.bat` updated to use it
- **Hint label blur** — transparent background on "Ctrl+Shift" label caused Windows compositing anti-aliasing artifacts at small font sizes; fixed to opaque panel surface
- **Memory growth on long sessions** — `queue.Queue(maxsize=500)` caps audio frame backlog during Whisper inference; high-frequency updates drop silently when full

### Changed
- Overlay max height reduced to 215 px (was 290 px)
- Preview box shows 3 comfortable lines of text
- Overlay positioned tighter to dock with reduced gap

---

## [3.2.0] — 2026-04-04

### Added
- **Ripple-ring animation** — center orb with expanding concentric rings; ring expansion rate and brightness respond to audio level in real time
- **Streaming preview overlay** — partial transcription visible while speaking, updates word-by-word
- **Audio preprocessing pipeline** — VAD filter, silence trimming, and chunk compaction before ASR
- **Adaptive learning daily reports** — nightly batch writes `daily_learning_reports/daily_learning_YYYY-MM-DD_*.json` summarizing learned patterns
- **Idle-aware monitoring** — hang detection and memory warning callbacks for 24/7 operation
- **Audio start/stop beeps** — brief confirmation tones on recording start and stop
- **Continual learning audit trail** — `adaptive_audit.jsonl` tracks every raw→final delta with learned pairs

### Changed
- **UI layout** — overlay now 108–144 px tall (was 142–182 px); wave canvas shrunk to 58 px; overlay-to-dock gap reduced to 2 px
- **Animation** — replaced cluttered bar+orb+spark+trail stack with clean ripple-ring design
- **Streaming context window** — expanded to 8 s with VAD filter for more accurate partial results
- **AGC scaling** — dynamic silence-floor estimation gives calmer idle visual and sharper speech reactivity
- **Cleanup defaults** — light typo correction and safe second-pass cleanup now on by default

### Fixed
- Duplicate-instance watchdog now correctly keeps oldest leaf process instead of newest
- Bootstrap-parent watchdog no longer fires spuriously on fast startup paths
- `transcription_corrections.jsonl` path now resolves correctly under `%LOCALAPPDATA%\VoiceFlow\` (migration from old `LocalFlow` directory name handled automatically)
- Canvas items that fade to zero opacity are moved off-screen rather than drawn at size 0

### Removed
- Geometric node/arc motif animation
- Spark particle system
- Trailing sine-wave overlay
- "Space HUD" look with star field and arcs

---

## [3.1.8] — 2026-03-15

### Added
- GPU acceleration with CUDA 11.8+ support
- Setup wizard with hardware detection and profile selection
- Cold-start elimination via model pre-warming
- Text injection via Windows clipboard (pywin32)

### Changed
- Switched ASR backend to faster-whisper (Distil-Whisper Large v3.5)
- Tray redesigned as primary control surface

### Fixed
- Hotkey listener race condition on rapid press/release
- Overlay positioning on multi-monitor setups

---

## [3.0.0] — 2026-01-20

### Added
- Initial public release
- Push-to-talk with Ctrl+Shift hotkey
- Local whisper inference (no cloud)
- Basic tray icon and setup wizard
- Windows-only text injection
