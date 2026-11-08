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

### Changed (VF-12 - dictation for long AI conversations)
- **Long dictations are decoded pause by pause** - recordings of 20 s or more are cut at their own pauses (`core/segmenter.py`) and each piece is decoded on its own with the same vocabulary prompt and hotwords. Silence never reaches the decoder (no "Thank you." in a 15 s thinking pause), a piece the silence-artifact classifier rejects is dropped and logged (`segment_suppressed`), and pauses of 2.5 s or more become paragraph breaks. This replaces pause compaction on those clips. Pieces are at most 25 s, a pause of 2 s or more always starts a new piece, and continuous speech longer than the cap is cut at its quietest point. Off switch: `segmented_transcription_enabled`.
- **Noise and silence are gated by a real VAD** - Whisper's own `no_speech_prob` is not trusted: on 30 s of stationary noise it reported about 0.04 while emitting "I think. Thank you.". The segmenter now asks Silero VAD (bundled with faster-whisper, offline, CPU): if it hears no speech in a long recording nothing is decoded (`segmentation_fallback_vad_no_speech`); speech the energy detector missed is decoded on its own, not with the noise around it; an energy segment with no VAD speech in it is skipped (`segment_suppressed reason=vad_no_speech`); a spoken "Thank you." is kept. If VAD cannot load, the previous behaviour applies and a `silence_vad_unavailable` warning is logged once. Off switch: `silence_vad_gate_enabled` (also `silence_vad_threshold`, `silence_vad_min_speech_seconds`).
- **Right context for the last word** - every final decode appends 0.4 s of room tone (`decode_right_context_seconds`), pause compaction keeps 250 ms of silence (was 80) and always keeps the real last 450 ms of the recording, and a short final chunk of a chunked retry no longer drops to the fast model while earlier chunks used the primary one.
- **Tiny-model cap 3.0 s -> 1.2 s** (`latency_boost_tiny_max_audio_seconds`) - suspected contributor to end-of-sentence errors (a ~1.5 s question was routed to the tiny model). Measured with real Whisper on TTS speech: in noise the old 3.0 s cap sent 20 of 25 short questions to the tiny model and made 4-5 word errors against 1-2 now (docs/VF-12-real-whisper-results.md; real-voice retest still needed).
- **Post-key-up tail** - unchanged: the listener keeps recording for 0.12 s release-confirm + `ptt_tail_buffer_seconds` (0.35 s) and the recorder drains 0.25 s more, about 0.7 s in total. An earlier VF-12 commit raised the drain and was reverted.
- **Formatting for AI prompts** (`core/dictation_format.py`) - removes `um`/`uh`, function-word stutters ("the, the thing"), verbatim 2-3 word restarts ("I think I think"), a sentence-opening "I mean," and "scratch that"; resolves "send it to John, no wait, send it to Jane". It leaves "that that", "had had", "very very", "no no no", "I guess", "you know" at the start of a clause, and mid-sentence "I mean" alone. Spoken `new line`, `new paragraph` and `bullet, ...` work when said as their own phrase (so "a new line of products" stays literal). `bullet` is a command only with a comma or colon straight after it ("Bullet, buy milk" / "Bullet point: ship it"); "Bullet train tickets are expensive", "bullet wound" and "bullet points are useful" are never rewritten. File names, paths, CamelCase, snake_case and flags are masked through the whole formatter (`config.yaml` used to become `config. YAML`). An unpunctuated question ends with `?`. A lone "First,"/"Second thought," is no longer turned into a bullet; two or more ordinals still make a list. The old rule-based course corrector now delegates to the same conservative code (it used to delete everything before any "I mean" and collapse "had had").
- **Chat windows keep requested line breaks when pasting** (`chat_preserve_newlines`, default on) - spoken breaks and pause paragraphs are kept, because a paste does not press Enter. Typed injection still strips them. Retest in Claude, ChatGPT and Slack.

- **Known trade-off (follow-up candidate)** - each pause-separated piece is a separate decode, and the long-form beam=2 lift is decided per call, so pieces under 12 s decode at beam=1 where one 200 s call used to get beam=2 throughout. Threading a beam override through `decode_audio` is the follow-up.
- **Fixed** - a code-ish token at the start of a sentence (`config.yaml is broken`) no longer makes the formatter capitalise the next word.

### Added (VF-12)
- **Transcript history** - the last 50 dictations are kept in `%LOCALAPPDATA%\VoiceFlow\transcript_history.json` (text, time, word count, paste outcome, target process name; no window titles; local only, atomic writes). The text is saved before the paste is attempted.
- **Alt+Shift+V** re-pastes the last transcript into the window that has focus (`repaste_hotkey`; empty disables). It avoids Ctrl+Shift (VoiceFlow's hold) and Ctrl+Alt (Wispr Flow and the toggles). Tray **Recent** lists the last 10 (click to copy), plus Re-paste and Clear history.
- **Target window policy** - `inject_target_policy`: `release` (default, as the work order requires) pastes into whatever has focus at the moment the key release is confirmed, before the 0.35 s post-key-up tail, so a window switch during the tail does not redirect the text (VoiceFlow's own windows are ignored). `start` pastes into the window that had focus when the hotkey went down. Before this review fix the shipped default was `start`; an existing saved config that already contains `inject_target_policy` keeps its value. If the target window no longer exists nothing is pasted anywhere: the text goes to history and the clipboard and the overlay reads "Target window closed - saved to history".
- **Overlay status after paste** - "Pasted 237 words"; misses say "saved to history".
- **Esc cancels a recording** (`cancel_recording_key`, empty disables) - the recording is discarded and nothing is transcribed. The key is armed only while recording and swallowed so Ctrl+Shift+Esc does not open Task Manager.
- **Corrections stick** - terms you correct twice in the history/correction review are stored locally (`learned_hotwords.json`, never uploaded, independent of the cloud-learning opt-in) and added to the Whisper hotwords (`learned_hotwords_enabled`, `learned_hotword_min_count`, `learned_hotwords_max`). Seed hotwords VoiceFlow, Wispr, Claude, Codex, Gemini, Ollama, Atlas, LIMS, Veeva, Madison are always present, including for configs saved before this change. A corrected proper noun is no longer lower-cased back by the replacement rule.

### Changed (VF-11 - snappier dictation)
- **Paste returns as soon as the keystroke is sent** - the 150 ms clipboard-restore wait moved to a timer (it was most of the ~190 ms median paste step). The restore is never dropped: a second dictation inside the delay inherits the still-pending original instead of snapshotting the first dictation, and a pending restore is flushed at shutdown. `press_enter_after_paste` keeps the old inline wait. If the restore write fails, its bounded retries now run inside the same pending restore (previously an untracked thread), so a dictation that starts during the retry window still inherits the user's original clipboard and the abandoned retry can never overwrite it.
- **Idle warm-up is hidden** - after a long idle the ASR runtime is warmed in the background when the hotkey goes down, not inside the release-to-text path (329-439 ms, 11 of 57 dictations in the VF-10 log).
- **Key release no longer depends on the poller** - the hook path used to record the first key-up and wait for *another* key event to finish; after the last key-up none comes, so the 30 ms poller completed every release. A one-shot timer now finishes it, the "physical" check asks Windows (`GetAsyncKeyState`) instead of the keyboard library's own hook-fed table, and `on_start`/`on_stop` no longer run under the listener lock on the hook thread. Polling backup kept.
- **One shared microphone stream** - recording no longer opens a second `sounddevice` stream next to the pre-roll stream; the capture worker switches routing from the pre-roll buffer to the recording ring in one locked step. `audio_single_stream=False` restores the old behaviour. Overflows are now explained in the log (`audio_overflow_detail`: when, queue depth, longest callback gap). Queue drops on the shared stream while a key is held are charged to the recording (`audio_queue_saturated`, `queue_dropped_recording`), not to the pre-roll (`queue_dropped_continuous`).
- **Custom vocabulary via hotwords** - `asr_hotwords` (VoiceFlow, Wispr, Claude, Codex, Atlas, LIMS, Veeva) is passed to faster-whisper on every decode window (`initial_prompt` only conditions the first 30 s window). A transcript made only of hotwords is discarded only when the decoder reports no-speech evidence (`no_speech_prob` >= 0.6) or when it is the entire list in order, so a dictated "Claude, Codex, Atlas" survives. The misheard app name ("voice flona") is repaired by a built-in rule that reaches existing installs.
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
