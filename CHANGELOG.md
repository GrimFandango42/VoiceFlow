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
- **One model on a GPU (VF-18)** — the short-utterance fast path (`latency_boost_enabled`, a second `tiny.en` model) now defaults to off. On this GPU the main model is ~65 ms slower than tiny.en on 2–4 s clips, so the second model cost a preload thread, a warmup, VRAM and accuracy for almost no gain. The GPU setup profile turns it off and a one-time migration (`single_model_migration_version`) turns it off in saved configs that are on a working GPU; CPU setups keep it (it saves ~1 s per clip there) and a later explicit opt-in is never overridden. Live previews fall back to the main model when the fast path is off.

### Fixed
- **Main model silently dropped to CPU at startup (VF-18)** — the main model and `tiny.en` preload on two threads and both entered `huggingface_hub.snapshot_download`, whose `disabled_tqdm` class shares a class-level `_lock`; one thread died with `type object 'disabled_tqdm' has no attribute '_lock'`, which the engine treated as a CUDA failure and demoted to CPU int8 for the life of the process (warmup 4.6 s vs 0.1 s). All model construction now runs under one process-wide lock and loads from the local cache first (`local_files_only=True`), using the network only when the model is not cached.
- **CPU fallback is no longer silent or permanent (VF-18)** — a CUDA init failure that is not out-of-memory or a missing runtime is retried on CUDA once before falling back. A fallback logs a WARNING, sets a standing tray tooltip, shows a balloon and an overlay message, and the app retries the GPU every ~2 minutes while idle (builds the CUDA model first, swaps only on success). Each engine now owns a copy of its `ModelConfig`; a fallback used to write `device=cpu` into the shared module-level entry.
- **Model label, config value and loaded weights now agree (VF-18)** — `distil-large-v3.5` never loaded v3.5 (no CTranslate2 export existed); it loaded the v3 weights. It is now a documented legacy alias of `distil-large-v3` (`canonical_model_key`), the balanced tier and the GPU setup profile name `distil-large-v3`, the wizard's download map no longer points at a repo that does not exist, and startup logs `model_selection … agrees=True|False`. The real v3.5 export is opt-in as `distil-large-v3.5-ct2`. Default weights are unchanged: on a small synthetic set v3.5 decoded at the same speed with at most a couple of words fewer errors, which is not enough to switch (see `docs/VF-18-report.md`).
- **Missing CUDA runtime and decode-time out-of-memory no longer fall to CPU silently (VF-18)** — an explicit `device=cuda` with the CUDA runtime missing now enters the same announced, retried CPU-fallback state as a failed model load (it used to be rewritten to plain CPU with no warning). faster-whisper decodes lazily, so an out-of-memory raised while iterating the segments escaped the fallback; the iteration now runs inside it and the clip is re-run on CPU.
- **Saved `model_name: distil-large-v3.5` is rewritten to `distil-large-v3` (VF-18)** — on the first launch of this build `config.json` is migrated (`model_name`, `fast_model_name`, `quality_model_name`) so the saved value matches the weights that actually load. `distil-large-v3.5-ct2` (the real v3.5 export) is not touched.
- **Launch diagnostics for "no log / no history when started by the watchdog, Task Scheduler or Explorer" (VF-18)** — every launch appends to `logs/boot_breadcrumb.log` with plain file I/O before the app's logging exists (stdout/stderr state, cwd, crash traceback), runs a startup self-check that writes a log record and a history-store record and reads both back (plus the `active_log_path.txt` pointer), and writes `startup_selfcheck.json` and `launch_contexts.jsonl` (parent process, session, console, environment variable *names* only) so launches can be compared. A failed self-check shows a tray warning. The root cause of the original symptom is not yet identified; these make the next occurrence diagnosable.
- **Dictation history failures were invisible (VF-18)** — `_append_history_store` ignored `append_jsonl_bounded`'s return value, and a long dictation (row over 8 KB) was dropped without a trace. Rows are now shortened (`truncated: true`) instead of dropped, writes are read back, and a failure logs an ERROR and raises a tray warning (at most once a minute).
- **A soft final word could be deleted by pause compaction (VF-17)** — on dictations long enough to be compacted, the "blip" filter (speech runs under 120 ms are zeroed) removed a short, unstressed last word that followed a pause ("...end of the", "...is good"). The last 1500 ms now use a relaxed threshold and bypass the filter (`pause_compaction_tail_protect_ms`, `0` = old behaviour). On offline TTS speech with a real Whisper this took tail-word retention from 83% to 100% for words down to -15 dB below the sentence, and left the -20 dB case unchanged (decoder limit). A trailing-silence pad before ASR (`asr_tail_pad_ms`) was measured and did not help, so it ships off. Review round: a faded last word (the speaker lets their voice drop on "...of the", "...for now") is now levelled before ASR (`lift_quiet_tail`, `asr_tail_lift_db` = 9, 0 = off): frames within the last 1.8 s that are clearly speech but >6 dB under the clip's speech level are lifted toward it, never above +9 dB, and anything near the noise floor is left alone. On the evaluator's tail set this took retention from 77.8% (base) / 88.9% (compaction fix alone) to 100%.
- **Live preview had no VAD in the packaged build (VF-09/VF-10)** — the Silero model `faster_whisper/assets/silero_vad_v6.onnx` was never bundled (`--collect-data faster_whisper` added), so every session logged `[ONNXRuntimeError] NO_SUCHFILE` and fell back to VAD-less previews.
- **Builds can no longer ship broken (VF-09/VF-10)** — `build_windows_exe.ps1` now runs `scripts/setup/verify_bundle.py` after PyInstaller and exits non-zero if the VAD asset, onnxruntime/ctranslate2 natives, the CUDA runtime DLLs (checked by loading them) or the app's modules are missing. A missing CUDA runtime fails the build unless `-AllowCpuOnly` is passed; `-SkipCudaRuntime` alone is now an error. The build also runs the frozen EXE's `--self-check` (one-dir and `-OneFile` alike) in a sandboxed environment and fails if it exits non-zero: in-bundle module imports, Silero VAD run through the bundled onnxruntime, and the bundled CUDA DLLs loaded from the bundle only. The self-check returns before tray, hotkey or microphone setup.
- **Dropped audio frames (`input overflow`) (VF-10)** — the PortAudio callbacks ran the logging validation guard twice per 32 ms block, logged from the audio thread and printed every 200 blocks; they also took the ring-buffer lock, so a slow reader (streaming preview) could stall the audio thread for 100 ms+. Callbacks now only copy the block, put it on a lock-free queue (`queue.SimpleQueue`) and count status flags; a capture worker thread moves blocks into the ring. `stop()` waits (bounded) for the queue to drain before reading the audio, and blocks from a previous recording can never leak into the next. The queue is bounded (`audio_queue_max_seconds`, default 4 s): if the worker falls that far behind, blocks are dropped and counted rather than growing memory. Overflows and drops are reported once per recording at stop (`audio_input_overflow …`, `audio_queue_saturated …`) and cumulatively in `longrun_health` (`audio_overflow_recording`, `audio_overflow_continuous`, `audio_status_other`, `audio_callback_errors`, `ring_wraps`, `audio_queue_dropped_recording`, `audio_queue_dropped_continuous`, `audio_queue_high_water`, `capture_worker_alive`). Stream latency is explicit (`audio_input_latency`, default `high`).
- **False "Hang detected" on long dictations (VF-05/VF-10)** — the watchdog flagged any hold past 120 s. A recording is now healthy while audio blocks keep arriving; it is flagged only if the stream stalls for 15 s or the hold passes 30 minutes (stuck key). Processing/injection timeouts are unchanged.
- **Long holds no longer lose audio silently** — memory stays fixed at the ring-buffer capacity (`max_recording_seconds`, default 300 s); a longer hold keeps the latest audio and logs `recording_ring_wrapped lost_seconds=…`.
- Gemini API key is sent in the `x-goog-api-key` header instead of the URL query string.
- `OllamaClient.refresh_availability()` reset the wrong attribute (`_availability` → `_available`).

### Added
- **Faithful dictation (VF-17)** — see [docs/FAITHFUL_DICTATION.md](docs/FAITHFUL_DICTATION.md).
  - **Reconstruction pass** (`ai/reconstruction.py`, on by default, `reconstruction_enabled`): after the normal text pipeline, a local Ollama model (CPU only — the GPU belongs to Reachy) proposes a legible rendering: casing, punctuation, run-ons, broken conjunctions, dropped function words, mis-hearings of vocabulary terms. It relaxes VF-12 item 4 from "never rewrite meaning" to **"never change meaning, but do repair form"**; the meaning half is enforced in code (numbers, URLs, paths, code-ish tokens and proper nouns must survive verbatim; word count 0.8x–1.4x; no new named entity; cap on novel content words). Any guard failure, timeout or Ollama error pastes the pre-reconstruction text unchanged.
  - **Guard hardening (review round 3).** A content word may now only become a vocabulary term or a term already in the same dictation (`the cat is here` -> `the car is here` is rejected); small-word swaps are limited to contractions and homophones (`he` -> `she`, `can` -> `can't` are rejected). Raw-ASR protection is multiset-based, compares spoken and typed numbers by value (`nine` == `9`), and covers sentence-initial names. `scripts/vf_eval.py` now fails the gate when either window-switch safeguard is false, missing or crashed.
  - **Guard hardening (review round 4).** Insertions are limited to the neutral connectors `and`/`to`/`of`; `not`, `maybe`, `always`, `because`, `should` etc. can never be added, even if they appear in the vocabulary (`I will ship today` -> `I will not ship today` is rejected). A content word may only be respelled to a vocabulary term or a name/identifier the speaker used (protected token, proper noun, sentence-initial name), not to an arbitrary earlier word (`The cat and car are here. The cat is red.` -> `...The car is red.` is rejected). The async outcome (accepted/rejected/timeout) is now always written to the tuning log, also when the paste fell back to the clipboard; only the "replace last paste" offer is withheld. `verify_bundle.py` turns a hung CUDA DLL load into a failed `cuda_runtime_dlls` check instead of raising `TimeoutExpired`, and the malformed-DLL tests no longer load DLLs natively.
  - **Never slows the paste.** `reconstruction_mode: auto` pastes immediately and goes synchronous only after ≥5 timed runs have p95 ≤ `reconstruction_budget_ms` (800). Otherwise an accepted result becomes a pending improvement: overlay note, tray entry **Replace last paste with improved version**, and `Ctrl+Alt+R` (`replace_last_paste_hotkey`). The swap is refused — improved text goes to the clipboard instead — unless the same window is focused, nothing was typed since, and the paste is recent, single-line and unchanged.
  - **Full-fidelity tuning log** (`ai/tuning_log.py`, `tuning_log.jsonl` under `%LOCALAPPDATA%\VoiceFlow`): untruncated raw / pasted / reconstructed / user-edited text (cap 8000 chars) plus the existing metadata. Local only — never uploaded. Rotates at 2000 entries or 30 days into one previous generation.
  - **Hotword promotion** (`ai/hotword_promotion.py`): repeated phonetic misses of a term, seen in ≥3 distinct utterances (or 2 explicit edits) and not ambiguous, are appended to `custom_vocabulary.txt`. The nightly learning report says how many were promoted, or why none were.
  - **Review-round hardening.** The reconstruction guards now also check the *raw ASR text* (digits, protected tokens and proper nouns that were in the raw must be in the candidate, even if text processing had already lost them), never allow an inserted determiner (a/an/the) and never allow an inserted word beside a name, number or technical term ("over WebSocket" -> "over a WebSocket" was a measured regression). Replace-last-paste now also refuses after any mouse click (system-wide low-level hook), a focus change or a caret move (`GetGUIThreadInfo`), stages the replacement on the clipboard and re-verifies before it deletes anything, and copies instead of replacing in typing mode or when it cannot prove the spot is unchanged. The bundle build now ships the stamp as a runtime hook so `CArchiveReader(exe).toc` lists `_build_stamp`, and `verify_bundle.py` fails a bundle without it. `vf_eval.py` exits non-zero when a fixture regresses or tail retention is below 100%.
  - `scripts/vf_eval.py` / `make vf-eval` — before/after scenario table (WER, tail-word retention, legibility proxy) on offline TTS speech + CPU Whisper + local Ollama.
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
