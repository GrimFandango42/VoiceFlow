# Testing Notes

## The suite

All maintained tests are in `tests/runtime/` (675 tests at the time of writing; `pytest --collect-only -q` gives the current count). `pytest.ini` sets `testpaths = tests/runtime`, `pythonpath = src`, strict markers and a 300 s per-test timeout.

```powershell
pytest -q tests\runtime                                   # everything
pytest tests\runtime -m "not audio and not gui and not slow"   # what CI runs
pytest -q tests\runtime\test_transcription_lengths.py     # length-specific decode checks
pytest -q tests\runtime\test_docs_links.py                # documentation links and images
python scripts\dev\quick_smoke_test.py                    # quick runtime smoke
```

Markers: `unit`, `integration`, `performance`, `slow`, `windows`, `audio` (needs a microphone), `gui` (needs a display), `e2e`.

The tests set `VOICEFLOW_CUDA_PROBE_BUNDLE=0` and use a temporary data directory (`test_app_data_sandbox.py`), so a test run does not read or write your real `%LOCALAPPDATA%\VoiceFlow`.

## CI

- `ci.yml` - `ruff check src/` (lint gate; `mypy` is configured in `pyproject.toml` but not gated) and the test suite on Windows, skipping audio/GUI/slow tests.
- `runtime-tests.yml` - the full `pytest -q tests/runtime` on Windows for pushes and pull requests to `main`.
- `build-release.yml` - builds the Windows bundle and publishes releases ([Build guide](BUILD_GUIDE.md)).

## Checking the packaged build

```powershell
dist\VoiceFlow\VoiceFlow.exe --self-check=$env:TEMP\voiceflow_self_check.json
python scripts\setup\verify_bundle.py dist\VoiceFlow --json-out build\pyinstaller\verify_bundle.json
```

Both run without the microphone, tray or hotkeys; the build script runs them for you and fails on any problem.

## Documentation checks

```powershell
python scripts\check_docs.py                  # every relative link, image path and #anchor resolves; no unreferenced images
python scripts\capture_screenshots.py         # regenerate docs\screenshots (demo mode; needs a Windows desktop)
```

## Manual dictation matrix

The full packaged-app pass is in the [Windows app test checklist](guides/WINDOWS_APP_TEST_CHECKLIST.md). In short, validate in Notepad and VS Code with a short clip (3-6 s), a medium clip (10-20 s) and a long clip (40-90 s, with pauses and a cough), and check release-to-text latency, transcript quality, injection reliability and that the tray returns to idle.

## Measuring

- **Latency.** `python scripts\dev\log_latency.py <voiceflow.log>` computes release-through-injection latency from `transcription_timing` lines (numeric fields only, never transcript text). Targets and knobs: [Latency budget](LATENCY_BUDGET.md).
- **Real-Whisper comparisons.** `scripts/vf12_make_tts_clips.py` and `scripts/vf12_real_whisper_eval.py` compare two source trees on synthetic speech; reproduction steps and results are in [VF-12 real-Whisper results](VF-12-real-whisper-results.md). TTS speech is a proxy: it does not replace a real-voice retest.

## Logs

`%LOCALAPPDATA%\VoiceFlow\logs\voiceflow.log`. Look for `transcription_engine`, `transcription_timing`, `asr_engine_initialized` (device), and, as problems, `asr_runtime_fallback` (should not appear in normal CUDA runs), `cuda_runtime_unavailable`, `audio_input_overflow`, `audio_queue_saturated`.
