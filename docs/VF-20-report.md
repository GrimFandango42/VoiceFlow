# VF-20: one line of VoiceFlow - land the integration branch on main

PR body for `claude/vf-20-land-integration` -> `main`. This branch is
`origin/claude/vf-19-integration` (cf94d78, what the daily binary is built from)
with `origin/main` (836af76) merged in. After this merges, `main` contains the
daily build's code and there is one line of development again.

## What main gains

The integration branch is 83 commits past the common base (026260e, VF-15).
About half of them are already on `main` in squashed form; the rest are new to main.

### Already on main (content identical; arrives here as the original commits)

| Group | Commits | On main as |
|---|---|---|
| VF-11 / VF-11b: snappier dictation, overlay timer, vocabulary, paste returns early, deferred clipboard restore, shared mic stream, exact-build verification | 627c9dc .. 15be897, 385734b, 23dc5c4 | #23 (da1a97c). `385734b`/`23dc5c4` are patch-id identical to `897000d`/`d35718e` on vf-11b-isolated. |
| VF-15: CI green without CUDA/mic/local state | 6e1987d, 2f3cb3e, a605c3f | #21 (026260e) |
| VF-18: GPU every launch, launch log/history, one model on a GPU (item 7) | 84625c7 .. bb31b88 | #24 (836af76) |
| silence-artifacts line carried by the VF-18 branch: PTT lost-Shift fix, watchdog, startup without stdout, logging proof, root-launcher fix, build no-silent-CPU, cold builds, docs scrub | d75c6a4, c038bbd, 455b4ae, 7427ba3, 393313e, 03a324c, 350faad, cde7104, 9c99982, 919ebd6, b460a24, 132e690, 614f6ef, 40389a4 | #24 |

### New to main

| Group | Commits | Relay order |
|---|---|---|
| **VF-12 daily driver** (vf-10-daily-driver): pause-segmented long dictation with tail capture and right context; history store, re-paste, Recent menu (all 50); release-window targeting sampled at key release and pinned synchronously; release callback on the ordered callback thread; Esc cancel; conservative prompt formatting, spoken commands, learned hotwords; Silero VAD gate on noise/silence; eval harness | 39c4ee7, b9d2c24, 2eb4b56, 28f08e6, 4ddf44e, 5bb34ce, 9acea7e, 1f3fb19, d35d736, cc56f91, 6a1ef05, fbda8f0 (merge 616a288) | **VF-12 - landed by this PR** |
| **VF-16 overlay**: smoother overlay animation, recording duration in the dock | 91f5470 (merge 1e185de) | **none - never had an order; landed by this PR** |
| VF-17 faithful dictation, rounds 1-4: soft final word kept by pause compaction, local tuning log, reconstruction pass with code-enforced guards (opt-in since 77810ca), async replace-last-paste, hotword promotion, `make vf-eval` | 508df27, 94389eb, e7ab6dc, afb8e64, 8160603, ba99529, 629aec5, 6ef0fb4, b031340, 41b5a56, a12e69e (merge a44a8c7) | VF-17 |
| VF-19 integration work: LiveCaptionSession (commit-as-you-go live caption), failed dictations recorded in history, paragraphs in long dictations, last 30 recordings kept for replay, VF-19 GPU settings migration, breath-pause seam mend, silent hold pastes nothing, overlay and mic start before the target-window lookup, background reconstruction off by default, spoken lists become list lines | a4dc41b, 5a7e75e, 38c48bf, bf69f79, 3fe4f48, 4c37b06, 4707010, 77810ca, cf94d78 | no order (integration-branch work) |
| Build: snapshot pruning opt-in (default keeps all), verify the bundle the build makes, frozen self-check finds CUDA at bundle root | 6342f64, f7678e0, 133c975, d711d93, e869cc1 | VF-12 review fix 4 / VF-19 |

Not on either line and not landed here: `1692f99` (VF-17 review round 5,
`origin/claude/vf-17-faithful-dictation`). Flagged so it is not lost.

## The merge: what main had that this branch did not

`origin/main` is tree-identical to `origin/claude/vf-18-fast-every-launch` (b696654).
The only behaviour on main missing from the integration branch was:

- **8771113** (VF-18 review finding 2): the one-model migration marker is recorded
  only after CUDA is confirmed and the fast path is actually off; a CPU-fallback
  launch or a raising CUDA probe leaves it unset. Applied on top of the integration
  versions of `utils/settings.py`, `CHANGELOG.md` and
  `tests/runtime/test_vf18_fast_every_launch.py` (applied cleanly).
- A 0.1 s wait in `test_stale_modifier_cannot_start_recording_on_single_key_tap`
  so the negative assertion gives the async `on_start` a chance to fire wrongly.

Every non-conflicted file merged to exactly the integration version (zero diff).

## Conflict calls (16 files)

Every hunk where `main` had text the integration side lacked was read. In all 16
files main's side was the *older* state of the same code (from the squashed
VF-11b/VF-18 branches) that the integration branch later changed on purpose.
There was no case of main carrying a newer decision, so no file needed main's
version except the two deltas above.

| File | Call | Why |
|---|---|---|
| `scripts/setup/build_windows_exe.ps1` | integration | **Deviates from the literal "main wins on packaging" rule; main had no newer packaging decision here.** Main's side is pre-VF-12-review: `KeepPackages` default 2 (deletes ~2 GB snapshots by default) vs. integration's opt-in default 0 (VF-12 review fix 4, 133c975); main lacks the exe-archive `_build_stamp` runtime hook and `VOICEFLOW_EXPECT_COMMIT` (VF-11b exact-build verification / VF-17 review round) and the `VOICEFLOW_SKIP_SETUP_UI` smoke-test fix. Taking main would remove those checks and make the build destructive by default. All VF-18 launch/GPU packaging changes are on both sides and are kept. |
| `tests/runtime/test_verify_bundle.py` | integration | Main lacks the exact-build-fails-closed and bounded-DLL-check tests that go with the build script above. |
| `Makefile` | integration | Main lacks the VF-17 `vf-eval` target only. |
| `CHANGELOG.md` | integration + 8771113 line | Integration has VF-12/16/17/19 entries; main's VF-18 one-model line updated per 8771113. |
| `core/config.py` | integration | User-visible defaults: `pause_compaction_keep_silence_ms` 250 (main 80), `latency_boost_tiny_max_audio_seconds` 1.2 (main 3.0), longer `asr_hotwords` - all measured VF-12/VF-17 decisions. `latency_boost_enabled` stays `False` on both sides. |
| `core/asr_engine.py` | integration | Main lacks VF-17 tail lift / tail pad and learned-hotword lookup. VF-18 GPU/launch code identical on both sides. |
| `core/textproc.py`, `core/vocab.py` | integration | Main has the pre-VF-12 bullet/ordinal formatting and capitalisation; integration has VF-12 conservative formatting and cf94d78 list lines. |
| `integrations/hotkeys_enhanced.py` | integration | Superset: ordered callback thread and release-window sampling (VF-12) on top of VF-11b release reliability and the VF-18 lost-Shift fix. Main differs only by an import line. |
| `ui/cli_enhanced.py` | integration | Main has the old `StreamingTranscriber` preview and the old inject-failure branch; integration has LiveCaptionSession, history-first paste (text on disk before the paste), failure reasons, Recent/re-paste. |
| `ui/tray.py` | integration | Main lacks the VF-17 "Replace last paste with improved version" item. |
| `ui/visual_indicators.py` | integration | VF-16 overlay animation and dock timer (the overlay Nithin uses daily); main has the earlier waveform loop. |
| `utils/settings.py` | integration + 8771113 | VF-19 migration kept; VF-18 marker fix applied. |
| `tests/runtime/test_hotkey_release_reliability.py` (add/add) | integration | Integration version is main's plus the VF-12 release-window tests. |
| `tests/runtime/test_hotkeys_enhanced.py` | integration + 0.1 s wait | See above. |
| `tests/runtime/test_vf18_fast_every_launch.py` (add/add) | integration + 8771113 tests | Three new tests from 8771113. |

Single-Whisper-model decision (2026-11-10) holds: `latency_boost_enabled = False`
default, GPU profile off, one-time migration (now with the 8771113 marker fix).

Also in this change: two unused imports removed (`hotword_promotion.py`,
`reconstruction_runtime.py`) so `ruff check src/` (CI "Lint and type check") passes.

## For the reviewer: paths where a regression costs words

Integration-only commits touching audio capture, hotkeys or paste (the rest is
already in daily use):

- Hotkeys / release: 1f3fb19, d35d736, fbda8f0 (release window sampled at key
  release and pinned synchronously; callback on the ordered thread), a4dc41b (test).
- Capture: 39c4ee7, b9d2c24 (tail capture, stop_drain 0.25 s), cc56f91 (Silero VAD
  gate), 4c37b06 (silent hold pastes nothing; mic and overlay start before the
  target-window lookup), 5a7e75e/38c48bf (live caption reads the ring buffer).
- Paste: 28f08e6 (history-first paste, re-paste, window targeting, Esc cancel),
  afb8e64/b031340 (async replace-last-paste; reconstruction is opt-in since 77810ca).

Follow-up worth an order (not changed here): `_apply_vf19_migration` records its
marker before the CUDA probe, the same pattern 8771113 fixed for the VF-18
migration; a CPU-fallback launch would leave pause compaction on permanently on a
GPU install.

## Verification

Local, on the merge result (system Python 3.13, CI's selection):

- `ruff check src/`: all checks passed (after the two unused-import removals).
- `pytest tests/ -m "not audio and not gui and not slow"`: **1004 passed, 12 skipped,
  3 failed**. The 3 failures are `TestExeSelfCheckFlag` tests in
  `test_verify_bundle.py` (`test_self_check_from_source_writes_report`,
  `test_self_check_never_starts_tray_hotkeys_or_microphone`,
  `test_cpu_only_flag_downgrades_only_the_cuda_check`). Each fails on the
  `vad_asset` check with `missing: ...\faster_whisper\assets\silero_vad_v6.onnx`:
  this machine's faster-whisper 1.2.0 has only `silero_encoder_v5.onnx` /
  `silero_decoder_v5.onnx`. 11 sibling tests skip for the same reason
  ("faster-whisper VAD asset not installed in this venv"). The `silero_vad_v6.onnx`
  check and these tests are the same on `origin/main` (the integration diff in
  `voiceflow_exe_entry.py` only changes the self-check module list and the CUDA DLL
  location), and the merge leaves both files exactly as on the integration branch.
  Whether CI's fresh `pip install -e ".[test]"` resolves a faster-whisper that ships
  `silero_vad_v6.onnx` was not verified here: CI status could not be read from
  this session.
- Merged deltas specifically: `test_vf18_fast_every_launch.py`,
  `test_hotkeys_enhanced.py`, `test_vf15_ci_hygiene.py`: 61 passed.
- `git diff --check`: clean.

Not run here: mypy (CI's "Lint and type check" job runs only `ruff check src/`;
`[tool.mypy]` exists but is not gated), CI (branch not pushed), the Runtime Tests workflow's unfiltered
`pytest tests/runtime` (includes audio/gui markers), the build script, the frozen
EXE, GPU behaviour, real paste into a target window.

## Relay bookkeeping (to be applied by the conductor; outside this worktree)

- VF-12 order: status `merged`, note "landed via VF-20".
- VF-14 order: checkout line -> `C:\AI_Projects\_wt\VoiceFlow-vf14`, branch
  `claude/vf-14`, created fresh off `main` after this PR merges.
