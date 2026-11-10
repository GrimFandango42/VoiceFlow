# VF-18 — fast and recorded on every launch

Executor report, 2026-11-10. Branch `claude/vf-18-fast-every-launch` (base `40389a4`, `origin/main` merged).
Nothing here was run against the live app: no process was stopped, started or
launched, and no scheduled task was touched.

## What changed, by order item

| # | Item | Result |
|---|------|--------|
| 1 | Startup race | **Fixed in code, unit-tested.** One module-level `_MODEL_INIT_LOCK` wraps every `WhisperModel` construction; cached models load with `local_files_only=True`, the network is used only when the model is absent. Per-backend `RLock`s never protected this (each backend has its own). A test shows peak concurrent constructions is 1 with the lock and 2 without. |
| 2 | Silent, permanent CPU fallback | **Fixed in code, unit-tested.** Non-CUDA init errors are retried on CUDA once; out-of-memory / missing-runtime go straight to CPU. A fallback logs `asr_cpu_fallback_active` (WARNING), sets a standing tray tooltip, a balloon and an overlay message, and a `CudaRestore` thread retries the GPU while idle (every ≥120 s, builds the CUDA model first and swaps only if it worked). Also found and fixed: `MODEL_CONFIGS` entries were shared between engines, so a fallback wrote `device=cpu` into the module-level entry. |
| 3 | No log / no history when started by watchdog, Task Scheduler or Explorer | **Root cause NOT found.** Instrumentation added so the next occurrence is diagnosable (below). |
| 4 | Label vs config vs loaded model | **Fixed.** `distil-large-v3.5` never loaded v3.5: no CTranslate2 export existed when the key was added, so it loaded the v3 weights. It is now a legacy alias of `distil-large-v3`; the balanced tier and GPU wizard profile say `distil-large-v3`; the wizard's repo map pointed at a repo that does not exist (`Systran/faster-distil-whisper-large-v3.5`) and now points at the real one. Startup logs `model_selection … agrees=…`. Nithin's `model_name: distil-large-v3.5` now resolves to the weights he is actually running. The real v3.5 export is opt-in as `distil-large-v3.5-ct2`. |
| 5 | Model comparison | See below. **Default unchanged.** |
| 6 | Nearly-full card | See below. Reported, not changed. |

### Item 3: what is and is not known

Checked: nothing was written to the fallback locations (`~\.voiceflow\logs`,
`%TEMP%\VoiceFlow`, `voiceflow-<pid>.log`), so the app is not logging somewhere
else.

Timeline (all 2026-11-07, local time): `393313e` stdout hardening 12:45,
`cde7104` log-delivery check 13:50, **live `dist\VoiceFlow\VoiceFlow.exe` built
17:29:57**, `b460a24` "cold builds by default" 17:48, `132e690` watchdog
`Win32_Process::Create` fix 19:13. So the live exe was built *after* both
logging fixes but *19 minutes before* cold builds became the default. `b460a24`
describes exactly this failure class: a warm PyInstaller cache shipped a bundle
built from modules dated 2026-09-13 ("no logging, no transcription history, no
live caption, and a stamp naming the right commit"). That is a plausible
explanation for the live binary, **but I could not confirm it** (I did not
inspect the bundle's modules), and it conflicts with the order's statement that
the same binary logs when started from a shell. The deciding test is a cold build
from this branch launched from Explorer and from the scheduled task; if it logs,
the cause was the stale build, and the instrumentation below stays as the
alarm.

Added so the next bad launch is explained rather than guessed at:

- `logs\boot_breadcrumb.log` — plain `open(..., "a")` lines written before the
  app's logging exists: stdout/stderr state *as inherited* (before repair), cwd,
  whether `LOCALAPPDATA` is set, and a traceback if `cli_main` dies.
- Startup self-check (after `AsyncLogger`): writes a log record and a history-store
  record, reads both back, checks `active_log_path.txt` points at the live log.
  On failure: `startup_selfcheck_failed` ERROR and a tray warning.
  The history probe uses a sibling file (`startup_selfcheck.jsonl`), not
  `recent_history_events.jsonl`, because that file feeds the history panel and
  the learning pass and a synthetic row would be mistaken for a dictation.
- `startup_selfcheck.json` (latest) and `launch_contexts.jsonl` (every launch):
  parent process, Windows session id, console present, stdout/stderr state,
  environment variable **names only** (plus a short allow-list of non-secret
  values). Comparing a watchdog launch with a shell launch is now a diff.
- History writes are verified. `_append_history_store` used to ignore
  `append_jsonl_bounded`'s `False` return, and rows over 8 KB (a ~1,200-word
  dictation) were silently dropped. They are now shortened (`truncated: true`),
  read back, and a failure is an ERROR plus a tray warning.

To finish item 3, launch once from Explorer and once via the scheduled task with
a cold build that contains this commit, then compare the last two lines of
`launch_contexts.jsonl` and `boot_breadcrumb.log`.

Scope of the self-check: it proves this process can write and read back in the
data directory it resolved. It does **not** prove that directory is the right
one. If a launcher gives the process a different `LOCALAPPDATA`, the self-check
passes and the tray stays quiet; that case is visible in
`launch_contexts.jsonl` (`env_values.LOCALAPPDATA`, `localappdata_set`) and in
where `boot_breadcrumb.log` appears, not in the warning.

## Acceptance grep for the 20 cold starts

Pass, every start (from `voiceflow.log`):
`model_ready key=distil-large-v3 weights=Systran/faster-distil-whisper-large-v3 device=cuda compute=float16 fell_back_to_cpu=False`
(and the same with `fast_model_ready key=tiny.en …` for the fast path).
Fail: any `asr_cpu_fallback_active`, `asr_cuda_init_failed`, or
`startup_selfcheck_failed`. `asr_cuda_init_retry_ok` means the old race fired and
the retry absorbed it (should not happen now that construction is serialized).

## Config value: reconciled, not migrated

Nithin's `config.json` still says `model_name: distil-large-v3.5`. It now
resolves by alias (`canonical_model_key`) to the weights that load, and startup
logs `model_selection … agrees=True`. I did not add a one-time rewrite of the
file to `distil-large-v3`; the wizard writes the new value for new setups.

## Item 5: speed and accuracy (offline, RTX 4080, float16)

No retained feedback audio exists on this machine (`VOICEFLOW_FEEDBACK_AUDIO` is
opt-in; no audio files were found under `%LOCALAPPDATA%\VoiceFlow` or in the repo), so the clips are **synthesized** with the
built-in Windows voices (David, Zira), seven clips, 3.7 s – 35.6 s, known
reference text (`scripts/ops/vf18_make_test_clips.ps1`,
`scripts/ops/vf18_model_compare.py`). This measures decode speed and word
accuracy on clean TTS speech. It says little about a real microphone, accents
or room noise.

| Model | Total decode, 7 clips (median of 3) | Realtime factor | Cold load | WER* |
|-------|------|------|------|------|
| `distil-large-v3` (current) | 1.18 s | 0.014 | 15.1 s | 10.7 % |
| `distil-large-v3.5` (`-ct2`) | 1.15 s | 0.014 | 19.4 s | 9.3 % |
| `large-v3-turbo` | 1.46 s | 0.017 | 21.1 s | 8.4 % |

\*The "invoice" clip contributes ~46 % WER to every model because they write
digits where the reference spells numbers out; that is a formatting difference,
not a hearing error, and it is identical across models.

Per-clip time for the 35.6 s dictation: v3 0.386 s, v3.5 0.382 s, turbo 0.534 s.
Short clips (4–5 s): 0.10–0.11 s for all three.

Word-level differences from the current model (excluding the invoice clip):

- v3 → v3.5: v3.5 fixes "Kubernetes" (v3: "kubearnet's"), "pytest" (v3: "tes"),
  "CUDA" (v3: "kuta") and one dropped phrase in the long clip ("fallback" →
  "back"). Both mishear "Redis" and both drop two words of the long clip
  ("finally", "restart").
- v3 → turbo: turbo fixes "Kubernetes"/"Redis"/"CUDA", but garbles "float16"
  ("fl08016") and is ~25–38 % slower on the long clip.

**Recommendation: keep `distil-large-v3` as the default.** v3.5 is as fast in
practice and a few words better, but the evidence is seven synthetic clips; the
order asks for "clearly more accurate", and that is not shown. `large-v3-turbo`
is slower and not clearly better. `distil-large-v3.5-ct2` is selectable
(`model_name`) if Nithin wants to try it on his own voice, ~200 MB less VRAM than v3.

## Item 6: nearly full card

Measured now, with GLaDOS's `gemma4:12b` + `buddy.py` and the live VoiceFlow resident:
13,322 / 16,376 MiB used, **~3.0 GB free**. Peak VRAM taken by each candidate
(this includes the ~0.3–0.4 GB CUDA context, one model at a time, float16):

| Model | Loaded | After a 35 s decode (beam 2) |
|-------|--------|------|
| `distil-large-v3` | +2,095 MB | +2,241 MB |
| `distil-large-v3.5-ct2` | +1,889 MB | +2,025 MB |
| `large-v3-turbo` | +2,016 MB | +2,152 MB |

What that means:

- **gemma loaded (now):** a second VoiceFlow fits with ~0.8 GB to spare. That is
  the situation during a watchdog restart, when the old and new process overlap.
  It is tight but OK; anything else that takes ~1 GB of VRAM (a game, a browser
  with GPU video) tips it over.
- **Card full at startup:** CUDA init raises an out-of-memory error → classified
  `out_of_memory` → no CUDA retry → CPU int8 fallback, now announced (log, tray,
  overlay) and retried every ≥120 s while idle. Before this change it was silent
  and permanent.
- **Card fills mid-session:** an OOM during a decode is caught by the existing
  runtime fallback (message matches "cuda") and re-run on CPU, now announced the
  same way.
- **gemma unloaded:** ~14 GB free; no pressure.

*Not measured:* the real behaviour with gemma toggled. I did not unload it
(not mine to touch) and did not fill the card with ballast to simulate it,
because that could have starved the live VoiceFlow. The fallback paths are
covered by unit tests with fake models, not by a real OOM.

## Verification

- `pytest tests` (test venv): 423 passed (30 new in `tests/runtime/test_vf18_fast_every_launch.py`).
  One existing test needed a stub for the new startup hook (`test_startup_background_services.py`).
- Race test checked by mutation: without the lock, peak concurrent constructions is 2.
- Merged `origin/main` (7 commits); the only conflict was `scripts/setup/build_windows_exe.ps1`.
  Kept both sides: the DLL-staging from main plus this branch's `-KeepPackages`,
  `Assert-CudaRuntimeComplete` and `Assert-BundleBehaves`; the script parses clean.

## Not tested

- **20 consecutive cold starts of a built bundle** — no bundle was built or launched.
- **Real Task Scheduler and Explorer launches** — not touched; item 3's root cause is therefore open.
- Build: the merged build script has not been run. Note for whoever does: `-SkipProcessCleanup` is a switch and
  cleanup is **on by default**, which kills the live app; pass it. `Assert-BundleBehaves` launches the real app.
- Item 6 with gemma actually unloaded / the card actually full.
- Model accuracy on a real microphone.
