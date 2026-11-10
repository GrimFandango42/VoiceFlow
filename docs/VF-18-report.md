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
| 4 | Label vs config vs loaded model | **Fixed.** `distil-large-v3.5` never loaded v3.5: no CTranslate2 export existed when the key was added, so it loaded the v3 weights. It is now a legacy alias of `distil-large-v3`; the balanced tier and GPU wizard profile say `distil-large-v3`; the wizard's repo map pointed at a repo that does not exist (`Systran/faster-distil-whisper-large-v3.5`) and now points at the real one. Startup logs `model_selection … agrees=…`. The real v3.5 export is opt-in as `distil-large-v3.5-ct2`. Review round 1: the saved value is now **migrated** on next launch (see "Config value" below), not only aliased. |
| 5 | Model comparison | See below. **Default unchanged.** |
| 6 | Nearly-full card | See below. Reported, not changed. |
| 7 | One model inside VoiceFlow | **Done for GPU setups; CPU setups keep tiny.en on purpose.** The main model is ~65 ms slower than tiny.en on 2–4 s clips on this GPU (bar: 150 ms). `latency_boost_enabled` now defaults off, the GPU wizard profile sets it off, and a one-time migration clears it in already-saved GPU configs. See "Item 7" below. |

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

## Config value: migrated (review round 1)

Codex was right that an alias alone masks the disagreement. `load_config` now runs
`_apply_model_key_migration` (`utils/settings.py`): `model_name`, `fast_model_name`
and `quality_model_name` are rewritten through `canonical_model_key`, and the file
is saved when anything changed. So Nithin's `distil-large-v3.5` becomes
`distil-large-v3` the first time the new build starts, and the saved value, the
tray/overlay label, the `model_selection … loaded_key=` log field and the weights
(`Systran/faster-distil-whisper-large-v3`) then name one model. The real export,
`distil-large-v3.5-ct2`, is never touched. The `distil-large-v3.5` entry stays in
`MODEL_CONFIGS` and the guardrail list so an un-migrated config still loads.
Tested against a temp config file (`TestPersistedModelKey`); **I did not run it
against Nithin's real `config.json`**, so the on-disk rewrite on his machine is
unverified until the new build launches.

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

## Item 7: one model (is tiny.en still worth loading?)

Measured offline from the local Hugging Face cache, app decode settings, median of
7 runs (GPU) or 3 (CPU), eight synthesized 2.1–4.2 s utterances
(`scripts/ops/vf18_make_test_clips.ps1 -Set short`, `scripts/ops/vf18_model_compare.py`).
The GPU run was made while GLaDOS's models were resident on the same card, so these
are not best-case numbers. Both models transcribed all eight clips with 0 % WER;
the only differences are capitalisation ("Settings", lowercase first word).

**GPU (RTX 4080, float16), main `distil-large-v3` vs `tiny.en`:**

| Clip | Audio | Main | tiny.en | Main − tiny |
|------|------:|-----:|--------:|------------:|
| s01 "Yes, send it." | 2.17 s | 85 ms | 18 ms | 67 ms |
| s02 | 2.11 s | 85 ms | 18 ms | 67 ms |
| s03 | 3.06 s | 95 ms | 26 ms | 69 ms |
| s04 | 2.78 s | 90 ms | 24 ms | 66 ms |
| s05 | 2.25 s | 86 ms | 20 ms | 66 ms |
| s06 | 4.21 s | 93 ms | 28 ms | 65 ms |
| s07 | 3.42 s | 92 ms | 28 ms | 64 ms |
| s08 | 3.48 s | 92 ms | 29 ms | 63 ms |

**Verdict: the gap is 63–69 ms, well inside the 150 ms bar**, so on a GPU the second
model buys almost nothing and costs a second preload thread, a second warmup, extra
VRAM and a less accurate transcript. (The shortest clip in the order's 1–5 s range is
2.1 s here; the TTS voices do not produce sub-2 s clips with natural padding.)

**CPU (int8), the case that decides the CPU profile:** `tiny.en` 167–179 ms per clip,
`small.en` (the CPU profile's main model) 1.08–1.15 s, `distil-large-v3` 4.7–4.9 s.
tiny.en saves ~0.95 s per short clip there, so the fast path **stays on for the
CPU-compatible profile** and in saved configs that are not on a working GPU.

**What changed:**

- `Config.latency_boost_enabled` defaults to `False` (was `True`). With it off,
  `_init_fast_asr_path` returns before constructing `WhisperASR`/`ModelPreloader`, so
  there is no second preload thread, no tiny.en load, no warmup call and
  `asr_fast is None`. A test patches both constructors to fail and asserts neither runs.
- The `gpu-balanced` wizard profile sets it `False`; `cpu-compatible` keeps `True`.
- **Persisted configs:** `save_config` writes every field, so Nithin's `config.json`
  almost certainly carries `latency_boost_enabled: true` and a default flip alone
  would change nothing for him. `_apply_single_model_migration` (new field
  `single_model_migration_version`) turns it off once when the saved config is a GPU
  setup (`enable_gpu_acceleration` and `device` cuda/auto) **and the CUDA runtime is
  actually usable here**, then records the version, so a later explicit opt-in is
  never overridden. CPU configs and GPU configs without a working runtime are left
  alone. Unit-tested against temp config files only; **not run against his real file.**
- Dead settings found: `enable_dual_model_strategy` and `fast_model_name` are defined
  in `Config` (and `fast_model_name` is rewritten by the model-label migration and the
  wizard) but **nothing reads them**. Left in place: removing config fields is a
  separate cleanup and changes the saved-config schema.

**Every place tiny.en / `asr_fast` is used, and what happens with the fast path off:**

| Use | Code | With fast path off |
|-----|------|--------------------|
| Short-utterance routing (≤3 s for tiny) | `EnhancedApp._pick_asr_engine` | `asr_fast` is `None` → always the main model (tested) |
| Blank-result retry on the main model | `_should_retry_blank_fast_path` | never triggers; the main model already ran |
| Warmup of the fast engine | `cli_enhanced.py` warmup block | skipped (`asr_fast` falsy) |
| Live checkpoint preview ("live caption" partials during long holds) | `_run_checkpoint_preview` | already `asr_fast if ready else asr` → main model |
| Streaming preview partials | `_start_streaming_preview` | already `asr_fast if asr_fast else asr` → main model |
| Dev two-process model server | `model_server._load_models` | gated on the same flag; no fast model loaded |
| CPU-fallback detection | `_fallen_back_engines` | skips `None` |

**Known limitation:** if a GPU machine falls back to CPU at runtime (item 2), the
fast path is not started at that moment, so short clips run on the main model on CPU
until the idle CUDA restore succeeds. That fallback is announced and temporary; I did
not add a lazy fast-path start for it.

**Risk to watch on first real use:** streaming (`enable_streaming`) and live-caption
previews are on by default, so with the fast path off they decode on the main model
every ~0.85 s while the key is held, windows up to 8 s, beam 2, VAD on. What the code
shows: `FasterWhisperBackend.transcribe` holds its `RLock` only while it prepares the
call; the decode itself is consumed outside the lock, so Python does not queue a
release behind a preview. CTranslate2's single worker (`asr_num_workers=1`) does
serialize the GPU work, so a release that lands mid-preview should wait for at most
that one in-flight preview decode. For scale, the main model took 85–95 ms for a
2–4 s clip (beam 1); an 8 s window at beam 2 is larger and **was not measured**. So
the ~65 ms gain on short final decodes is offset by an unmeasured worst-case wait of
roughly one preview decode on release. If dictation feels slower after this lands,
set `latency_boost_enabled` back to true in `config.json` (the migration will not
override it) or turn off `enable_streaming` / `live_caption_enabled`. I could not
exercise this under a live hold without launching the app.

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
- **Card fills mid-session:** *corrected in review round 1.* The first version of
  this report said the existing runtime fallback already covered this. It did
  not: faster-whisper decodes lazily, `transcribe()` returns a generator, and the
  CUDA work (and any OOM) happens while the segments are iterated, which was
  outside the `try`. An iteration-time OOM escaped as an exception with the engine
  still marked CUDA and no event. The segment loop now runs inside the guard
  (`FasterWhisperBackend.transcribe`), `"out of memory"` joined the runtime
  markers, and a decode-time OOM falls back to CPU, re-runs that clip there, and
  is announced like any other fallback. Covered by unit tests with a fake
  generator that raises; **not** reproduced with a genuinely full card.
- **CUDA runtime libraries missing at startup (explicit `device=cuda`):** also
  corrected. This used to rewrite the request to plain CPU before the backend was
  built, so there was no warning and no idle retry. It now enters the same
  announced, retried fallback state (`missing_runtime: …` reason). `device=auto`
  with no CUDA is still plain CPU, not a fallback. In the real app the listener is
  registered (`EnhancedApp.__init__`) before the engine is built, so the event sets
  the standing warning, and the post-tray call to `_apply_device_warning` shows it
  once the tray exists; the event does not need to arrive after the tray.
- **gemma unloaded:** ~14 GB free; no pressure.

*Not measured:* the real behaviour with gemma toggled. I did not unload it
(not mine to touch) and did not fill the card with ballast to simulate it,
because that could have starved the live VoiceFlow. The fallback paths are
covered by unit tests with fake models, not by a real OOM.

## Verification

- `pytest tests` (test venv, `--timeout=120`): **435 passed, 0 failed** after review round 1
  (42 in `tests/runtime/test_vf18_fast_every_launch.py`, 9 of them new this round:
  missing-runtime fallback x4, decode-time OOM x2, persisted model key x3).
  The earlier "423" and "426" figures were counts from before this round.
  Codex could not run five model-loading tests offline (no `tiny.en` cache in its
  sandbox); they passed here, where the cache exists.
  One existing test needed a stub for the new startup hook (`test_startup_background_services.py`).
- Race test checked by mutation: without the lock, peak concurrent constructions is 2.
- Merged `origin/main` (7 commits); the only conflict was `scripts/setup/build_windows_exe.ps1`.
  Kept both sides: the DLL-staging from main plus this branch's `-KeepPackages`,
  `Assert-CudaRuntimeComplete` and `Assert-BundleBehaves`; the script parses clean.

## Item 3 after review round 1: still open, and why

Codex asked for the cause to be found and fixed, then proven with a side-directory
bundle, the real scheduled task, Explorer and 20 cold starts. This run's dispatch
forbids launching any app and touching scheduled tasks (and the standing rule is
never to disturb Nithin's running `VoiceFlow.exe`), so none of that could be done
here. What static reading did establish:

- The repo's watchdog (`scripts/ops/voiceflow-watchdog.ps1`) already launches with
  `Start-Process`; its comment documents the earlier `Win32_Process::Create`
  launch as the one that produced a GPU-less, log-less, history-less process.
  Nothing else under `scripts/` uses `Win32_Process::Create`/`Invoke-CimMethod`.
- Source env/cwd dependencies are few: `LOCALAPPDATA` (data dir; absent means
  `~\.voiceflow\logs`), `Path.cwd()` as one CUDA DLL probe root, and
  `VOICEFLOW_*` switches. None of those explains "no log, no history, no GPU" by
  itself, and no fallback log location held any file.
- `asr_engine.py` uses `Path.cwd()` as one CUDA-DLL probe root, and the working
  directory differs by launcher (shell: repo root; Explorer: the exe folder; Task
  Scheduler: System32 unless the task sets "Start in"). It cannot explain a missing
  log, but it is a concrete GPU-side suspect for a scheduler-launched process.
- Unchecked, and the first thing to check: whether the registered scheduled task
  actually runs this script copy (and its "Start in", logon type and run level),
  and whether the live `dist\VoiceFlow\VoiceFlow.exe` (built 2026-11-07 17:29) is the
  stale-module build `b460a24` describes. I did not query the task: the dispatch
  says not to touch scheduled tasks and I read that conservatively. A read-only
  `Get-ScheduledTask | Where TaskName -like '*VoiceFlow*'` / `Export-ScheduledTask`
  by the conductor answers it in one command.

### Why no bundle was built in this round

Building is not launching, but this build script launches. `Invoke-BundleVerification`
runs `verify_bundle.py`, which executes the frozen exe with `--self-check` (sandboxed
`LOCALAPPDATA`/`TEMP`, returns before tray/hotkey/mic), and no switch skips it
(`-SkipSmokeTest` only skips `Assert-BundleBehaves`). That is an app launch, which this
dispatch forbids, so I did not run the build. Other properties checked in the script
so the next run is safe: output is fixed at `<repo>\dist` of the checkout being built
(this worktree's `dist`, not `C:\AI_Projects\VoiceFlow\dist`, which the watchdog
runs); `-SkipProcessCleanup` turns the live-app kill off; `-SkipSmokeTest` skips the
behaviour launch; nothing copies to the live dist.

**Runbook for whoever is cleared to launch** (do not stop the live app):

1. From this worktree: `scripts\setup\build_windows_exe.ps1 -SkipProcessCleanup`
   (cold by default; cleanup is on by default and kills the live app). The bundle
   lands in this worktree's `dist\VoiceFlow`. Its `--self-check` runs sandboxed; leave
   `Assert-BundleBehaves` on only if its launch (own data dir, different hotkey) is
   acceptable, else add `-SkipSmokeTest` and do the launches in step 2 by hand.
2. Launch that bundle (a) from Explorer, (b) via a *copy* of the watchdog pointed
   at the side exe, (c) via a one-off scheduled task for the side exe. After each,
   compare the last two lines of `launch_contexts.jsonl` and `boot_breadcrumb.log`,
   confirm `voiceflow.log` grows, and dictate one test clip into the history store.
3. 20 cold starts: after each, require
   `model_ready key=distil-large-v3 … device=cuda compute=float16 fell_back_to_cpu=False`.
4. If a launcher gives a bad launch, diff its `launch_contexts.jsonl` record against
   a good one (names only) and bisect the differing variables.

## Review round 2 (Codex, on `0de208c`): status

Codex confirmed the three round-1 code findings as corrected (42/42 VF-18 tests,
428/428 broader suite) and kept one finding: item 3's root cause and every
end-to-end gate are unproven. That finding **stands**; this dispatch has the same
prohibitions (no app launch, no scheduled-task access), so it cannot be closed by
the executor. No source change was made in round 2.

What was tried this round, read-only, and where it stopped:

- Looked for a build stamp in the live bundle (`C:\AI_Projects\VoiceFlow\dist\VoiceFlow`):
  it is a one-file `VoiceFlow.exe` plus `_internal`; no stamp file is on disk.
- Tried to test the stale-module hypothesis statically: parse the exe's embedded PYZ
  (never executing it) and check whether `voiceflow.utils.logging_setup` contains
  `_verify_delivery_or_fall_back` (added in `cde7104`, 2026-11-07 13:50). The
  interpreter call needed an approval this non-interactive session could not
  give, so **it was not run**. A "no" would mean the live exe predates the logging
  fixes and item 3 is the stale-cache build `b460a24` describes, not a launcher
  problem; a "yes" sends the bisect to the environment diff in runbook step 4.
  That check never starts the app, so the conductor can run it directly.

The decision for the conductor: either run the runbook above (build with
`-SkipProcessCleanup`, three launch paths, 20 cold starts) under an order that
permits launching a side-directory bundle, or accept items 1, 2, 4, 5, 6 as done
and split item 3 plus the acceptance runs into their own order.

## Review round 3 (Codex, on `e62427c`)

Same single finding (item 3 plus the end-to-end gates). **Unchanged and launch-gated:**
this dispatch still forbids launching apps and touching scheduled tasks. The only new
work this round is item 7 (above), which needed no launch.

## Not tested

- **20 consecutive cold starts of a built bundle** — no bundle was built or launched: the build script's mandatory `--self-check` launches the frozen exe, which this dispatch forbids (see "Why no bundle was built").
- **Scheduled task definition** — not queried (see above).
- **Real Task Scheduler, Explorer, Startup-shortcut launches** — not touched; item 3's root cause is therefore open.
- The `config.json` migration on Nithin's real file and the missing-runtime/decode-OOM paths on a real GPU — unit tests with fakes only.
- Build: the merged build script has not been run (reason above). Note for whoever does: `-SkipProcessCleanup` is a
  switch and cleanup is **on by default**, which kills the live app; pass it.
- Item 6 with gemma actually unloaded / the card actually full.
- Model accuracy on a real microphone.
- Item 7: clips are synthesized (no real voice, no sub-2 s clips); the single-model migration was not run on Nithin's real `config.json`; streaming/checkpoint previews on the shared main engine were not exercised under a live hold; the dev model server was not started.
