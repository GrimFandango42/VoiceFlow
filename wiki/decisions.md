# VoiceFlow Design Decisions

## Two ways to run: source for development, the frozen bundle for validation
- **Decision**: Develop with `dev.py` (hot reload, `.venv-gpu`); validate end to end with the packaged `dist\VoiceFlow\VoiceFlow.exe`.
- **Rationale**: Hot reload makes UI and logic iteration fast without reloading the model. The bundle is what users run, so acceptance testing uses it — and the build verifies itself (`verify_bundle.py` plus the frozen `--self-check`), so a broken or stale bundle cannot be shipped.
- **Trade-off**: Two environments to keep working (the CUDA DLLs come from the venv's torch in source mode and are bundled in the EXE).
- *Supersedes the earlier "run from source, not frozen exe" decision (VF-14): a frozen build with a build gate exists now.*

## Silero VAD on by default
- **Decision**: Silero VAD filters silence before Whisper; long recordings are also cut at pauses and gated per piece.
- **Rationale**: Without VAD, Whisper decodes silence and noise and hallucinates text ("Thank you." after a long pause). Whisper's own `no_speech_prob` was measured to be unreliable on stationary noise (VF-12).
- **Trade-off**: Very quiet speech can be filtered. Switch off with `silence_vad_gate_enabled`.

## Short retention for learning data
- **Decision**: Learning and audit records are purged after `adaptive_retention_hours` (default 72 h). *(An older note here said 14 days; the shipped config default is 72 hours. `adaptive_memory.py` only falls back to 336 h if the setting is absent.)*
- **Rationale**: Recent corrections matter most; this keeps stored data bounded.
- **Trade-off**: Learned rules not reinforced within the window are forgotten. Twice-corrected terms are kept separately as learned hotwords (`learned_hotwords.json`).

## Two-process dev architecture
- **Decision**: Separate the model server from the app logic in dev mode.
- **Rationale**: Model loading takes seconds; keeping it resident means hot reload only restarts the app. A UI bug also cannot take down the model.
- **Trade-off**: More process management (ports, stale processes). The packaged app does not use it.

## Model tiers
- **Decision**: The default `quick` tier is `small.en` on CPU and `distil-large-v3` on CUDA.
- **Rationale**: Distilled models give most of large-v3's accuracy at a fraction of the latency; a smaller model keeps CPU latency acceptable.
- **Note**: The `balanced` tier's `distil-large-v3.5` entry loads the same faster-whisper distil-large-v3 weights, so on a GPU `balanced` and `quick` are not different models.

## Local first; cloud is opt-in
- **Decision**: Nothing leaves the machine by default. The nightly cloud analysis is a checkbox, off by default, with a disclosure of exactly what is sent.
- **Rationale**: Privacy is the point of the product; consent has to be explicit and verifiable (the nightly report records whether the step ran).

## Save before paste
- **Decision**: Every transcript is written to history before the paste is attempted.
- **Rationale**: A paste can miss (window closed, focus stolen). The recognised text must never be lost; it stays in the tray's Recent list, and on the clipboard when a paste fails.
