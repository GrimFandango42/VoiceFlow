# VoiceFlow Roadmap

Where the project is and where it is going. Priorities come from the April 2026 competitive review (WhisperWriter, OpenWhispr, Amical, OmniDictate, whisper-standalone-win) and from daily use since. The short version: VoiceFlow's engine is ahead of the comparable open-source tools; the remaining gaps are mostly **first-run experience, observability and polish**.

Detailed history is in the [CHANGELOG](CHANGELOG.md); work orders are referenced by number (VF-nn).

---

## Done

| Area | What shipped | Where |
|---|---|---|
| Engine | Local faster-whisper, CUDA with CPU fallback, model tiers, background warm-up | 3.1.x |
| Live caption | Streaming preview with filler stripping; spring-physics waveform overlay | 3.2.x |
| Release builds | One-click Windows release workflow (`build-release.yml`), installer, winget manifest template | 3.2.x |
| First run | Setup wizard with hardware check, profiles and a model-download progress bar | 3.2.x |
| Reliability | Copy-only audio callbacks, bounded queues, no false "hang" on long holds, ring-buffer cap | VF-10 |
| Build gate | Build fails on a broken, CPU-only-by-accident or stale bundle; frozen `--self-check` | VF-09/10/11b |
| Speed | Paste returns at the keystroke, idle warm-up hidden, one shared mic stream, timer-based key release | VF-11 |
| Long dictation | Pause-segmented decoding, real VAD gate, right context for the last word, spoken commands, conservative cleanup | VF-12 |
| Never lose text | Local history (last 50), tray **Recent**, `Alt+Shift+V` re-paste, `Esc` cancel, target-window policy | VF-12 |
| Vocabulary | Hotwords on every decode, terms corrected twice are learned | VF-11/12 |
| Privacy | Cloud transcript analysis is opt-in and fully disclosed | VF-03 |
| CI | GitHub CI green without CUDA or a microphone | VF-15 |
| Docs | Refreshed docs, generated screenshots (`scripts/capture_screenshots.py`), link checker | VF-14 |

## Next

### Health tracking (VF-13)
A small, local, metadata-only record of how VoiceFlow is behaving over time: which build and device is running, whether the GPU path is healthy or has silently fallen back to the CPU, error and fallback counts, and release-to-text latency. Today the nearest things are the `longrun_health` and `transcription_timing` log lines and the idle-aware monitor, which you have to go and read. The scope is defined in the VF-13 work order; nothing from it is in this tree yet. It should stay metadata-only (no transcript text, no audio) and local.

### Fix what the docs refresh found
These are recorded in [`wiki/known-issues.md`](wiki/known-issues.md):
- The setup wizard's primary "Save and Launch VoiceFlow" button renders white-on-white on the default Tk theme.
- The overlay computes "Pasted N words" / "saved to history" messages but never draws them.
- The `balanced` tier (`distil-large-v3.5`) loads the same weights as `quick` on a GPU, so there is no real "balanced" model yet.

### Presentation and install
- A short demo GIF in the README (hold key, waveform, text appears). The README now has generated screenshots, not a recording.
- Winget submission (the manifest template exists in `packaging/windows/winget`).
- Smaller first download: ship a small runtime and fetch the model on first launch (the bundle is large because it carries torch and CUDA DLLs; the figure of ~826 MB comes from the April review and has not been re-measured).

### Runtime model swap
`core/model_server.py` already keeps a persistent model process in dev mode. A tray item "Switch model → Quick | Balanced | Quality" that reloads without restarting the app would let you use a small model for notes and a large one for long dictation. No comparable open-source tool does this.

### Context-aware behaviour
`destination_aware_formatting` and `infer_destination_profile` in `textproc.py` already adapt output to the target. The gap is more app categories (editor, mail, chat, terminal) and a tray control to choose a profile.

### Latency, measured
[`docs/LATENCY_BUDGET.md`](docs/LATENCY_BUDGET.md) lists *expected* gains from VF-11 and the config-only levers still to try (`stop_drain_seconds`, the release confirm, the tail buffer). They have not been measured in the field; re-measure with `scripts/dev/log_latency.py` after a few days of use, then try the levers one at a time.

### Community
A Discord server or GitHub Discussions space, and user feedback gathered there as input to the learning system.

---

## Already handled well — don't revisit

- **int8 quantization on CTranslate2** for the CPU path; float16 on CUDA.
- **Voice activity detection** — Silero VAD (bundled with faster-whisper) gates long recordings and each decoded piece, alongside the custom non-speech guard and silence-artifact classifier. Whisper's own `no_speech_prob` is not trusted (measured, VF-12).
- **Model server for persistent loading** in dev mode.
- **Streaming preview with real-time cleanup.**
- **Long-form dictation** — pause-segmented decoding with paragraph breaks at long pauses.
- **Three-tier text cleanup** (light, safe, heavy opt-in).
- **Adaptive learning loop**, local by default.
- **24/7 idle stability** — idle-aware monitor, bounded queues, overlay focus hardening.

## Not planned

- macOS / Linux builds: see the [forking guide](docs/guides/FORKING_AND_PLATFORM_GUIDE.md) for the seams a fork would replace.
- Any default behaviour that sends audio or transcripts off the machine.
