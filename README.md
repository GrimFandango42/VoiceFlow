# VoiceFlow

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

VoiceFlow is a Windows-first, local push-to-talk transcription app.
Hold a hotkey, speak, release, and text is inserted into your active app.

## What The App Looks Like

<p align="center">
  <img src="assets/control-center-polished-main.png" width="100%" alt="VoiceFlow Control Center main view"/>
</p>

<p align="center">
  <img src="assets/control-center-polished-troubleshoot.png" width="100%" alt="VoiceFlow Control Center troubleshooting view"/>
</p>

## Install (Recommended For Most Users)

1. Download the latest Windows release artifact from GitHub Releases.
2. Use `VoiceFlow-Setup-<version>.exe` if available, or unzip the portable package.
3. Launch `VoiceFlow` from Start Menu or run `VoiceFlow.exe`.

## First 2 Minutes

1. Open the Control Center.
2. Click `Setup & Install` once.
3. Click `Launch VoiceFlow`.
4. Hold `Ctrl+Shift`, speak, release to transcribe.
5. Use tray menu items `Recent History` and `Correction Review` for review and edits.

## Daily Experience

- Fast release-to-text for short and long dictation.
- Capitalization and paragraph formatting tuned for readability.
- Better handling for coughs, sniffles, and longer pauses.
- Local recent-history and correction review workflows.
- Optional daily learning pass from your saved correction data.

## Privacy And Local Data

VoiceFlow is local-first for core transcription.

- Config: `%LOCALAPPDATA%\LocalFlow\config.json`
- Logs: `%LOCALAPPDATA%\LocalFlow\logs\localflow.log`
- Recent history: `%LOCALAPPDATA%\LocalFlow\recent_history_events.jsonl`
- Correction review data: `%LOCALAPPDATA%\LocalFlow\transcription_corrections.jsonl`
- Adaptive patterns: `%LOCALAPPDATA%\LocalFlow\adaptive_patterns.json`

## Basic Troubleshooting

1. If no transcription appears, reopen Control Center and run `Setup & Install` once.
2. If hotkey input fails in elevated apps, run VoiceFlow with matching permissions.
3. If performance is unexpectedly slow, restart VoiceFlow from Control Center.

## Advanced (Developers And AI Companions)

- Technical playbook: `docs/AI_COMPANION_TECHNICAL.md`
- Build and packaging: `docs/BUILD_GUIDE.md`
- Architecture: `docs/ARCHITECTURE.md`
- Full docs index: `docs/README.md`

## License

MIT. See `LICENSE`.
