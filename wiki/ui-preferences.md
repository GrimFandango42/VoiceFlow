# VoiceFlow UI Preferences

## Visualization Style
- **Waveform type**: Frequency waveform bars (NOT ripple rings)
- **Color scheme**: Rainbow HSV colours on the bars; neutral dark panels for the badge, caption and dock
- **Animation**: Spring physics with per-bar excitability
- **Layout**: Compact overlay centred above the dock, close to the taskbar

## Transcription Display
- **Preview box**: 2 lines (a label sized for two lines of text)
- **Position**: Directly under the waveform and the status badge
- **Behavior**: Shows the newest words (up to `live_caption_words`, default 20); the finished text stays for about 2 s after the paste
- **Recording timer**: right of the badge (`7s`, then `1:05` from one minute)

## Dock
- Always-on strip showing the state (Ready / Listening / ...) and the build's "Updated MM-DD HH:MM" date, with **History** and **Hide** buttons; draggable, position remembered.

## Design Principles
- Compact and unobtrusive — should not dominate the screen
- Visually appealing but functional
- Responsive to audio input (bars react to frequency)
- Documentation screenshots come from `scripts/capture_screenshots.py` (demo mode), never from a real desktop

## Rejected Alternatives
- Ripple rings — too abstract, hard to read audio characteristics
- Static waveform — not engaging enough
- Full-window overlay — too intrusive for a utility app
