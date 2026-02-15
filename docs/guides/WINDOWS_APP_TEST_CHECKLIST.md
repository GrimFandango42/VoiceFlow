# Windows App Test Checklist

## Launch

1. Start tray mode: `wscript.exe VoiceFlow_Tray.vbs`
2. Confirm tray icon appears within 10 seconds.
3. Confirm default hotkey is `Ctrl+Shift` using:
   - `python scripts/dev/test_hotkey_config.py`

## Baseline Dictation Tests

For each app below:

1. Click text input.
2. Hold `Ctrl+Shift`, speak one short sentence, release.
3. Verify text appears in under 1.5 seconds for short phrases.
4. Repeat with a longer sentence (10-20 words).
5. Speak one phrase with a correction:
   - "send this Friday no wait Thursday"
6. Confirm output quality and punctuation.

Apps:

- Notepad
- VS Code
- Chrome text field (e.g., Gmail draft)
- Microsoft Word
- Slack or Teams chat box

## Stress

1. Run 20 short dictations back-to-back in Notepad.
2. Watch for hangs or missed injections.
3. Confirm tray status returns to idle after each transcription.

## Logs

- Runtime log: `%LOCALAPPDATA%\LocalFlow\logs\voiceflow_silent.log`
- Adaptive audit: `%LOCALAPPDATA%\LocalFlow\adaptive_audit.jsonl`
- Adaptive patterns: `%LOCALAPPDATA%\LocalFlow\adaptive_patterns.json`

## Expected Default Profile

- `model_tier`: `quick`
- `model_name`: `distil-large-v3`
- adaptive snippets enabled with 72h retention
