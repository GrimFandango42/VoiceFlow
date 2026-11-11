# VoiceFlow Known Issues

## Active Issues

### A leftover VoiceFlow process blocks a fresh launch
- **Severity**: Medium
- **Description**: The single-instance guard refuses to start (or ends the new process) while another VoiceFlow process is alive, for example one that hung or is running hidden.
- **Workaround**: End the old process (Task Manager, or `scripts\setup\stop_voiceflow_processes.ps1`) and launch again. Never start with `python -m voiceflow.ui.cli_enhanced` (the guard mistakes the py.exe launcher's child for a duplicate); use `_app_entry.py`, `dev.py` or the EXE.
- *Not re-tested in VF-14. A named mutex is released by the OS when its process exits, so the usual cause is a surviving process rather than a stale mutex.*

### Setup wizard: the primary "Save and Launch VoiceFlow" button is unreadable on the default Tk theme
- **Severity**: Medium (first-run experience)
- **Description**: Rendering the wizard in demo mode (VF-14, Windows 11) showed the primary button as white text on a white face. The wizard picks the `vista` ttk theme first, and that theme ignores the `background` style mapping used for `SetupPrimaryReady.TButton` (the likely cause; only the rendering was observed, the button was not clicked).
- **Fix needed**: Use a theme that honours button colours (for example `clam`) for the primary buttons, or style them without the background map. The documentation screenshot of this window is cropped above the footer because of this; remove the crop (`SETUP_FOOTER_CROP_PX` in `scripts/capture_screenshots.py`) once it is fixed.

### The overlay does not show the paste outcome text
- **Severity**: Low
- **Description**: After a paste the app passes "Pasted N words" (or "Target window closed - saved to history" and similar) to the overlay, but `_update_ui` only draws the status badge (**Done** / **Error**) and the caption; the message string is never displayed. The outcome is recorded in the history entry and the log.
- **Fix needed**: Render the message (for example in the badge or the dock), or drop the unused argument.

### Learning needs corrections to accumulate data
- **Severity**: Low
- **Description**: Personalization only improves when the user corrects transcripts (Correction Review or the History panel). Without corrections there is little to learn from.
- **Impact**: New users do not see accuracy gains until they invest time in corrections. Terms corrected twice become hotwords immediately.

## Resolved Issues
- Audio device enumeration on startup
- Streaming buffer overflow on long utterances
- Hotkey registration conflict with other apps
- Model server crash on malformed audio packets
- Dropped audio frames ("input overflow"): callbacks are now copy-only (VF-10)
- False "Hang detected" on long dictations (VF-05/VF-10)
- Live preview had no VAD in the packaged build (VF-09/VF-10)
