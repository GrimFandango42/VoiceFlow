# Windows Executable Evaluation

## Question

Should VoiceFlow ship as a Windows executable to simplify onboarding for forks and non-Python users?

## Short Answer

Yes, but as a **secondary distribution option** after keeping the Python-first path stable.

## Why It Helps

- easier first-run for non-Python users
- fewer environment mismatch issues
- better handoff for internal teams

## Tradeoffs

- larger artifact sizes (Whisper/runtime dependencies)
- antivirus/signing friction for unsigned binaries
- packaging complexity around `keyboard`, tray UI, and optional CUDA paths
- harder debugging compared to Python source launch

## Recommended Strategy

1. Keep Python path as canonical development/runtime path.
2. Add experimental PyInstaller packaging for Windows.
3. Validate packaged behavior in:
   - Notepad
   - VS Code
   - browser textareas
4. Publish executable only after passing the same smoke + manual matrix checks used for source mode.

## Packaging Candidate

Tool: `pyinstaller`

Potential entrypoints:
- primary: `voiceflow.py`
- optional silent mode wrapper: `src/voiceflow/ui/launcher_silent.pyw`

## Minimal Packaging Checklist

- include `src/voiceflow` package modules
- verify tray and overlay launch behavior
- verify hotkey hold/release lifecycle
- verify text injection in target windows
- verify logs/config path behavior in packaged mode

## Practical Recommendation For This Repo

- Add packaging as a documented experimental path first.
- Do not replace the existing `VoiceFlow_Quick.bat` workflow yet.
- Treat executable output as convenience distribution, not source-of-truth runtime.
