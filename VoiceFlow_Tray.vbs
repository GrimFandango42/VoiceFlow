' VoiceFlow 3.0 - Silent Tray Launcher
' Runs VoiceFlow minimized to system tray without console window
' Debug logs: %LOCALAPPDATA%\LocalFlow\logs\voiceflow_silent.log

Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")

' Get script directory
scriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)

' Build path to pythonw:
' 1) .venv-gpu (preferred for CUDA retest)
' 2) venv
' 3) system launcher
pythonw = scriptDir & "\.venv-gpu\Scripts\pythonw.exe"
If Not FSO.FileExists(pythonw) Then
    pythonw = scriptDir & "\venv\Scripts\pythonw.exe"
    If Not FSO.FileExists(pythonw) Then
        pythonw = "pyw"
    End If
End If
launcher = scriptDir & "\src\voiceflow\ui\launcher_silent.pyw"

' Change to src directory for imports to work
srcDir = scriptDir & "\src"
WshShell.CurrentDirectory = srcDir

' Run launcher with no console window
WshShell.Run """" & pythonw & """ """ & launcher & """", 0, False
