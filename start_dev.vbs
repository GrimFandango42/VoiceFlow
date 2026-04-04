' VoiceFlow dev launcher — runs dev.py from source with hot-reload
' Uses .venv-gpu Python, minimized console window
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.CurrentDirectory = "C:\AI_Projects\VoiceFlow"
' Launch dev.py minimized (7 = minimized window, False = don't wait)
objShell.Run """C:\AI_Projects\VoiceFlow\.venv-gpu\Scripts\python.exe"" ""C:\AI_Projects\VoiceFlow\dev.py""", 7, False
Set objShell = Nothing
