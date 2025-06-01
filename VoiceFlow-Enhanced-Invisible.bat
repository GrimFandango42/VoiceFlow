@echo off
REM Launch Enhanced VoiceFlow invisibly in system tray (like Wispr Flow)
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0VoiceFlow-Enhanced-Tray.ps1"