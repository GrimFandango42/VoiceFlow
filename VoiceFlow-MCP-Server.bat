@echo off
title VoiceFlow MCP Server - Integration with Claude MCP Ecosystem
echo.
echo ================================================================
echo               VoiceFlow MCP Server - Claude Integration
echo                    Voice Transcription via MCP Protocol
echo ================================================================
echo.

cd /d "%~dp0"

echo [SETUP] Checking Python environment...
if not exist "python\venv\Scripts\python.exe" (
    echo [ERROR] Python virtual environment not found!
    echo [FIX] Run: INSTALL_ENHANCED_DEPS.bat
    pause
    exit /b 1
)

echo [SETUP] Activating Python environment...
call python\venv\Scripts\activate.bat

echo [SETUP] Checking MCP framework...
python -c "import mcp" 2>nul
if errorlevel 1 (
    echo [WARNING] MCP framework not found!
    echo [FIX] Installing MCP framework...
    pip install mcp
)

echo [SETUP] Verifying VoiceFlow MCP dependencies...
python -c "
try:
    import mcp.server
    import RealtimeSTT
    import requests
    import pyaudio
    import keyboard
    import pyautogui
    import win32api
    print('✅ All MCP dependencies available')
except ImportError as e:
    print(f'❌ Missing dependency: {e}')
    print('Run INSTALL_ENHANCED_DEPS.bat to install all packages')
"

echo.
echo [STARTUP] Starting VoiceFlow MCP Server...
echo.
echo ✅ MCP Protocol Integration
echo ✅ Voice transcription tools for Claude
echo ✅ AI enhancement via Ollama
echo ✅ Windows text injection capabilities
echo ✅ Application context detection
echo ✅ Transcription history management
echo.
echo Available MCP Tools:
echo   • voice_transcribe_text - Transcribe audio files
echo   • voice_record_and_transcribe - Record and transcribe
echo   • voice_enhance_text - AI text enhancement
echo   • voice_inject_text - Inject text at cursor
echo   • voice_get_transcription_history - Get history
echo   • voice_get_statistics - Get usage stats
echo   • voice_detect_application_context - Detect app context
echo.
echo The server will communicate via stdio with Claude Code.
echo Press Ctrl+C to stop the server.
echo.

python voiceflow_mcp_server.py

echo.
echo [SHUTDOWN] VoiceFlow MCP Server stopped
pause