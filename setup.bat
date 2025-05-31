@echo off
echo ============================================
echo VoiceFlow Setup Script
echo ============================================
echo.

echo [1/5] Creating Python virtual environment...
cd python
python -m venv venv
call venv\Scripts\activate

echo.
echo [2/5] Installing Python dependencies...
pip install --upgrade pip
pip install -r requirements.txt

echo.
echo [3/5] Installing CUDA-optimized PyTorch...
pip install torch==2.1.1+cu121 torchaudio==2.1.1 --index-url https://download.pytorch.org/whl/cu121

echo.
echo [4/5] Downloading Whisper models...
python -c "from faster_whisper import WhisperModel; print('Downloading Whisper large-v3...'); model = WhisperModel('large-v3', device='cuda', compute_type='float16'); print('Download complete!')"

echo.
echo [5/5] Testing Ollama connection...
curl -X POST http://localhost:11434/api/generate -d "{\"model\": \"deepseek-r1:14b\", \"prompt\": \"Hello\", \"stream\": false}" > nul 2>&1
if %errorlevel% == 0 (
    echo Ollama connection successful!
) else (
    echo WARNING: Could not connect to Ollama. Make sure Ollama is running with deepseek-r1:14b model.
)

cd ..

echo.
echo ============================================
echo Setup complete! Now run build.bat to build the app.
echo ============================================
pause