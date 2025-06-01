@echo off
title VoiceFlow Simple - Quick Test
echo.
echo ================================================================
echo                VoiceFlow Simple - Quick Test Suite
echo ================================================================
echo.

cd /d "%~dp0"

echo [Test] Checking Python environment...
if not exist "python\venv\Scripts\python.exe" (
    echo [Error] Python environment not found!
    echo [Fix] Run: INSTALL_ENHANCED_DEPS.bat
    pause
    exit /b 1
)

call python\venv\Scripts\activate.bat

echo [Test] Running quick validation...
python -c "
import sys
import os

# Test results
tests_passed = 0
tests_total = 0

def test(name, condition):
    global tests_passed, tests_total
    tests_total += 1
    if condition:
        tests_passed += 1
        print(f'✅ {name}')
    else:
        print(f'❌ {name}')

print('Testing VoiceFlow Simple dependencies...')
print()

# Core imports
try:
    import RealtimeSTT
    test('RealtimeSTT available', True)
except ImportError:
    test('RealtimeSTT available', False)

try:
    import keyboard
    test('keyboard available', True)
except ImportError:
    test('keyboard available', False)

try:
    import pyautogui
    test('pyautogui available', True)
except ImportError:
    test('pyautogui available', False)

try:
    import win32api
    import win32gui
    import win32clipboard
    test('Windows integration available', True)
except ImportError:
    test('Windows integration available', False)

try:
    import pyaudio
    audio = pyaudio.PyAudio()
    device_count = audio.get_device_count()
    audio.terminate()
    test(f'Audio system ({device_count} devices)', device_count > 0)
except:
    test('Audio system', False)

# Check files exist
test('Streamlined server exists', os.path.exists('python/voiceflow_streamlined.py'))
test('Simple launcher exists', os.path.exists('VoiceFlow-Simple.bat'))
test('Tray launcher exists', os.path.exists('VoiceFlow-Simple-Tray.bat'))

# Test AI connectivity
try:
    import requests
    response = requests.get('http://localhost:11434/api/tags', timeout=2)
    if response.status_code == 200:
        models = response.json().get('models', [])
        test(f'AI enhancement ({len(models)} models)', len(models) > 0)
    else:
        test('AI enhancement', False)
except:
    test('AI enhancement (optional)', False)

# Test syntax
try:
    with open('python/voiceflow_streamlined.py', 'r') as f:
        code = f.read()
    compile(code, 'voiceflow_streamlined.py', 'exec')
    test('Streamlined server syntax', True)
except Exception as e:
    test('Streamlined server syntax', False)
    print(f'  Error: {e}')

print()
print('=' * 50)
print(f'Test Results: {tests_passed}/{tests_total} passed')

if tests_passed >= tests_total - 1:  # Allow 1 optional failure (AI)
    print('🎉 VoiceFlow Simple is ready!')
    print()
    print('Next steps:')
    print('  1. Run: VoiceFlow-Simple-Tray.bat')
    print('  2. Press and hold Ctrl+Alt anywhere')
    print('  3. Speak and release keys')
    print('  4. Enjoy free voice transcription!')
else:
    print('⚠️ Some issues found. Run INSTALL_ENHANCED_DEPS.bat to fix.')

print()
print('Usage reminder:')
print('  • Ctrl+Alt = Press and hold to record')
print('  • Release keys = Stop and inject text')
print('  • Works in any Windows application')
print('  • Completely free and private')
"

echo.
pause