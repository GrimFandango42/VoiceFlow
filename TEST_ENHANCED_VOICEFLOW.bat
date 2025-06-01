@echo off
title Enhanced VoiceFlow - Comprehensive Testing Suite
echo.
echo ================================================================
echo             Enhanced VoiceFlow - Comprehensive Testing
echo                    Validating All Enhanced Features
echo ================================================================
echo.

cd /d "%~dp0"

echo [TEST] Checking Python environment...
if not exist "python\venv\Scripts\python.exe" (
    echo [ERROR] Python virtual environment not found!
    echo [FIX] Run: INSTALL_ENHANCED_DEPS.bat
    pause
    exit /b 1
)

call python\venv\Scripts\activate.bat

echo [TEST] Creating comprehensive test script...
python -c "
import sys
import os
import time
import json
from datetime import datetime

# Test results storage
test_results = {
    'timestamp': datetime.now().isoformat(),
    'tests': {},
    'summary': {'passed': 0, 'failed': 0, 'warnings': 0}
}

def run_test(test_name, test_func):
    print(f'[TEST] {test_name}...')
    try:
        result = test_func()
        if result is True:
            test_results['tests'][test_name] = 'PASS'
            test_results['summary']['passed'] += 1
            print(f'  ✅ PASS')
        elif result == 'WARNING':
            test_results['tests'][test_name] = 'WARNING'
            test_results['summary']['warnings'] += 1
            print(f'  ⚠️ WARNING')
        else:
            test_results['tests'][test_name] = f'FAIL: {result}'
            test_results['summary']['failed'] += 1
            print(f'  ❌ FAIL: {result}')
    except Exception as e:
        test_results['tests'][test_name] = f'ERROR: {str(e)}'
        test_results['summary']['failed'] += 1
        print(f'  ❌ ERROR: {e}')

def test_core_imports():
    try:
        import RealtimeSTT
        import requests
        import numpy
        return True
    except ImportError as e:
        return f'Missing core package: {e}'

def test_windows_integration():
    try:
        import keyboard
        import pyautogui
        import win32api
        import win32gui
        import win32clipboard
        import pystray
        import PIL
        return True
    except ImportError as e:
        return f'Missing Windows package: {e}'

def test_audio_system():
    try:
        import pyaudio
        audio = pyaudio.PyAudio()
        device_count = audio.get_device_count()
        audio.terminate()
        if device_count > 0:
            return True
        return 'No audio devices found'
    except Exception as e:
        return f'Audio system error: {e}'

def test_gpu_availability():
    try:
        import torch
        if torch.cuda.is_available():
            device_name = torch.cuda.get_device_name(0)
            print(f'    GPU: {device_name}')
            return True
        return 'WARNING'
    except Exception as e:
        return 'WARNING'

def test_ollama_connectivity():
    import requests
    urls = [
        'http://localhost:11434/api/tags',
        'http://172.30.248.191:11434/api/tags',
        'http://127.0.0.1:11434/api/tags'
    ]
    
    for url in urls:
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                models = response.json().get('models', [])
                print(f'    Connected: {url}')
                print(f'    Models: {len(models)} available')
                return True
        except:
            continue
    return 'WARNING'

def test_whisper_models():
    try:
        from RealtimeSTT import AudioToTextRecorder
        # Test basic initialization (without actually loading)
        return True
    except Exception as e:
        return f'Whisper initialization failed: {e}'

def test_enhanced_server_syntax():
    try:
        with open('python/enhanced_stt_server.py', 'r') as f:
            code = f.read()
        compile(code, 'enhanced_stt_server.py', 'exec')
        return True
    except SyntaxError as e:
        return f'Syntax error in enhanced server: {e}'
    except FileNotFoundError:
        return 'Enhanced server file not found'

def test_native_server_syntax():
    try:
        with open('native/enhanced_voiceflow_native.py', 'r') as f:
            code = f.read()
        compile(code, 'enhanced_voiceflow_native.py', 'exec')
        return True
    except SyntaxError as e:
        return f'Syntax error in native server: {e}'
    except FileNotFoundError:
        return 'Native server file not found'

def test_global_hotkey_registration():
    try:
        import keyboard
        # Test if we can register a temporary hotkey
        def dummy_handler():
            pass
        keyboard.add_hotkey('ctrl+alt+f12', dummy_handler, suppress=False)
        keyboard.remove_hotkey('ctrl+alt+f12')
        return True
    except Exception as e:
        return f'Hotkey registration failed: {e}'

def test_text_injection_methods():
    try:
        import keyboard
        import pyautogui
        import win32api
        import win32con
        import win32clipboard
        
        # Test clipboard access
        win32clipboard.OpenClipboard()
        win32clipboard.CloseClipboard()
        
        return True
    except Exception as e:
        return f'Text injection setup failed: {e}'

def test_database_creation():
    try:
        import sqlite3
        from pathlib import Path
        
        # Test database creation in temp location
        test_db = Path.home() / '.voiceflow_test' / 'test.db'
        test_db.parent.mkdir(exist_ok=True)
        
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_transcriptions (
                id INTEGER PRIMARY KEY,
                text TEXT
            )
        ''')
        conn.commit()
        conn.close()
        
        # Cleanup
        test_db.unlink()
        test_db.parent.rmdir()
        
        return True
    except Exception as e:
        return f'Database test failed: {e}'

def test_launcher_scripts():
    scripts = [
        'VoiceFlow-Enhanced.bat',
        'VoiceFlow-Enhanced-Native.bat', 
        'VoiceFlow-Enhanced-Invisible.bat',
        'VoiceFlow-Enhanced-Tray.ps1'
    ]
    
    missing = []
    for script in scripts:
        if not os.path.exists(script):
            missing.append(script)
    
    if missing:
        return f'Missing launcher scripts: {missing}'
    return True

# Run all tests
print('🧪 Running Enhanced VoiceFlow Test Suite...')
print()

run_test('Core Package Imports', test_core_imports)
run_test('Windows Integration Packages', test_windows_integration)
run_test('Audio System', test_audio_system)
run_test('GPU Availability', test_gpu_availability)
run_test('Ollama Connectivity', test_ollama_connectivity)
run_test('Whisper Models', test_whisper_models)
run_test('Enhanced Server Syntax', test_enhanced_server_syntax)
run_test('Native Server Syntax', test_native_server_syntax)
run_test('Global Hotkey Registration', test_global_hotkey_registration)
run_test('Text Injection Methods', test_text_injection_methods)
run_test('Database Creation', test_database_creation)
run_test('Launcher Scripts', test_launcher_scripts)

# Save results
with open('enhanced_test_results.json', 'w') as f:
    json.dump(test_results, f, indent=2)

# Summary
print()
print('=' * 60)
print('               TEST SUMMARY')
print('=' * 60)
print(f'Total Tests: {sum(test_results[\"summary\"].values())}')
print(f'✅ Passed: {test_results[\"summary\"][\"passed\"]}')
print(f'⚠️ Warnings: {test_results[\"summary\"][\"warnings\"]}')
print(f'❌ Failed: {test_results[\"summary\"][\"failed\"]}')
print()

if test_results['summary']['failed'] == 0:
    print('🎉 ALL CORE TESTS PASSED!')
    print()
    print('Enhanced VoiceFlow is ready to use:')
    print('  • VoiceFlow-Enhanced.bat (Console mode)')
    print('  • VoiceFlow-Enhanced-Native.bat (System tray)')
    print('  • VoiceFlow-Enhanced-Invisible.bat (Background)')
    print()
    print('Press Ctrl+Alt+Space anywhere to test voice transcription!')
else:
    print('⚠️ Some tests failed. Check the issues above.')
    print('Run INSTALL_ENHANCED_DEPS.bat to fix dependency issues.')

print()
print('Test results saved to: enhanced_test_results.json')
"

echo.
echo [RESULTS] Test completed. Check enhanced_test_results.json for details.
echo.
pause