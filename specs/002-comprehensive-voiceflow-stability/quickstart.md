# Quickstart: VoiceFlow 24/7 Stability Testing

## Prerequisites
- Windows 10/11
- Python 3.13+
- VoiceFlow installed and configured
- Administrative permissions (for global hotkeys)

## Quick Validation Test

### 1. Start VoiceFlow
```bash
cd C:\AI_Projects\VoiceFlow
python tools/VoiceFlow_Control_Center.py
```

**Expected**: Control Center GUI launches, tray icon appears

### 2. Basic Functionality Test
1. Press and hold Ctrl+Shift
2. Speak for 2-3 seconds: "This is a basic test"
3. Release hotkey

**Expected**: Text appears in system, no errors in console

### 3. Idle Recovery Test
1. Wait 30 minutes without using VoiceFlow
2. Press and hold Ctrl+Shift
3. Speak: "Testing after idle period"
4. Release hotkey

**Expected**: System responds normally, no logger errors or crashes

### 4. Rapid Usage Test
1. Perform 10 transcriptions in quick succession
2. Vary between 0.5-second commands and 5-second speeches
3. Check system tray for status updates

**Expected**: All transcriptions complete, system remains responsive

### 5. Error Recovery Test
1. Monitor system for error messages
2. If errors occur, verify system continues operation
3. Check logs in `logs/stability.log`

**Expected**: System recovers automatically from errors

## Extended Validation (30-minute test)

### Setup Monitoring
```bash
# Terminal 1 - Start VoiceFlow
python tools/VoiceFlow_Control_Center.py

# Terminal 2 - Monitor logs
tail -f logs/stability.log

# Terminal 3 - Monitor system resources
python -c "
import psutil
import time
while True:
    print(f'Memory: {psutil.virtual_memory().percent}% CPU: {psutil.cpu_percent()}%')
    time.sleep(30)
"
```

### Test Scenarios
1. **Minutes 0-5**: Regular usage (1 transcription per minute)
2. **Minutes 5-15**: Idle period (no activity)
3. **Minutes 15-20**: Intensive usage (3-5 transcriptions per minute)
4. **Minutes 20-25**: Mixed length audio (0.5s to 30s clips)
5. **Minutes 25-30**: Return to regular usage

### Success Criteria
- ✅ No crashes or hangs
- ✅ Memory usage stable (< 500MB)
- ✅ All transcriptions complete successfully
- ✅ Response time < 500ms for hotkey activation
- ✅ No logger undefined errors
- ✅ System recovers from idle periods

## 24-Hour Stress Test

### Setup
```bash
# Run comprehensive stability test
python tests/stability/test_24hour_operation.py
```

### Success Criteria
- ✅ Uptime > 23 hours
- ✅ Memory growth < 100MB over 24 hours
- ✅ Response time remains consistent
- ✅ Error rate < 1% of transcriptions
- ✅ Automatic recovery from all error conditions

## Performance Baselines

### Acceptable Performance
- Memory usage: < 500MB during operation
- Hotkey response: < 200ms
- Transcription speed: > 1x realtime
- Error rate: < 5% per session

### Excellent Performance
- Memory usage: < 300MB during operation
- Hotkey response: < 100ms
- Transcription speed: > 3x realtime
- Error rate: < 1% per session

This quickstart provides comprehensive validation of the VoiceFlow stability improvements for production use.