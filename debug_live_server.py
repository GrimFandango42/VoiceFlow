"""
VoiceFlow Live Server Diagnostic
Check what's happening with the running VoiceFlow server
"""

import requests
import json
import time
import websocket
import threading

def test_websocket_connection():
    """Test connection to running VoiceFlow server"""
    print("🔗 Testing WebSocket connection to VoiceFlow server...")
    
    try:
        def on_message(ws, message):
            data = json.loads(message)
            print(f"📨 Server message: {data}")
            
        def on_error(ws, error):
            print(f"❌ WebSocket error: {error}")
            
        def on_close(ws, close_status_code, close_msg):
            print("🔌 WebSocket connection closed")
            
        def on_open(ws):
            print("✅ WebSocket connected to VoiceFlow server")
            # Send a ping
            ws.send(json.dumps({"type": "ping"}))
            
        ws = websocket.WebSocketApp(
            "ws://localhost:8765",
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close
        )
        
        # Run for 5 seconds
        ws.run_forever(timeout=5)
        return True
        
    except Exception as e:
        print(f"❌ WebSocket test failed: {e}")
        return False

def check_server_logs():
    """Check if we can see server activity"""
    print("\n📋 Checking server status...")
    
    # Test if server is responding
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex(('localhost', 8765))
        s.close()
        
        if result == 0:
            print("✅ VoiceFlow server is running on port 8765")
            return True
        else:
            print("❌ VoiceFlow server not accessible on port 8765")
            return False
            
    except Exception as e:
        print(f"❌ Server check failed: {e}")
        return False

def test_quick_microphone():
    """Quick microphone test"""
    print("\n🎤 Quick microphone test...")
    
    try:
        import pyaudio
        import numpy as np
        
        # Quick audio level test
        p = pyaudio.PyAudio()
        stream = p.open(
            format=pyaudio.paInt16,
            channels=1,
            rate=16000,
            input=True,
            frames_per_buffer=1024
        )
        
        print("Listening for 3 seconds... speak now!")
        max_volume = 0
        
        for _ in range(50):  # 3 seconds of samples
            data = stream.read(1024, exception_on_overflow=False)
            audio_data = np.frombuffer(data, dtype=np.int16)
            volume = np.abs(audio_data).mean()
            max_volume = max(max_volume, volume)
            time.sleep(0.06)
        
        stream.stop_stream()
        stream.close()
        p.terminate()
        
        print(f"Max audio level detected: {max_volume}")
        
        if max_volume > 100:
            print("✅ Microphone is receiving audio")
            return True
        else:
            print("⚠️  Very low or no audio detected")
            print("   - Check microphone permissions")
            print("   - Ensure microphone is not muted")
            print("   - Try speaking louder")
            return False
            
    except Exception as e:
        print(f"❌ Microphone test failed: {e}")
        return False

def simulate_hotkey_trigger():
    """Simulate what happens when Ctrl+Alt is pressed"""
    print("\n🔥 Simulating hotkey trigger...")
    
    try:
        # This simulates the hotkey being pressed
        import keyboard
        
        print("Triggering hotkey handler manually...")
        
        # Check if hotkey is registered
        hotkeys = keyboard._hotkeys
        print(f"Registered hotkeys: {len(hotkeys)}")
        
        if hotkeys:
            print("✅ Global hotkeys are registered")
            
            # Try to trigger manually (this might not work but will show us info)
            print("Note: Actual hotkey triggering requires physical key press")
            return True
        else:
            print("❌ No global hotkeys registered")
            return False
            
    except Exception as e:
        print(f"❌ Hotkey simulation failed: {e}")
        return False

def main():
    """Run live diagnostic on running VoiceFlow"""
    print("="*60)
    print("🔍 VoiceFlow Live Server Diagnostic")
    print("="*60)
    print("This checks the currently running VoiceFlow server")
    print("Make sure VoiceFlow is running before starting this test")
    print("")
    
    # Check if server is running
    if not check_server_logs():
        print("\n❌ VoiceFlow server is not running!")
        print("Start VoiceFlow first, then run this diagnostic")
        input("Press Enter to exit...")
        return
    
    # Test WebSocket connection
    websocket_ok = test_websocket_connection()
    
    # Test microphone
    mic_ok = test_quick_microphone()
    
    # Test hotkey system
    hotkey_ok = simulate_hotkey_trigger()
    
    # Summary
    print("\n" + "="*60)
    print("📊 LIVE DIAGNOSTIC RESULTS")
    print("="*60)
    
    components = [
        ("Server Running", True),  # We know this if we got here
        ("WebSocket Connection", websocket_ok),
        ("Microphone Audio", mic_ok),
        ("Hotkey System", hotkey_ok)
    ]
    
    for name, status in components:
        status_text = "✅ OK" if status else "❌ FAIL"
        print(f"{name:20} {status_text}")
    
    print("\n" + "="*60)
    print("🎯 LIKELY ISSUE ANALYSIS")
    print("="*60)
    
    if not mic_ok:
        print("🎤 MICROPHONE ISSUE:")
        print("   - Check Windows microphone permissions")
        print("   - Ensure microphone is not muted") 
        print("   - Try a different microphone")
        print("   - Check Windows Privacy Settings > Microphone")
        
    elif not websocket_ok:
        print("🔌 SERVER COMMUNICATION ISSUE:")
        print("   - Restart VoiceFlow")
        print("   - Check for firewall blocking")
        
    elif not hotkey_ok:
        print("🔥 HOTKEY REGISTRATION ISSUE:")
        print("   - Run VoiceFlow as Administrator")
        print("   - Check for conflicting hotkeys")
        
    else:
        print("🤔 UNCLEAR ISSUE:")
        print("   - All components seem to be working")
        print("   - Try speaking louder when using Ctrl+Alt")
        print("   - Check VoiceFlow server console for errors")
        print("   - Try running the full diagnostic")
    
    print("="*60)
    input("Press Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Diagnostic stopped by user")
    except Exception as e:
        print(f"\n💥 Diagnostic error: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")
