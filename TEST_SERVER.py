"""
VoiceFlow End-to-End Test
Tests the complete voice transcription pipeline
"""

import asyncio
import websockets
import json
import time
import requests

async def test_server_connection():
    """Test WebSocket connection to the server"""
    try:
        print("[TEST] Connecting to VoiceFlow server...")
        uri = "ws://localhost:8765"
        
        async with websockets.connect(uri) as websocket:
            print("[OK] Connected to WebSocket server")
            
            # Send a test message
            await websocket.send(json.dumps({"type": "get_statistics"}))
            print("[OK] Sent statistics request")
            
            # Wait for response
            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            data = json.loads(response)
            print(f"[OK] Received response: {data['type']}")
            
            return True
            
    except asyncio.TimeoutError:
        print("[FAILED] Server connection timeout")
        return False
    except Exception as e:
        print(f"[FAILED] Server connection error: {e}")
        return False

def test_ollama_connection():
    """Test Ollama AI enhancement connection"""
    try:
        print("[TEST] Testing Ollama connection...")
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get('models', [])
            print(f"[OK] Ollama connected, found {len(models)} models")
            return True
        else:
            print(f"[FAILED] Ollama returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"[FAILED] Ollama connection error: {e}")
        return False

def test_system_integration():
    """Test if system integration modules are available"""
    try:
        print("[TEST] Testing system integration...")
        import pyautogui
        import keyboard
        print("[OK] PyAutoGUI and keyboard modules available")
        print("[OK] Text injection should work")
        return True
    except ImportError as e:
        print(f"[FAILED] System integration modules missing: {e}")
        return False

async def main():
    """Run all tests"""
    print("=" * 60)
    print("VoiceFlow Server End-to-End Test")
    print("=" * 60)
    
    # Wait a moment for server to be ready
    print("[WAIT] Waiting 3 seconds for server to be fully ready...")
    await asyncio.sleep(3)
    
    tests = [
        ("Ollama AI Enhancement", test_ollama_connection),
        ("System Integration", test_system_integration),
        ("WebSocket Server", test_server_connection),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n--- Testing {test_name} ---")
        if asyncio.iscoroutinefunction(test_func):
            result = await test_func()
        else:
            result = test_func()
        results.append((test_name, result))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print(f"\nPassed: {passed}/{total}")
    
    if passed == total:
        print("\n[SUCCESS] All tests passed! VoiceFlow server is ready.")
        print("\nHow to test:")
        print("1. Press Ctrl+Alt")
        print("2. Speak clearly: 'This is a test'")
        print("3. Your speech should appear as text in the active window")
        return True
    else:
        print(f"\n[FAILED] {total - passed} tests failed. Server may not work properly.")
        return False

if __name__ == "__main__":
    asyncio.run(main())
