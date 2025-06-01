"""
VoiceFlow Quick Microphone Test
"""

import time
import numpy as np

def test_microphone():
    """Test microphone access and audio levels"""
    print("MICROPHONE TEST")
    print("===============")
    
    try:
        import pyaudio
        
        print("Initializing microphone...")
        p = pyaudio.PyAudio()
        
        # Get default input device info
        default_device = p.get_default_input_device_info()
        print(f"Default microphone: {default_device['name']}")
        
        # Open audio stream
        stream = p.open(
            format=pyaudio.paInt16,
            channels=1,
            rate=16000,
            input=True,
            frames_per_buffer=1024
        )
        
        print("\nListening for 5 seconds...")
        print("SPEAK NOW - say something clearly!")
        print("Monitoring audio levels...")
        
        max_volume = 0
        volumes = []
        
        for i in range(80):  # 5 seconds of samples
            try:
                data = stream.read(1024, exception_on_overflow=False)
                audio_data = np.frombuffer(data, dtype=np.int16)
                volume = np.abs(audio_data).mean()
                volumes.append(volume)
                max_volume = max(max_volume, volume)
                
                # Show live volume indicator
                if i % 8 == 0:  # Update every ~0.5 seconds
                    bars = int(volume / 100)
                    bar_display = "█" * min(bars, 20)
                    print(f"Volume: {volume:6.0f} |{bar_display:<20}|")
                    
            except Exception as e:
                print(f"Audio read error: {e}")
                break
                
            time.sleep(0.0625)  # ~16fps
        
        stream.stop_stream()
        stream.close()
        p.terminate()
        
        print(f"\nRESULTS:")
        print(f"Max volume detected: {max_volume:.0f}")
        print(f"Average volume: {np.mean(volumes):.0f}")
        
        if max_volume > 500:
            print("PASS: Good audio levels detected")
            return True
        elif max_volume > 100:
            print("WARNING: Low audio levels - try speaking louder")
            return False
        else:
            print("FAIL: No meaningful audio detected")
            print("Check:")
            print("- Microphone permissions in Windows Settings")
            print("- Microphone is not muted")
            print("- Correct microphone is selected as default")
            return False
            
    except Exception as e:
        print(f"MICROPHONE TEST FAILED: {e}")
        return False

def test_speech_recognition():
    """Test speech recognition with simple recording"""
    print("\nSPEECH RECOGNITION TEST")
    print("=======================")
    
    try:
        from RealtimeSTT import AudioToTextRecorder
        
        print("Initializing speech recognition...")
        
        # Create recorder with simple config
        recorder = AudioToTextRecorder(
            model="base",
            language="en",
            device="cpu", 
            compute_type="int8",
            use_microphone=True,
            spinner=False,
            level=0,
            enable_realtime_transcription=False,
            post_speech_silence_duration=1.5,
            min_length_of_recording=1.0,
            min_gap_between_recordings=0.5
        )
        
        print("Speech recognition ready!")
        print("\nRECORDING TEST:")
        print("Say something clearly for 3-5 seconds...")
        print("Recording starts in 3 seconds...")
        
        for i in range(3, 0, -1):
            print(f"{i}...")
            time.sleep(1)
        
        print("RECORDING NOW - SPEAK!")
        
        # Record for up to 10 seconds with timeout
        text = recorder.text(timeout=10, phrase_timeout=3)
        
        if text and text.strip():
            print(f"\nSUCCESS: Transcribed text: '{text}'")
            return True, text
        else:
            print("\nFAIL: No speech was transcribed")
            print("Possible issues:")
            print("- Audio too quiet")
            print("- Not speaking long enough")
            print("- Background noise interference")
            return False, None
            
    except Exception as e:
        print(f"SPEECH RECOGNITION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False, None

def main():
    print("VoiceFlow Speech Diagnostic")
    print("===========================")
    print("This will test microphone and speech recognition")
    print("")
    
    # Test microphone first
    mic_ok = test_microphone()
    
    if not mic_ok:
        print("\nMICROPHONE ISSUE DETECTED")
        print("Fix microphone before testing speech recognition")
        input("Press Enter to exit...")
        return
    
    # Test speech recognition
    speech_ok, transcribed = test_speech_recognition()
    
    print("\n" + "="*50)
    print("DIAGNOSTIC SUMMARY")
    print("="*50)
    
    print(f"Microphone Test:       {'PASS' if mic_ok else 'FAIL'}")
    print(f"Speech Recognition:    {'PASS' if speech_ok else 'FAIL'}")
    
    if speech_ok:
        print(f"Last transcription:    '{transcribed}'")
        print("\nSpeech recognition is working!")
        print("If VoiceFlow still doesn't work, the issue is likely:")
        print("- Hotkey timing (hold Ctrl+Alt longer)")
        print("- Text injection (cursor position)")
    else:
        print("\nSpeech recognition is not working.")
        print("This is why VoiceFlow isn't transcribing.")
        
    print("="*50)
    input("Press Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"Test crashed: {e}")
        input("Press Enter to exit...")
