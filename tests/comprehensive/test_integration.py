#!/usr/bin/env python3
"""
VoiceFlow Integration Test Suite
================================
End-to-end integration tests for full system functionality
"""

import sys
import time
import threading
import os
import numpy as np
import tempfile
import json
from unittest.mock import patch, MagicMock
import signal
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from voiceflow.config import Config
    from voiceflow.cli_enhanced import EnhancedApp
    from voiceflow.audio_enhanced import EnhancedAudioRecorder
    from voiceflow.asr_buffer_safe import BufferSafeWhisperASR
    from voiceflow.inject import ClipboardInjector
    from voiceflow.enhanced_tray import EnhancedTrayController
    from voiceflow.visual_indicators import (
        show_listening, show_processing, show_transcribing, 
        show_complete, show_error, hide_status,
        cleanup_indicators
    )
    from voiceflow.textproc import apply_code_mode
    from voiceflow.hotkeys_enhanced import EnhancedPTTHotkeyListener
except ImportError as e:
    print(f"Import error: {e}")
    print("Please run from VoiceFlow root directory")
    sys.exit(1)

class IntegrationTestSuite:
    """Integration tests for full system workflows"""
    
    def __init__(self):
        self.test_results = []
        self.cfg = Config()
        self.temp_files = []
        
    def log_test(self, test_name: str, status: str, details: str = ""):
        """Log test result"""
        result = f"{status.ljust(8)} {test_name.ljust(50)} {details}"
        print(result)
        self.test_results.append((test_name, status, details))
    
    def cleanup(self):
        """Cleanup temporary files and resources"""
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except:
                pass
        self.temp_files.clear()
        
        # Cleanup visual indicators
        try:
            cleanup_indicators()
        except:
            pass
    
    def test_complete_transcription_workflow(self):
        """Test complete transcription workflow from audio to text injection"""
        print("\nTEST: Complete Transcription Workflow")
        
        try:
            app = EnhancedApp(self.cfg)
            
            # Generate test audio with known content
            sample_rate = 16000
            duration = 2.0  # 2 seconds
            
            # Generate a simple sine wave (simulates speech-like audio)
            t = np.linspace(0, duration, int(sample_rate * duration))
            frequency = 440  # A4 note
            audio_data = (np.sin(2 * np.pi * frequency * t) * 0.1).astype(np.float32)
            
            # Mock the transcription to return known text
            expected_text = "This is a test transcription"
            
            with patch.object(app.asr, 'transcribe', return_value=expected_text):
                with patch.object(app.injector, 'inject') as mock_inject:
                    
                    # Simulate recording workflow
                    app.start_recording()
                    time.sleep(0.1)
                    
                    # Override the recorder's audio buffer
                    with patch.object(app.rec, 'stop', return_value=audio_data):
                        app.stop_recording()
                        
                        # Wait for transcription to complete
                        time.sleep(2.0)
                        
                        # Verify injection was called
                        mock_inject.assert_called_with(expected_text)
                        self.log_test("Complete transcription workflow", "PASS", 
                                    f"Text: '{expected_text}'")
            
            app.shutdown()
            
        except Exception as e:
            self.log_test("Complete transcription workflow", "FAIL", str(e))
    
    def test_visual_tray_integration(self):
        """Test integration between visual indicators and tray system"""
        print("\nTEST: Visual+Tray Integration")
        
        try:
            # Create mock app for tray
            class MockApp:
                def __init__(self):
                    self.cfg = Config()
                    self.code_mode = False
                    self.visual_indicators_enabled = True
            
            app = MockApp()
            tray = EnhancedTrayController(app)
            
            # Test status transitions
            status_sequence = [
                ("idle", False, "Ready"),
                ("listening", True, "Recording..."),
                ("processing", False, "Processing audio"),
                ("transcribing", False, "Converting speech to text"),
                ("complete", False, "Transcription complete: Hello world"),
                ("error", False, "Transcription failed"),
                ("idle", False, "Ready")
            ]
            
            for status, recording, message in status_sequence:
                tray.update_status(status, recording, message)
                time.sleep(0.2)  # Brief pause to observe transitions
            
            self.log_test("Visual+Tray integration", "PASS", 
                         f"Processed {len(status_sequence)} status updates")
            
        except Exception as e:
            self.log_test("Visual+Tray integration", "FAIL", str(e))
    
    def test_hotkey_system_integration(self):
        """Test hotkey system integration"""
        print("\nTEST: Hotkey System Integration")
        
        try:
            app = EnhancedApp(self.cfg)
            
            # Test hotkey listener creation
            recording_started = threading.Event()
            recording_stopped = threading.Event()
            
            def on_start():
                recording_started.set()
                app.start_recording()
            
            def on_stop():
                app.stop_recording()
                recording_stopped.set()
            
            # Create hotkey listener
            listener = EnhancedPTTHotkeyListener(
                self.cfg,
                on_start=on_start,
                on_stop=on_stop
            )
            
            # Test listener lifecycle
            listener.start()
            time.sleep(0.5)
            
            # Simulate hotkey events
            on_start()
            time.sleep(0.1)
            on_stop()
            time.sleep(0.1)
            
            listener.stop()
            
            # Verify events occurred
            assert recording_started.is_set(), "Recording start event not triggered"
            assert recording_stopped.is_set(), "Recording stop event not triggered"
            
            self.log_test("Hotkey system integration", "PASS", "Events triggered correctly")
            
            app.shutdown()
            
        except Exception as e:
            self.log_test("Hotkey system integration", "FAIL", str(e))
    
    def test_config_persistence_integration(self):
        """Test configuration persistence across app restarts"""
        print("\nTEST: Config Persistence Integration")
        
        try:
            # Create temporary config file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                test_config = {
                    "code_mode_default": True,
                    "paste_injection": False,
                    "hotkey_ctrl": True,
                    "hotkey_shift": False,
                    "hotkey_alt": True,
                    "hotkey_key": "space"
                }
                json.dump(test_config, f)
                config_path = f.name
                self.temp_files.append(config_path)
            
            # Test loading custom config
            cfg = Config()
            
            # Manually load from our test file
            with open(config_path, 'r') as f:
                loaded_config = json.load(f)
            
            for key, value in loaded_config.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, value)
            
            # Create app with loaded config
            app = EnhancedApp(cfg)
            
            # Verify config was applied
            assert app.code_mode == test_config["code_mode_default"], "Code mode not loaded"
            assert app.cfg.paste_injection == test_config["paste_injection"], "Paste injection not loaded"
            
            self.log_test("Config persistence integration", "PASS", 
                         "Configuration loaded and applied correctly")
            
            app.shutdown()
            
        except Exception as e:
            self.log_test("Config persistence integration", "FAIL", str(e))
    
    def test_audio_processing_chain(self):
        """Test complete audio processing chain"""
        print("\nTEST: Audio Processing Chain")
        
        try:
            app = EnhancedApp(self.cfg)
            
            # Test audio recorder
            recorder = app.rec
            
            # Test buffer initialization
            assert recorder.audio_buffer is not None, "Audio buffer not initialized"
            assert recorder.tail_buffer is not None, "Tail buffer not initialized"
            
            # Generate test audio
            sample_rate = 16000
            test_audio = np.random.random(sample_rate).astype(np.float32) * 0.1  # 1 second
            
            # Test ASR processing
            asr = app.asr
            result = asr.transcribe(test_audio)
            
            # Verify transcription completed (even if empty)
            assert isinstance(result, str), f"Expected string result, got {type(result)}"
            
            # Test text processing
            processed_text = apply_code_mode(result or "test text", lowercase=False)
            assert isinstance(processed_text, str), "Text processing failed"
            
            self.log_test("Audio processing chain", "PASS", 
                         f"Chain completed: audio -> ASR -> text processing")
            
            app.shutdown()
            
        except Exception as e:
            self.log_test("Audio processing chain", "FAIL", str(e))
    
    def test_error_propagation_integration(self):
        """Test error propagation through the system"""
        print("\nTEST: Error Propagation Integration")
        
        try:
            app = EnhancedApp(self.cfg)
            
            # Test ASR error propagation
            with patch.object(app.asr, 'transcribe', side_effect=Exception("Mock ASR error")):
                
                # This should not crash the app
                test_audio = np.random.random(8000).astype(np.float32) * 0.1
                
                try:
                    app._perform_transcription(test_audio)
                    self.log_test("ASR error propagation", "PASS", "Error handled gracefully")
                except Exception as e:
                    self.log_test("ASR error propagation", "WARNING", f"Error not fully contained: {e}")
            
            # Test injection error propagation  
            with patch.object(app.injector, 'inject', side_effect=Exception("Mock injection error")):
                
                # Transcription should work, injection should fail gracefully
                test_audio = np.random.random(8000).astype(np.float32) * 0.1
                
                try:
                    result = app._perform_transcription(test_audio)
                    self.log_test("Injection error propagation", "PASS", "Injection error handled")
                except Exception as e:
                    self.log_test("Injection error propagation", "FAIL", f"Error not handled: {e}")
            
            # Test visual error propagation
            with patch('localflow.visual_indicators.show_complete', side_effect=Exception("Mock visual error")):
                
                test_audio = np.random.random(8000).astype(np.float32) * 0.1
                
                try:
                    result = app._perform_transcription(test_audio)
                    self.log_test("Visual error propagation", "PASS", "Visual error handled")
                except Exception as e:
                    self.log_test("Visual error propagation", "FAIL", f"Visual error not handled: {e}")
            
            app.shutdown()
            
        except Exception as e:
            self.log_test("Error propagation integration", "FAIL", str(e))
    
    def test_resource_management_integration(self):
        """Test resource management across components"""
        print("\nTEST: Resource Management Integration")
        
        try:
            import psutil
            import gc
            
            initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            # Create and destroy multiple app instances
            for i in range(3):
                app = EnhancedApp(self.cfg)
                
                # Simulate activity
                test_audio = np.random.random(8000).astype(np.float32) * 0.1
                result = app.asr.transcribe(test_audio)
                
                # Proper shutdown
                app.shutdown()
                del app
                gc.collect()
                
                current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                memory_growth = current_memory - initial_memory
                
                if memory_growth > 100:  # More than 100MB growth
                    self.log_test("Resource management integration", "WARNING", 
                                 f"Memory growth: {memory_growth:.1f}MB after {i+1} cycles")
                    break
            else:
                self.log_test("Resource management integration", "PASS", 
                             f"Memory stable after 3 cycles")
            
        except Exception as e:
            self.log_test("Resource management integration", "FAIL", str(e))
    
    def test_threading_integration(self):
        """Test threading integration across components"""
        print("\nTEST: Threading Integration")
        
        try:
            app = EnhancedApp(self.cfg)
            
            # Test transcription manager
            manager = app.transcription_manager
            
            # Submit multiple concurrent jobs
            test_audios = [
                np.random.random(4000).astype(np.float32) * 0.1,
                np.random.random(4000).astype(np.float32) * 0.1,
                np.random.random(4000).astype(np.float32) * 0.1
            ]
            
            job_ids = []
            for audio in test_audios:
                def callback(audio_data):
                    return app.asr.transcribe(audio_data)
                
                job_id = manager.submit_transcription(audio, callback)
                job_ids.append(job_id)
            
            # Wait for all jobs to complete
            time.sleep(5.0)
            
            # Check job cleanup
            manager._cleanup_completed_jobs()
            
            self.log_test("Threading integration", "PASS", 
                         f"Submitted {len(job_ids)} concurrent jobs")
            
            app.shutdown()
            
        except Exception as e:
            self.log_test("Threading integration", "FAIL", str(e))
    
    def test_full_system_stress_integration(self):
        """Test full system under integrated stress"""
        print("\nTEST: Full System Stress Integration")
        
        try:
            app = EnhancedApp(self.cfg)
            
            # Create tray controller
            class MockApp:
                def __init__(self, real_app):
                    self.cfg = real_app.cfg
                    self.code_mode = real_app.code_mode
                    self.visual_indicators_enabled = True
                    self.asr = real_app.asr
            
            mock_app = MockApp(app)
            tray = EnhancedTrayController(mock_app)
            
            # Stress test with rapid operations
            operations = 20
            
            for i in range(operations):
                # Rapid recording cycle
                app.start_recording()
                time.sleep(0.05)  # 50ms recording
                app.stop_recording()
                
                # Visual status updates
                tray.update_status("listening", True, f"Operation {i}")
                time.sleep(0.01)
                tray.update_status("processing", False, f"Processing {i}")
                time.sleep(0.01)
                tray.update_status("complete", False, f"Complete {i}")
                time.sleep(0.01)
                
                # Brief pause
                time.sleep(0.02)
            
            # Final cleanup
            tray.update_status("idle", False)
            time.sleep(0.5)  # Allow completion
            
            self.log_test("Full system stress integration", "PASS", 
                         f"Completed {operations} rapid operations")
            
            app.shutdown()
            
        except Exception as e:
            self.log_test("Full system stress integration", "FAIL", str(e))
    
    def run_all_tests(self):
        """Run all integration tests"""
        print("=" * 70)
        print("VoiceFlow Integration Test Suite")
        print("=" * 70)
        
        test_methods = [
            self.test_complete_transcription_workflow,
            self.test_visual_tray_integration,
            self.test_hotkey_system_integration,
            self.test_config_persistence_integration,
            self.test_audio_processing_chain,
            self.test_error_propagation_integration,
            self.test_resource_management_integration,
            self.test_threading_integration,
            self.test_full_system_stress_integration
        ]
        
        start_time = time.perf_counter()
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                self.log_test(test_method.__name__, "FAIL", f"Test runner error: {e}")
            
            time.sleep(0.5)  # Pause between tests
        
        total_time = time.perf_counter() - start_time
        
        # Cleanup
        self.cleanup()
        
        # Summary
        print("\n" + "=" * 70)
        print("INTEGRATION TEST SUMMARY")
        print("=" * 70)
        
        passed = len([r for r in self.test_results if r[1] == "PASS"])
        failed = len([r for r in self.test_results if r[1] == "FAIL"])
        warnings = len([r for r in self.test_results if r[1] == "WARNING"])
        
        print(f"Total Tests: {len(self.test_results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Warnings: {warnings}")
        print(f"Total Duration: {total_time:.2f}s")
        
        return {
            "total": len(self.test_results),
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "duration": total_time,
            "results": self.test_results
        }

def main():
    """Main test runner"""
    try:
        suite = IntegrationTestSuite()
        summary = suite.run_all_tests()
        
        # Exit based on critical failures
        if summary["failed"] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nIntegration tests interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"Integration test suite error: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()