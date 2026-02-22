#!/usr/bin/env python3
"""
End-to-End Testing Expert
Tests complete user workflows to catch real-world issues.
"""

import pytest
import subprocess
import sys
import os
import time
import tempfile
from pathlib import Path

# Test data
TEST_AUDIO_PATH = Path(__file__).parent.parent / "audio_samples" / "short_clear.wav"


class TestEndToEndWorkflows:
    """Test complete end-to-end user workflows."""
    
    def test_audio_file_processing_workflow(self):
        """Test the complete audio file processing workflow."""
        if not TEST_AUDIO_PATH.exists():
            pytest.skip("Test audio file not available")
        
        # Test the exact command a user would run
        cmd = [
            sys.executable, 
            "voiceflow_main.py", 
            "--audio_input", 
            str(TEST_AUDIO_PATH)
        ]
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=60,
                cwd=Path(__file__).parent.parent.parent
            )
            
            # Should not crash
            assert result.returncode == 0, f"Command failed with: {result.stderr}"
            
            # Should produce some output
            assert len(result.stdout) > 0, "No output produced"
            
            # Should not contain the error we fixed
            assert "Unsupported audio recorder type" not in result.stdout
            assert "Unsupported audio recorder type" not in result.stderr
            
        except subprocess.TimeoutExpired:
            pytest.fail("Audio processing timed out")
        except Exception as e:
            pytest.fail(f"Audio processing workflow failed: {e}")
    
    def test_simple_app_startup(self):
        """Test that the simple app starts without crashing."""
        cmd = [sys.executable, "voiceflow_simple.py"]
        
        try:
            # Start the process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=Path(__file__).parent.parent.parent
            )
            
            # Give it time to start and show any immediate errors
            time.sleep(3)
            
            # Check if it's still running (good sign)
            poll_result = process.poll()
            
            if poll_result is not None:
                # Process exited - check for errors
                stdout, stderr = process.communicate()
                pytest.fail(f"Simple app crashed on startup. STDOUT: {stdout}, STDERR: {stderr}")
            
            # Terminate the process
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                
        except Exception as e:
            pytest.fail(f"Simple app startup test failed: {e}")
    
    def test_configuration_loading(self):
        """Test configuration loading workflow."""
        try:
            # Test that configuration can be loaded
            cmd = [
                sys.executable, 
                "-c", 
                "from voiceflow.core.config import VoiceFlowConfig; "
                "config = VoiceFlowConfig(); "
                "config.validate(); "
                "print('Config loaded successfully')"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=Path(__file__).parent.parent.parent
            )
            
            assert result.returncode == 0, f"Config loading failed: {result.stderr}"
            assert "Config loaded successfully" in result.stdout
            
        except Exception as e:
            pytest.fail(f"Configuration loading test failed: {e}")


class TestUserScenarios:
    """Test specific user scenarios that could reveal bugs."""
    
    def test_rapid_hotkey_presses(self):
        """Test rapid hotkey presses don't cause crashes."""
        # This would test the scenario where a user rapidly presses F12
        # For now, we test the toggle_recording function directly
        
        try:
            from voiceflow_simple import toggle_recording, config
            
            # Simulate rapid calls (what happens with rapid hotkey presses)
            for _ in range(5):
                try:
                    toggle_recording()
                    time.sleep(0.1)  # Brief pause
                except Exception as e:
                    # Should handle errors gracefully
                    assert "Unsupported audio recorder type" not in str(e)
                    
        except ImportError:
            pytest.skip("voiceflow_simple not importable in test environment")
        except Exception as e:
            pytest.fail(f"Rapid hotkey test failed: {e}")
    
    def test_invalid_audio_file_handling(self):
        """Test handling of invalid audio files."""
        # Create a fake audio file
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(b"invalid audio data")
            fake_audio_path = f.name
        
        try:
            cmd = [
                sys.executable, 
                "voiceflow_main.py", 
                "--audio_input", 
                fake_audio_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=Path(__file__).parent.parent.parent
            )
            
            # Should handle the error gracefully, not crash with parameter errors
            assert "Unsupported audio recorder type" not in result.stderr
            assert "Unsupported audio recorder type" not in result.stdout
            
        finally:
            os.unlink(fake_audio_path)


class TestRegressionScenarios:
    """Test specific scenarios that caused previous bugs."""
    
    def test_audio_recorder_parameter_order_regression(self):
        """Test that the audio recorder parameter order bug doesn't return."""
        try:
            # This exact pattern caused the bug
            from voiceflow.core.config import VoiceFlowConfig
            from voiceflow.core.audio import create_audio_recorder
            
            config = VoiceFlowConfig()
            
            # This should work (correct order)
            recorder = create_audio_recorder(config, config.audio_recorder_type)
            assert recorder is not None
            
            # This should fail (wrong order that caused the bug)
            with pytest.raises((TypeError, ValueError, AttributeError)):
                create_audio_recorder(config.audio_recorder_type, config)
                
        except Exception as e:
            pytest.fail(f"Regression test failed: {e}")
    
    def test_transcription_engine_parameter_order_regression(self):
        """Test that the transcription engine parameter order bug doesn't return."""
        try:
            from voiceflow.core.config import VoiceFlowConfig
            from voiceflow.core.transcription import create_transcription_engine
            
            config = VoiceFlowConfig()
            
            # This should work (correct order)
            engine = create_transcription_engine(config, config.transcription_engine_type)
            assert engine is not None
            
            # This should fail (wrong order that caused the bug)
            with pytest.raises((TypeError, ValueError, AttributeError)):
                create_transcription_engine(config.transcription_engine_type, config)
                
        except Exception as e:
            pytest.fail(f"Regression test failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])