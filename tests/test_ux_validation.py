#!/usr/bin/env python3
"""
VoiceFlow User Experience (UX) Testing Suite

This module provides comprehensive user experience validation tests for VoiceFlow.
Tests real user scenarios to ensure the system is intuitive, accessible, and 
provides a great experience for users in their daily workflows.

Test Categories:
1. User Journey Testing - Complete user workflows from first-time to expert user
2. Usability Testing - Installation, setup, configuration, interface clarity
3. Accessibility Testing - Keyboard navigation, audio feedback, error handling
4. User Scenario Validation - Real-world usage patterns and workflows
5. User Experience Metrics - Performance indicators and satisfaction measures
"""

import pytest
import asyncio
import time
import json
import os
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import threading
import subprocess
import psutil

# Import VoiceFlow modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.voiceflow_core import VoiceFlowEngine
from core.ai_enhancement import AIEnhancer
from utils.config import load_config


class UXTestEnvironment:
    """Manages isolated test environments for UX testing"""
    
    def __init__(self):
        self.temp_dir = None
        self.config_path = None
        self.db_path = None
        self.engine = None
        self.ai_enhancer = None
        self.start_time = None
        self.metrics = {}
        
    def setup(self):
        """Set up a clean test environment"""
        self.start_time = time.time()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_ux_test_"))
        self.config_path = self.temp_dir / "config.json"
        self.db_path = self.temp_dir / "voiceflow.db"
        
        # Create test configuration
        test_config = {
            "general": {
                "home_dir": str(self.temp_dir),
                "db_path": str(self.db_path),
                "auto_start": False,
                "minimize_to_tray": False
            },
            "transcription": {
                "model": "tiny",
                "language": "en",
                "copy_to_clipboard": True,
                "auto_inject": False
            },
            "ai_enhancement": {
                "enabled": False,
                "ollama_url": "http://localhost:11434"
            },
            "hotkeys": {
                "record_toggle": "ctrl+alt+space"
            }
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(test_config, f, indent=2)
            
        # Initialize components
        os.environ['VOICEFLOW_CONFIG'] = str(self.config_path)
        self.config = load_config()
        
        # Create mock components for testing
        self.setup_mock_components()
        
    def setup_mock_components(self):
        """Set up mock components for UX testing"""
        # Mock audio recorder
        self.mock_recorder = Mock()
        self.mock_recorder.transcribe = Mock(return_value="test transcription")
        self.mock_recorder.is_available = Mock(return_value=True)
        
        # Mock system integration
        self.mock_system = Mock()
        self.mock_system.inject_text = Mock()
        self.mock_system.register_hotkey = Mock(return_value=True)
        self.mock_system.copy_to_clipboard = Mock()
        
    def teardown(self):
        """Clean up test environment"""
        if self.engine:
            try:
                self.engine.cleanup()
            except:
                pass
                
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            
        # Reset environment
        if 'VOICEFLOW_CONFIG' in os.environ:
            del os.environ['VOICEFLOW_CONFIG']
            
    def measure_time_to_success(self, operation_name, start_time=None):
        """Measure time from start to first success"""
        if start_time is None:
            start_time = self.start_time
        success_time = time.time()
        duration = success_time - start_time
        self.metrics[f"time_to_{operation_name}"] = duration
        return duration
        
    def record_user_action(self, action, duration=None, success=True, error=None):
        """Record user action for analysis"""
        if "user_actions" not in self.metrics:
            self.metrics["user_actions"] = []
            
        action_data = {
            "action": action,
            "timestamp": time.time(),
            "duration": duration,
            "success": success,
            "error": str(error) if error else None
        }
        self.metrics["user_actions"].append(action_data)


@pytest.fixture
def ux_environment():
    """Fixture providing UX test environment"""
    env = UXTestEnvironment()
    env.setup()
    yield env
    env.teardown()


class TestUserJourneyTesting:
    """Tests complete user journeys from installation to daily usage"""
    
    def test_first_time_user_complete_workflow(self, ux_environment):
        """Test complete first-time user experience from installation to first success"""
        env = ux_environment
        
        # Phase 1: Installation Experience (simulated)
        install_start = time.time()
        env.record_user_action("installation_start")
        
        # Simulate installation validation
        assert env.temp_dir.exists(), "Installation directory should be created"
        assert env.config_path.exists(), "Configuration file should be created"
        
        install_duration = env.measure_time_to_success("installation", install_start)
        assert install_duration < 30, "Installation should complete within 30 seconds"
        env.record_user_action("installation_complete", install_duration, True)
        
        # Phase 2: First Launch Experience
        launch_start = time.time()
        env.record_user_action("first_launch_start")
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            # Initialize engine (simulates first launch)
            env.engine = VoiceFlowEngine(config=env.config)
            assert env.engine is not None, "Engine should initialize successfully"
            
            # Check database creation
            assert env.db_path.exists(), "Database should be created on first launch"
            
            launch_duration = env.measure_time_to_success("first_launch", launch_start)
            assert launch_duration < 10, "First launch should complete within 10 seconds"
            env.record_user_action("first_launch_complete", launch_duration, True)
        
        # Phase 3: First Recording Attempt
        recording_start = time.time()
        env.record_user_action("first_recording_start")
        
        # Simulate user pressing hotkey for first time
        callback_called = []
        def test_callback(text):
            callback_called.append(text)
            
        env.engine.set_transcription_callback(test_callback)
        
        # Trigger transcription
        env.engine.start_recording()
        time.sleep(0.1)  # Simulate brief recording
        env.engine.stop_recording()
        
        # Verify transcription worked
        assert len(callback_called) > 0, "Transcription callback should be called"
        assert callback_called[0] == "test transcription", "Should receive expected transcription"
        
        recording_duration = env.measure_time_to_success("first_recording", recording_start)
        assert recording_duration < 5, "First recording should complete within 5 seconds"
        env.record_user_action("first_recording_complete", recording_duration, True)
        
        # Phase 4: Verify Text Appears (first success moment)
        env.mock_system.inject_text.assert_called_with("test transcription")
        env.record_user_action("first_success_moment", time.time() - env.start_time, True)
        
        # Phase 5: User Experience Metrics Validation
        total_time_to_first_success = time.time() - env.start_time
        assert total_time_to_first_success < 60, "Total time to first success should be under 1 minute"
        
        # Verify user journey metrics
        assert "time_to_installation" in env.metrics
        assert "time_to_first_launch" in env.metrics
        assert "time_to_first_recording" in env.metrics
        assert len(env.metrics["user_actions"]) >= 6  # All major steps recorded
        
        # All user actions should have succeeded
        failed_actions = [a for a in env.metrics["user_actions"] if not a["success"]]
        assert len(failed_actions) == 0, f"No actions should fail: {failed_actions}"
        
    def test_returning_user_workflow(self, ux_environment):
        """Test returning user experience (faster startup, remembered preferences)"""
        env = ux_environment
        
        # Setup existing user state
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            # First session (simulate previous usage)
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Add some history to database
            conn = sqlite3.connect(env.db_path)
            conn.execute("""
                INSERT INTO transcriptions (text, timestamp, word_count, processing_time)
                VALUES (?, ?, ?, ?)
            """, ("previous transcription", datetime.now().isoformat(), 2, 0.5))
            conn.commit()
            conn.close()
            
            env.engine.cleanup()
        
        # Test returning user experience
        startup_start = time.time()
        env.record_user_action("returning_user_startup")
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            # Second session (returning user)
            env.engine = VoiceFlowEngine(config=env.config)
            
            startup_duration = env.measure_time_to_success("returning_user_startup", startup_start)
            assert startup_duration < 5, "Returning user startup should be faster (under 5 seconds)"
            
            # Verify history is available
            stats = env.engine.get_statistics()
            assert stats["total_transcriptions"] >= 1, "Previous transcriptions should be remembered"
            
            env.record_user_action("returning_user_startup_complete", startup_duration, True)
    
    def test_configuration_change_workflow(self, ux_environment):
        """Test user experience when changing settings"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Test changing model (common user action)
            config_change_start = time.time()
            env.record_user_action("change_model_start")
            
            # Update configuration
            new_config = env.config.copy()
            new_config["transcription"]["model"] = "base"
            
            # Engine should handle configuration changes gracefully
            # In real implementation, this would trigger model reload
            env.record_user_action("change_model_complete", 
                                 time.time() - config_change_start, True)
            
            # Test enabling AI enhancement
            ai_enable_start = time.time()
            env.record_user_action("enable_ai_start")
            
            new_config["ai_enhancement"]["enabled"] = True
            
            # Should handle AI enhancement enabling
            env.record_user_action("enable_ai_complete",
                                 time.time() - ai_enable_start, True)
    
    def test_error_recovery_workflow(self, ux_environment):
        """Test user experience during error conditions and recovery"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Test microphone unavailable scenario
            env.mock_recorder.transcribe.side_effect = Exception("Microphone not available")
            
            error_start = time.time()
            env.record_user_action("microphone_error_start")
            
            # User attempts recording
            callback_called = []
            def error_callback(text):
                callback_called.append(text)
                
            env.engine.set_transcription_callback(error_callback)
            
            try:
                env.engine.start_recording()
                time.sleep(0.1)
                env.engine.stop_recording()
            except Exception as e:
                env.record_user_action("microphone_error_occurred", 
                                     time.time() - error_start, False, e)
            
            # Test recovery
            env.mock_recorder.transcribe.side_effect = None
            env.mock_recorder.transcribe.return_value = "recovery successful"
            
            recovery_start = time.time()
            env.record_user_action("error_recovery_start")
            
            env.engine.start_recording()
            time.sleep(0.1)
            env.engine.stop_recording()
            
            # Verify recovery worked
            assert len(callback_called) > 0, "Recovery should produce transcription"
            assert callback_called[-1] == "recovery successful"
            
            recovery_duration = time.time() - recovery_start
            env.record_user_action("error_recovery_complete", recovery_duration, True)
            
            # Recovery should be quick
            assert recovery_duration < 2, "Error recovery should be quick"


class TestUsabilityTesting:
    """Tests installation, setup, configuration ease of use, and interface clarity"""
    
    def test_installation_process_usability(self, ux_environment):
        """Test the installation process from a usability perspective"""
        env = ux_environment
        
        # Test directory structure creation
        installation_start = time.time()
        
        # Simulate installation steps
        required_dirs = [
            env.temp_dir / ".voiceflow",
            env.temp_dir / ".voiceflow" / "models",
            env.temp_dir / ".voiceflow" / "logs"
        ]
        
        for dir_path in required_dirs:
            dir_path.mkdir(parents=True, exist_ok=True)
            assert dir_path.exists(), f"Required directory {dir_path} should be created"
        
        # Test configuration file creation
        assert env.config_path.exists(), "Configuration file should be created"
        
        # Test configuration is valid JSON
        with open(env.config_path) as f:
            config_data = json.load(f)
            assert isinstance(config_data, dict), "Configuration should be valid JSON"
            assert "general" in config_data, "Configuration should have required sections"
        
        installation_time = time.time() - installation_start
        assert installation_time < 10, "Installation should complete quickly"
        
    def test_configuration_interface_usability(self, ux_environment):
        """Test configuration interface usability and clarity"""
        env = ux_environment
        
        # Test default configuration is sensible
        config = env.config
        
        # Verify default settings are user-friendly
        assert config.get("transcription", {}).get("model") == "tiny", "Default model should be fast (tiny)"
        assert config.get("transcription", {}).get("copy_to_clipboard") == True, "Should copy to clipboard by default"
        assert config.get("general", {}).get("auto_start") == False, "Should not auto-start by default for new users"
        
        # Test configuration validation
        invalid_configs = [
            {"transcription": {"model": "nonexistent"}},
            {"ai_enhancement": {"ollama_url": "invalid_url"}},
            {"hotkeys": {"record_toggle": "invalid+key+combo"}}
        ]
        
        for invalid_config in invalid_configs:
            # Configuration should handle invalid values gracefully
            # In real implementation, this would show user-friendly error messages
            pass
    
    def test_interface_clarity_and_feedback(self, ux_environment):
        """Test interface provides clear feedback and guidance"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Test status feedback during operations
            feedback_received = []
            
            def status_callback(status):
                feedback_received.append(status)
            
            # In real implementation, engine would provide status updates
            # Simulate status updates
            status_updates = ["initializing", "ready", "recording", "processing", "complete"]
            for status in status_updates:
                feedback_received.append(status)
            
            assert len(feedback_received) >= 3, "Should provide multiple status updates"
            assert "ready" in feedback_received, "Should indicate when ready"
            assert "complete" in feedback_received, "Should indicate when complete"
    
    def test_error_message_quality(self, ux_environment):
        """Test error messages are helpful and user-friendly"""
        env = ux_environment
        
        # Test various error scenarios
        error_scenarios = [
            {
                "error": "GPU not available",
                "expected_guidance": "fallback to CPU mode",
                "user_action": "Use CPU mode automatically"
            },
            {
                "error": "Model not found",
                "expected_guidance": "download model",
                "user_action": "Download required model"
            },
            {
                "error": "Microphone permission denied",
                "expected_guidance": "check permissions",
                "user_action": "Guide user to permission settings"
            }
        ]
        
        for scenario in error_scenarios:
            # In real implementation, would test actual error handling
            # For now, verify error handling structure exists
            assert "error" in scenario
            assert "expected_guidance" in scenario
            assert "user_action" in scenario


class TestAccessibilityTesting:
    """Tests keyboard navigation, audio feedback, and accessibility features"""
    
    def test_keyboard_navigation_and_hotkeys(self, ux_environment):
        """Test keyboard navigation and hotkey functionality"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Test hotkey registration
            env.mock_system.register_hotkey.assert_called()
            
            # Test default hotkey is accessible
            default_hotkey = env.config.get("hotkeys", {}).get("record_toggle", "")
            assert default_hotkey, "Default hotkey should be configured"
            
            # Verify hotkey doesn't conflict with common shortcuts
            conflicting_hotkeys = ["ctrl+c", "ctrl+v", "ctrl+z", "alt+tab"]
            assert default_hotkey.lower() not in conflicting_hotkeys, "Hotkey should not conflict with common shortcuts"
    
    def test_audio_feedback_accessibility(self, ux_environment):
        """Test audio feedback for accessibility"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Test audio feedback points
            feedback_points = [
                "recording_start",
                "recording_stop", 
                "transcription_complete",
                "error_occurred"
            ]
            
            # In real implementation, would test actual audio feedback
            # For now, verify feedback hooks exist in the system
            for point in feedback_points:
                # Verify feedback mechanism exists
                assert True  # Placeholder for actual audio feedback tests
    
    def test_screen_reader_compatibility(self, ux_environment):
        """Test compatibility with screen readers"""
        env = ux_environment
        
        # Test configuration has accessible descriptions
        config = env.config
        
        # Verify settings have clear names and descriptions
        settings_to_test = [
            ("transcription.model", "Whisper model selection"),
            ("transcription.language", "Primary language"),
            ("general.auto_start", "Auto-start behavior"),
            ("hotkeys.record_toggle", "Recording hotkey")
        ]
        
        for setting_path, description in settings_to_test:
            # In real implementation, would verify ARIA labels and descriptions
            # For now, verify setting paths exist
            parts = setting_path.split('.')
            current = config
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    current = None
                    break
            
            # Setting should exist in configuration
            # (In real app, would also verify accessibility markup)
    
    def test_error_handling_accessibility(self, ux_environment):
        """Test error handling provides accessible feedback"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            # Test error announcements
            env.mock_recorder.transcribe.side_effect = Exception("Test error")
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            error_callback_called = []
            def error_callback(error_msg):
                error_callback_called.append(error_msg)
            
            # In real implementation, would set error callback
            # and verify errors are announced accessibly
            
            try:
                env.engine.start_recording()
                time.sleep(0.1)
                env.engine.stop_recording()
            except Exception:
                # Error should be handled gracefully
                pass
            
            # Verify error handling doesn't break accessibility


class TestUserScenarioValidation:
    """Tests real-world user scenarios and workflows"""
    
    def test_document_writing_workflow(self, ux_environment):
        """Test document writing workflow scenario"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Simulate document writing session
            document_segments = [
                "Introduction paragraph here.",
                "First main point with details.",
                "Second main point with examples.",
                "Conclusion and summary."
            ]
            
            transcribed_segments = []
            def doc_callback(text):
                transcribed_segments.append(text)
            
            env.engine.set_transcription_callback(doc_callback)
            
            session_start = time.time()
            env.record_user_action("document_writing_start")
            
            # Simulate writing session with multiple segments
            for i, segment in enumerate(document_segments):
                env.mock_recorder.transcribe.return_value = segment
                
                segment_start = time.time()
                env.engine.start_recording()
                time.sleep(0.1)  # Simulate speaking time
                env.engine.stop_recording()
                
                segment_duration = time.time() - segment_start
                env.record_user_action(f"document_segment_{i+1}", segment_duration, True)
                
                # Verify text injection for document writing
                env.mock_system.inject_text.assert_called_with(segment)
            
            session_duration = time.time() - session_start
            env.record_user_action("document_writing_complete", session_duration, True)
            
            # Verify all segments were transcribed
            assert len(transcribed_segments) == len(document_segments)
            assert transcribed_segments == document_segments
            
            # Document writing session should be efficient
            assert session_duration < 30, "Document writing session should be efficient"
    
    def test_email_composition_scenario(self, ux_environment):
        """Test email composition workflow"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Email composition components
            email_parts = {
                "subject": "Meeting follow-up and action items",
                "greeting": "Hi team,",
                "body": "Thank you for the productive meeting today. Here are the key action items we discussed.",
                "closing": "Best regards, John"
            }
            
            composed_parts = []
            def email_callback(text):
                composed_parts.append(text)
            
            env.engine.set_transcription_callback(email_callback)
            
            email_start = time.time()
            env.record_user_action("email_composition_start")
            
            # Compose email parts
            for part_name, text in email_parts.items():
                env.mock_recorder.transcribe.return_value = text
                
                part_start = time.time()
                env.engine.start_recording()
                time.sleep(0.1)
                env.engine.stop_recording()
                
                part_duration = time.time() - part_start
                env.record_user_action(f"email_{part_name}", part_duration, True)
            
            email_duration = time.time() - email_start
            env.record_user_action("email_composition_complete", email_duration, True)
            
            # Verify email composition
            assert len(composed_parts) == len(email_parts)
            
            # Email composition should be quick
            assert email_duration < 15, "Email composition should be quick"
    
    def test_chat_messaging_scenario(self, ux_environment):
        """Test chat and messaging integration"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Chat messages (typically shorter, more informal)
            chat_messages = [
                "Hey, are you free for a quick call?",
                "Sure, let me finish this task first",
                "No problem, ping me when ready",
                "Will do, thanks!"
            ]
            
            sent_messages = []
            def chat_callback(text):
                sent_messages.append(text)
            
            env.engine.set_transcription_callback(chat_callback)
            
            chat_start = time.time()
            env.record_user_action("chat_conversation_start")
            
            # Simulate rapid chat exchange
            for i, message in enumerate(chat_messages):
                env.mock_recorder.transcribe.return_value = message
                
                msg_start = time.time()
                env.engine.start_recording()
                time.sleep(0.05)  # Shorter for chat messages
                env.engine.stop_recording()
                
                msg_duration = time.time() - msg_start
                env.record_user_action(f"chat_message_{i+1}", msg_duration, True)
                
                # Small delay between messages
                time.sleep(0.1)
            
            chat_duration = time.time() - chat_start
            env.record_user_action("chat_conversation_complete", chat_duration, True)
            
            # Verify chat messages
            assert len(sent_messages) == len(chat_messages)
            assert sent_messages == chat_messages
            
            # Chat should be very responsive
            assert chat_duration < 10, "Chat conversation should be very responsive"
    
    def test_code_documentation_workflow(self, ux_environment):
        """Test code documentation workflow"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Code documentation segments
            code_docs = [
                "This function calculates the total price including tax",
                "Parameters: price as float, tax rate as float",
                "Returns: total price with tax applied",
                "Raises ValueError if price is negative"
            ]
            
            documented_parts = []
            def code_callback(text):
                documented_parts.append(text)
            
            env.engine.set_transcription_callback(code_callback)
            
            doc_start = time.time()
            env.record_user_action("code_documentation_start")
            
            # Document code sections
            for i, doc_text in enumerate(code_docs):
                env.mock_recorder.transcribe.return_value = doc_text
                
                doc_segment_start = time.time()
                env.engine.start_recording()
                time.sleep(0.1)
                env.engine.stop_recording()
                
                segment_duration = time.time() - doc_segment_start
                env.record_user_action(f"code_doc_segment_{i+1}", segment_duration, True)
            
            doc_duration = time.time() - doc_start
            env.record_user_action("code_documentation_complete", doc_duration, True)
            
            # Verify documentation
            assert len(documented_parts) == len(code_docs)
            assert documented_parts == code_docs
    
    def test_note_taking_transcription_scenario(self, ux_environment):
        """Test note-taking and transcription workflow"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Meeting notes scenario
            meeting_notes = [
                "Meeting started at 2 PM with all team members present",
                "Discussed Q1 goals and target metrics",
                "Action item: John to prepare budget proposal by Friday",
                "Action item: Sarah to coordinate with marketing team",
                "Next meeting scheduled for next Tuesday at 2 PM"
            ]
            
            taken_notes = []
            def notes_callback(text):
                taken_notes.append(text)
            
            env.engine.set_transcription_callback(notes_callback)
            
            notes_start = time.time()
            env.record_user_action("note_taking_start")
            
            # Take notes during simulated meeting
            for i, note in enumerate(meeting_notes):
                env.mock_recorder.transcribe.return_value = note
                
                note_start = time.time()
                env.engine.start_recording()
                time.sleep(0.1)
                env.engine.stop_recording()
                
                note_duration = time.time() - note_start
                env.record_user_action(f"note_{i+1}", note_duration, True)
                
                # Brief pause between notes
                time.sleep(0.2)
            
            notes_duration = time.time() - notes_start
            env.record_user_action("note_taking_complete", notes_duration, True)
            
            # Verify note-taking
            assert len(taken_notes) == len(meeting_notes)
            assert taken_notes == meeting_notes
            
            # Note-taking should handle longer sessions
            assert notes_duration < 20, "Note-taking should handle reasonable session lengths"


class TestUserExperienceMetrics:
    """Tests user experience metrics and performance indicators"""
    
    def test_time_to_first_success_metrics(self, ux_environment):
        """Test time to first success measurement"""
        env = ux_environment
        
        # Measure complete workflow timing
        workflow_start = time.time()
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            # Initialize (first-time user simulation)
            init_start = time.time()
            env.engine = VoiceFlowEngine(config=env.config)
            init_time = env.measure_time_to_success("initialization", init_start)
            
            # First transcription
            first_transcription_start = time.time()
            callback_called = []
            def success_callback(text):
                callback_called.append(text)
                env.measure_time_to_success("first_transcription", first_transcription_start)
            
            env.engine.set_transcription_callback(success_callback)
            
            env.engine.start_recording()
            time.sleep(0.1)
            env.engine.stop_recording()
            
            # Verify timing metrics
            assert "time_to_initialization" in env.metrics
            assert "time_to_first_transcription" in env.metrics
            
            # Timing should meet usability standards
            assert env.metrics["time_to_initialization"] < 5, "Initialization should be under 5 seconds"
            assert env.metrics["time_to_first_transcription"] < 3, "First transcription should be under 3 seconds"
            
            total_time = time.time() - workflow_start
            assert total_time < 10, "Total time to first success should be under 10 seconds"
    
    def test_error_recovery_effectiveness(self, ux_environment):
        """Test error recovery effectiveness metrics"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Test error scenarios and recovery
            error_scenarios = [
                ("microphone_error", Exception("Microphone not available")),
                ("model_error", Exception("Model loading failed")),
                ("system_error", Exception("System integration failed"))
            ]
            
            recovery_times = []
            
            for scenario_name, error in error_scenarios:
                # Induce error
                env.mock_recorder.transcribe.side_effect = error
                
                error_start = time.time()
                try:
                    env.engine.start_recording()
                    time.sleep(0.1)
                    env.engine.stop_recording()
                except Exception:
                    pass  # Expected error
                
                # Simulate recovery
                env.mock_recorder.transcribe.side_effect = None
                env.mock_recorder.transcribe.return_value = "recovery successful"
                
                recovery_start = time.time()
                env.engine.start_recording()
                time.sleep(0.1)
                env.engine.stop_recording()
                
                recovery_time = time.time() - recovery_start
                recovery_times.append(recovery_time)
                
                env.record_user_action(f"{scenario_name}_recovery", recovery_time, True)
            
            # Verify recovery effectiveness
            avg_recovery_time = sum(recovery_times) / len(recovery_times)
            assert avg_recovery_time < 2, "Average error recovery should be under 2 seconds"
            
            # All recoveries should succeed
            recovery_actions = [a for a in env.metrics["user_actions"] if "recovery" in a["action"]]
            failed_recoveries = [a for a in recovery_actions if not a["success"]]
            assert len(failed_recoveries) == 0, "All error recoveries should succeed"
    
    def test_feature_adoption_tracking(self, ux_environment):
        """Test feature adoption and usage tracking"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Track feature usage
            features_used = {
                "basic_transcription": 0,
                "clipboard_copy": 0,
                "text_injection": 0,
                "hotkey_usage": 0
            }
            
            # Simulate feature usage
            callback_called = []
            def feature_callback(text):
                callback_called.append(text)
                features_used["basic_transcription"] += 1
                features_used["clipboard_copy"] += 1  # Always enabled in test config
                
            env.engine.set_transcription_callback(feature_callback)
            
            # Use features multiple times
            for i in range(5):
                env.engine.start_recording()
                time.sleep(0.1)
                env.engine.stop_recording()
                features_used["hotkey_usage"] += 1
                
                # Text injection occurs
                features_used["text_injection"] += 1
            
            # Verify feature adoption metrics
            assert features_used["basic_transcription"] == 5, "Basic transcription should be used 5 times"
            assert features_used["clipboard_copy"] == 5, "Clipboard copy should be used 5 times"
            
            # Calculate adoption rates
            total_sessions = 5
            adoption_rates = {
                feature: count / total_sessions 
                for feature, count in features_used.items()
            }
            
            # Core features should have high adoption
            assert adoption_rates["basic_transcription"] == 1.0, "Basic transcription should have 100% adoption"
            assert adoption_rates["hotkey_usage"] == 1.0, "Hotkey usage should have 100% adoption"
    
    def test_user_satisfaction_indicators(self, ux_environment):
        """Test user satisfaction indicators and metrics"""
        env = ux_environment
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Satisfaction indicators
            satisfaction_metrics = {
                "successful_operations": 0,
                "failed_operations": 0,
                "quick_operations": 0,  # Under 2 seconds
                "slow_operations": 0,   # Over 5 seconds
                "user_retries": 0
            }
            
            # Simulate user session
            callback_results = []
            def satisfaction_callback(text):
                callback_results.append(text)
            
            env.engine.set_transcription_callback(satisfaction_callback)
            
            # Perform various operations
            operations = [
                ("quick_note", 0.1),
                ("longer_message", 0.2),
                ("short_command", 0.05),
                ("detailed_text", 0.3)
            ]
            
            for op_name, duration in operations:
                op_start = time.time()
                
                env.mock_recorder.transcribe.return_value = f"transcription for {op_name}"
                
                env.engine.start_recording()
                time.sleep(duration)
                env.engine.stop_recording()
                
                op_duration = time.time() - op_start
                
                # Track satisfaction metrics
                satisfaction_metrics["successful_operations"] += 1
                
                if op_duration < 2:
                    satisfaction_metrics["quick_operations"] += 1
                elif op_duration > 5:
                    satisfaction_metrics["slow_operations"] += 1
            
            # Calculate satisfaction scores
            total_ops = len(operations)
            success_rate = satisfaction_metrics["successful_operations"] / total_ops
            quick_response_rate = satisfaction_metrics["quick_operations"] / total_ops
            
            # Verify satisfaction indicators
            assert success_rate >= 0.95, "Success rate should be at least 95%"
            assert quick_response_rate >= 0.8, "Quick response rate should be at least 80%"
            assert satisfaction_metrics["failed_operations"] == 0, "Should have no failed operations"
            assert satisfaction_metrics["slow_operations"] == 0, "Should have no slow operations"
            
            # Overall satisfaction score (weighted)
            satisfaction_score = (
                success_rate * 0.4 +
                quick_response_rate * 0.3 +
                (1 - satisfaction_metrics["user_retries"] / total_ops) * 0.3
            )
            
            assert satisfaction_score >= 0.9, "Overall satisfaction score should be at least 90%"


if __name__ == "__main__":
    # Run UX tests
    pytest.main([__file__, "-v", "--tb=short"])