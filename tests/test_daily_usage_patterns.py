#!/usr/bin/env python3
"""
VoiceFlow Daily Usage Patterns Testing

Tests realistic daily usage patterns and workflows to ensure VoiceFlow
works well for actual users in their daily activities.

This module focuses on:
1. Realistic user sessions with varying intensity
2. Multi-application workflow testing
3. Performance under typical daily usage
4. User habit and pattern validation
5. Long-term usage sustainability
"""

import pytest
import time
import json
import tempfile
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import threading
import random

# Import VoiceFlow modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.voiceflow_core import VoiceFlowEngine
from utils.config import load_config


class DailyUsageSimulator:
    """Simulates realistic daily usage patterns"""
    
    def __init__(self):
        self.temp_dir = None
        self.config_path = None
        self.db_path = None
        self.engine = None
        self.usage_metrics = {}
        self.session_data = []
        
    def setup(self):
        """Set up test environment"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_daily_test_"))
        self.config_path = self.temp_dir / "config.json"
        self.db_path = self.temp_dir / "voiceflow.db"
        
        # Create realistic configuration
        test_config = {
            "general": {
                "home_dir": str(self.temp_dir),
                "db_path": str(self.db_path),
                "auto_start": True,
                "minimize_to_tray": True
            },
            "transcription": {
                "model": "base",  # Realistic model choice
                "language": "en",
                "copy_to_clipboard": True,
                "auto_inject": True
            },
            "ai_enhancement": {
                "enabled": True,
                "ollama_url": "http://localhost:11434"
            },
            "hotkeys": {
                "record_toggle": "ctrl+alt+space"
            }
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(test_config, f, indent=2)
            
        # Set environment
        import os
        os.environ['VOICEFLOW_CONFIG'] = str(self.config_path)
        self.config = load_config()
        
        # Setup mock components
        self.setup_mock_components()
        
    def setup_mock_components(self):
        """Set up realistic mock components"""
        # Mock audio recorder with realistic transcription
        self.mock_recorder = Mock()
        self.mock_recorder.is_available = Mock(return_value=True)
        
        # Mock system integration
        self.mock_system = Mock()
        self.mock_system.inject_text = Mock()
        self.mock_system.register_hotkey = Mock(return_value=True)
        self.mock_system.copy_to_clipboard = Mock()
        
        # Realistic transcription responses
        self.realistic_transcriptions = [
            # Email responses
            "Hi team, thanks for the update. I'll review the document and get back to you by end of day.",
            "Can we schedule a meeting for next week to discuss the project timeline?",
            "Please send me the latest version of the proposal when you have a chance.",
            
            # Document writing
            "The quarterly results show a significant improvement in user engagement metrics.",
            "Our analysis indicates that the new feature has been well-received by customers.",
            "Moving forward, we should focus on optimizing the user onboarding experience.",
            
            # Chat/messaging
            "Sure, let me check my calendar and get back to you.",
            "Thanks for the heads up, I'll take care of it.",
            "Great work on the presentation today!",
            
            # Notes/reminders
            "Remember to follow up with the client about the contract renewal.",
            "Meeting notes: discussed budget allocation and resource planning.",
            "Action item: prepare quarterly report for next week's board meeting.",
            
            # Code documentation
            "This function validates user input and returns sanitized data.",
            "TODO: optimize this loop for better performance.",
            "Bug fix: resolved issue with null pointer exception in login handler."
        ]
        
    def simulate_realistic_transcription(self, context="general"):
        """Generate realistic transcription based on context"""
        if context == "email":
            options = [t for t in self.realistic_transcriptions if any(word in t.lower() 
                      for word in ["team", "meeting", "send", "document", "schedule"])]
        elif context == "document":
            options = [t for t in self.realistic_transcriptions if any(word in t.lower() 
                      for word in ["results", "analysis", "quarterly", "forward"])]
        elif context == "chat":
            options = [t for t in self.realistic_transcriptions if any(word in t.lower() 
                      for word in ["sure", "thanks", "great", "check"])]
        elif context == "notes":
            options = [t for t in self.realistic_transcriptions if any(word in t.lower() 
                      for word in ["remember", "meeting", "action", "notes"])]
        elif context == "code":
            options = [t for t in self.realistic_transcriptions if any(word in t.lower() 
                      for word in ["function", "todo", "bug", "optimize"])]
        else:
            options = self.realistic_transcriptions
            
        return random.choice(options) if options else random.choice(self.realistic_transcriptions)
        
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


@pytest.fixture
def daily_usage_simulator():
    """Fixture providing daily usage simulator"""
    simulator = DailyUsageSimulator()
    simulator.setup()
    yield simulator
    simulator.teardown()


class TestMorningWorkflowPatterns:
    """Tests typical morning workflow patterns"""
    
    def test_morning_startup_routine(self, daily_usage_simulator):
        """Test typical morning startup and first usage"""
        simulator = daily_usage_simulator
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=simulator.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=simulator.mock_system):
            
            # Morning startup sequence
            startup_start = time.time()
            simulator.engine = VoiceFlowEngine(config=simulator.config)
            startup_time = time.time() - startup_start
            
            # Morning startup should be quick (user is ready to work)
            assert startup_time < 3, "Morning startup should be under 3 seconds"
            
            # First task: Check and respond to emails
            email_session_start = time.time()
            email_transcriptions = []
            
            def email_callback(text):
                email_transcriptions.append(text)
            
            simulator.engine.set_transcription_callback(email_callback)
            
            # Simulate 3 email responses (typical morning email check)
            for i in range(3):
                email_text = simulator.simulate_realistic_transcription("email")
                simulator.mock_recorder.transcribe.return_value = email_text
                
                simulator.engine.start_recording()
                time.sleep(0.1)  # Brief recording
                simulator.engine.stop_recording()
                time.sleep(0.2)  # Brief pause between emails
            
            email_session_time = time.time() - email_session_start
            
            # Email session should be efficient
            assert len(email_transcriptions) == 3
            assert email_session_time < 10, "Email session should complete quickly"
            
            # Verify all emails were processed
            assert all("team" in t.lower() or "meeting" in t.lower() or "send" in t.lower() 
                      for t in email_transcriptions), "Should generate email-like content"
    
    def test_morning_calendar_planning(self, daily_usage_simulator):
        """Test morning calendar and planning activities"""
        simulator = daily_usage_simulator
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=simulator.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=simulator.mock_system):
            
            simulator.engine = VoiceFlowEngine(config=simulator.config)
            
            # Planning session
            planning_items = [
                "Schedule team standup for 10 AM",
                "Block 2 hours for deep work on project proposal", 
                "Lunch meeting with client at 12:30",
                "Review and prepare for 3 PM presentation",
                "Send follow-up emails after client meeting"
            ]
            
            planned_items = []
            def planning_callback(text):
                planned_items.append(text)
            
            simulator.engine.set_transcription_callback(planning_callback)
            
            planning_start = time.time()
            
            for item in planning_items:
                simulator.mock_recorder.transcribe.return_value = item
                
                simulator.engine.start_recording()
                time.sleep(0.1)
                simulator.engine.stop_recording()
                time.sleep(0.1)  # Quick planning entries
            
            planning_time = time.time() - planning_start
            
            # Planning should be efficient
            assert len(planned_items) == len(planning_items)
            assert planning_time < 8, "Planning session should be quick"
            
            # Verify planning content
            assert all(any(keyword in item.lower() for keyword in ["schedule", "block", "meeting", "review", "send"]) 
                      for item in planned_items), "Should capture planning activities"


class TestWorkdayIntensiveUsage:
    """Tests intensive usage patterns during workday"""
    
    def test_document_writing_session(self, daily_usage_simulator):
        """Test sustained document writing session"""
        simulator = daily_usage_simulator
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=simulator.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=simulator.mock_system):
            
            simulator.engine = VoiceFlowEngine(config=simulator.config)
            
            # Simulate 30-minute document writing session
            writing_session_start = time.time()
            document_parts = []
            
            def writing_callback(text):
                document_parts.append(text)
            
            simulator.engine.set_transcription_callback(writing_callback)
            
            # Write document in 10 segments (realistic for focused writing)
            for i in range(10):
                doc_text = simulator.simulate_realistic_transcription("document")
                simulator.mock_recorder.transcribe.return_value = doc_text
                
                segment_start = time.time()
                simulator.engine.start_recording()
                time.sleep(0.15)  # Longer segments for document writing
                simulator.engine.stop_recording()
                
                # Realistic pause between segments (thinking time)
                time.sleep(0.3)
            
            writing_session_time = time.time() - writing_session_start
            
            # Verify sustained writing capability
            assert len(document_parts) == 10
            assert writing_session_time < 20, "Document writing should be efficient"
            
            # Check for document-like content
            assert all(any(word in part.lower() for word in ["results", "analysis", "should", "experience"]) 
                      for part in document_parts), "Should generate document-like content"
            
            # Verify system handled sustained usage
            simulator.mock_system.inject_text.assert_called()
            assert simulator.mock_system.inject_text.call_count == 10
    
    def test_meeting_notes_intensive(self, daily_usage_simulator):
        """Test intensive meeting notes taking"""
        simulator = daily_usage_simulator
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=simulator.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=simulator.mock_system):
            
            simulator.engine = VoiceFlowEngine(config=simulator.config)
            
            # Simulate 45-minute meeting with active note-taking
            meeting_start = time.time()
            meeting_notes = []
            
            def notes_callback(text):
                meeting_notes.append({
                    "text": text,
                    "timestamp": time.time()
                })
            
            simulator.engine.set_transcription_callback(notes_callback)
            
            # Take notes throughout meeting (15 note entries)
            for i in range(15):
                note_text = simulator.simulate_realistic_transcription("notes")
                simulator.mock_recorder.transcribe.return_value = note_text
                
                simulator.engine.start_recording()
                time.sleep(0.1)
                simulator.engine.stop_recording()
                
                # Variable pauses (realistic meeting dynamics)
                time.sleep(random.uniform(0.2, 0.8))
            
            meeting_time = time.time() - meeting_start
            
            # Verify meeting notes capability
            assert len(meeting_notes) == 15
            assert meeting_time < 25, "Meeting notes should be captured efficiently"
            
            # Check note timing distribution
            timestamps = [note["timestamp"] for note in meeting_notes]
            time_gaps = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            avg_gap = sum(time_gaps) / len(time_gaps)
            
            # Should handle variable timing
            assert 0.3 < avg_gap < 2.0, "Should handle realistic meeting note timing"
    
    def test_rapid_chat_responses(self, daily_usage_simulator):
        """Test rapid chat/messaging responses"""
        simulator = daily_usage_simulator
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=simulator.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=simulator.mock_system):
            
            simulator.engine = VoiceFlowEngine(config=simulator.config)
            
            # Simulate active chat conversation (20 rapid responses)
            chat_start = time.time()
            chat_responses = []
            
            def chat_callback(text):
                chat_responses.append(text)
            
            simulator.engine.set_transcription_callback(chat_callback)
            
            for i in range(20):
                chat_text = simulator.simulate_realistic_transcription("chat")
                simulator.mock_recorder.transcribe.return_value = chat_text
                
                response_start = time.time()
                simulator.engine.start_recording()
                time.sleep(0.05)  # Quick chat responses
                simulator.engine.stop_recording()
                
                response_time = time.time() - response_start
                
                # Chat responses should be very quick
                assert response_time < 1, f"Chat response {i+1} took too long: {response_time:.2f}s"
                
                # Brief pause between messages
                time.sleep(0.1)
            
            total_chat_time = time.time() - chat_start
            
            # Verify rapid response capability
            assert len(chat_responses) == 20
            assert total_chat_time < 15, "Rapid chat should be very responsive"
            
            # Verify chat-like content
            assert all(any(word in response.lower() for word in ["sure", "thanks", "great", "check"]) 
                      for response in chat_responses), "Should generate chat-like content"


class TestApplicationSwitchingPatterns:
    """Tests switching between different applications and contexts"""
    
    def test_multi_application_workflow(self, daily_usage_simulator):
        """Test switching between multiple applications"""
        simulator = daily_usage_simulator
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=simulator.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=simulator.mock_system):
            
            simulator.engine = VoiceFlowEngine(config=simulator.config)
            
            # Simulate realistic application switching workflow
            workflow_start = time.time()
            app_usage = []
            
            def app_callback(text):
                app_usage.append({
                    "text": text,
                    "app": current_app,
                    "timestamp": time.time()
                })
            
            simulator.engine.set_transcription_callback(app_callback)
            
            # Application switching sequence
            applications = [
                ("email", "email", 3),      # 3 email responses
                ("document", "document", 5), # 5 document segments  
                ("chat", "chat", 4),        # 4 chat messages
                ("code", "code", 3),        # 3 code comments
                ("notes", "notes", 2)       # 2 quick notes
            ]
            
            for app_name, context, count in applications:
                current_app = app_name
                
                for i in range(count):
                    text = simulator.simulate_realistic_transcription(context)
                    simulator.mock_recorder.transcribe.return_value = text
                    
                    simulator.engine.start_recording()
                    time.sleep(0.1)
                    simulator.engine.stop_recording()
                    time.sleep(0.1)
                
                # Simulate app switching delay
                time.sleep(0.3)
            
            workflow_time = time.time() - workflow_start
            
            # Verify multi-app usage
            assert len(app_usage) == 17  # Total entries across all apps
            assert workflow_time < 30, "Multi-app workflow should be efficient"
            
            # Verify all applications were used
            apps_used = set(entry["app"] for entry in app_usage)
            expected_apps = {"email", "document", "chat", "code", "notes"}
            assert apps_used == expected_apps, "Should handle all application types"
            
            # Verify context switching worked
            email_entries = [e for e in app_usage if e["app"] == "email"]
            doc_entries = [e for e in app_usage if e["app"] == "document"]
            
            assert len(email_entries) == 3
            assert len(doc_entries) == 5
    
    def test_concurrent_usage_simulation(self, daily_usage_simulator):
        """Test handling of concurrent-like usage patterns"""
        simulator = daily_usage_simulator
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=simulator.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=simulator.mock_system):
            
            simulator.engine = VoiceFlowEngine(config=simulator.config)
            
            # Simulate interrupted workflows (common in real usage)
            concurrent_start = time.time()
            usage_events = []
            
            def concurrent_callback(text):
                usage_events.append({
                    "text": text,
                    "task": current_task,
                    "timestamp": time.time()
                })
            
            simulator.engine.set_transcription_callback(concurrent_callback)
            
            # Simulate interruption pattern
            # Task 1: Start document writing
            current_task = "document_writing"
            for i in range(3):
                text = simulator.simulate_realistic_transcription("document")
                simulator.mock_recorder.transcribe.return_value = text
                
                simulator.engine.start_recording()
                time.sleep(0.1)
                simulator.engine.stop_recording()
                time.sleep(0.2)
            
            # Interruption: Urgent chat response
            current_task = "urgent_chat"
            for i in range(2):
                text = simulator.simulate_realistic_transcription("chat")
                simulator.mock_recorder.transcribe.return_value = text
                
                simulator.engine.start_recording()
                time.sleep(0.05)  # Quick responses
                simulator.engine.stop_recording()
                time.sleep(0.1)
            
            # Return to document writing
            current_task = "document_writing_resume"
            for i in range(2):
                text = simulator.simulate_realistic_transcription("document")
                simulator.mock_recorder.transcribe.return_value = text
                
                simulator.engine.start_recording()
                time.sleep(0.1)
                simulator.engine.stop_recording()
                time.sleep(0.2)
            
            concurrent_time = time.time() - concurrent_start
            
            # Verify handling of interruptions
            assert len(usage_events) == 7
            assert concurrent_time < 15, "Should handle task interruptions efficiently"
            
            # Verify task switching
            tasks_used = set(event["task"] for event in usage_events)
            expected_tasks = {"document_writing", "urgent_chat", "document_writing_resume"}
            assert tasks_used == expected_tasks, "Should handle task interruptions"


class TestLongTermUsagePatterns:
    """Tests patterns that emerge over longer usage periods"""
    
    def test_daily_usage_sustainability(self, daily_usage_simulator):
        """Test system sustainability over a full day simulation"""
        simulator = daily_usage_simulator
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=simulator.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=simulator.mock_system):
            
            simulator.engine = VoiceFlowEngine(config=simulator.config)
            
            # Simulate full day usage (compressed to reasonable test time)
            daily_start = time.time()
            daily_usage = {
                "morning": [],
                "afternoon": [],
                "evening": []
            }
            
            def daily_callback(text):
                current_period = current_time_period
                daily_usage[current_period].append({
                    "text": text,
                    "timestamp": time.time()
                })
            
            simulator.engine.set_transcription_callback(daily_callback)
            
            # Morning session (heavy email/planning)
            current_time_period = "morning"
            for i in range(15):
                context = "email" if i < 8 else "notes"
                text = simulator.simulate_realistic_transcription(context)
                simulator.mock_recorder.transcribe.return_value = text
                
                simulator.engine.start_recording()
                time.sleep(0.1)
                simulator.engine.stop_recording()
                time.sleep(0.1)
            
            # Afternoon session (document work, meetings)
            current_time_period = "afternoon"
            for i in range(25):
                context = "document" if i < 15 else "notes"
                text = simulator.simulate_realistic_transcription(context)
                simulator.mock_recorder.transcribe.return_value = text
                
                simulator.engine.start_recording()
                time.sleep(0.1)
                simulator.engine.stop_recording()
                time.sleep(0.1)
            
            # Evening session (wrap-up, light usage)
            current_time_period = "evening"
            for i in range(8):
                context = "email" if i < 4 else "notes"
                text = simulator.simulate_realistic_transcription(context)
                simulator.mock_recorder.transcribe.return_value = text
                
                simulator.engine.start_recording()
                time.sleep(0.1)
                simulator.engine.stop_recording()
                time.sleep(0.1)
            
            daily_time = time.time() - daily_start
            
            # Verify daily sustainability
            total_operations = sum(len(period) for period in daily_usage.values())
            assert total_operations == 48, "Should handle full day of operations"
            assert daily_time < 60, "Daily simulation should complete in reasonable time"
            
            # Verify usage distribution
            assert len(daily_usage["morning"]) == 15
            assert len(daily_usage["afternoon"]) == 25  # Peak usage
            assert len(daily_usage["evening"]) == 8
            
            # Check system remains responsive throughout day
            response_times = []
            for period in daily_usage.values():
                for i in range(1, len(period)):
                    gap = period[i]["timestamp"] - period[i-1]["timestamp"]
                    response_times.append(gap)
            
            avg_response = sum(response_times) / len(response_times)
            assert avg_response < 1.0, "Should maintain responsiveness throughout day"
    
    def test_usage_pattern_consistency(self, daily_usage_simulator):
        """Test consistency of performance across different usage patterns"""
        simulator = daily_usage_simulator
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=simulator.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=simulator.mock_system):
            
            simulator.engine = VoiceFlowEngine(config=simulator.config)
            
            # Test different usage intensity patterns
            patterns = {
                "burst": {"count": 10, "interval": 0.05, "duration": 0.05},  # Rapid burst
                "steady": {"count": 10, "interval": 0.5, "duration": 0.1},   # Steady pace
                "mixed": {"count": 10, "interval": "variable", "duration": 0.1}  # Variable timing
            }
            
            pattern_results = {}
            
            for pattern_name, pattern_config in patterns.items():
                pattern_start = time.time()
                pattern_transcriptions = []
                
                def pattern_callback(text):
                    pattern_transcriptions.append({
                        "text": text,
                        "timestamp": time.time()
                    })
                
                simulator.engine.set_transcription_callback(pattern_callback)
                
                for i in range(pattern_config["count"]):
                    text = simulator.simulate_realistic_transcription()
                    simulator.mock_recorder.transcribe.return_value = text
                    
                    op_start = time.time()
                    simulator.engine.start_recording()
                    time.sleep(pattern_config["duration"])
                    simulator.engine.stop_recording()
                    op_time = time.time() - op_start
                    
                    # Variable interval for mixed pattern
                    if pattern_config["interval"] == "variable":
                        interval = random.uniform(0.1, 1.0)
                    else:
                        interval = pattern_config["interval"]
                    
                    time.sleep(interval)
                
                pattern_time = time.time() - pattern_start
                
                pattern_results[pattern_name] = {
                    "total_time": pattern_time,
                    "operations": len(pattern_transcriptions),
                    "avg_response": pattern_time / len(pattern_transcriptions)
                }
            
            # Verify consistency across patterns
            for pattern_name, results in pattern_results.items():
                assert results["operations"] == 10, f"{pattern_name} should complete all operations"
                assert results["avg_response"] < 2.0, f"{pattern_name} should maintain good response time"
            
            # Verify performance doesn't degrade significantly between patterns
            response_times = [results["avg_response"] for results in pattern_results.values()]
            max_response = max(response_times)
            min_response = min(response_times)
            
            # Response time variation should be reasonable
            variation_ratio = max_response / min_response
            assert variation_ratio < 3.0, "Response time variation should be reasonable across usage patterns"


if __name__ == "__main__":
    # Run daily usage pattern tests
    pytest.main([__file__, "-v", "--tb=short"])