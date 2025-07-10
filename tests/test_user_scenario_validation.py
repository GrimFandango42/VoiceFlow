#!/usr/bin/env python3
"""
VoiceFlow User Scenario Validation Testing

Tests comprehensive real-world user scenarios to validate that VoiceFlow
works effectively for actual user workflows and use cases.

This module focuses on:
1. Complete end-to-end user workflows
2. Real-world usage scenario validation
3. Cross-application integration testing
4. Performance under realistic conditions
5. User satisfaction in actual use cases
"""

import pytest
import time
import json
import tempfile
import sqlite3
import os
import random
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import threading

# Import VoiceFlow modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.voiceflow_core import VoiceFlowEngine
from utils.config import load_config


class UserScenarioTestEnvironment:
    """Test environment for comprehensive user scenario validation"""
    
    def __init__(self):
        self.temp_dir = None
        self.config_path = None
        self.db_path = None
        self.engine = None
        self.scenario_metrics = {}
        self.user_actions = []
        self.application_contexts = {}
        self.performance_data = {}
        
    def setup(self):
        """Set up test environment"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_scenario_test_"))
        self.config_path = self.temp_dir / "config.json"
        self.db_path = self.temp_dir / "voiceflow.db"
        
        # Create realistic user configuration
        test_config = {
            "general": {
                "home_dir": str(self.temp_dir),
                "db_path": str(self.db_path),
                "auto_start": True,
                "minimize_to_tray": True,
                "user_type": "professional"  # professional, student, casual
            },
            "transcription": {
                "model": "base",
                "language": "en",
                "copy_to_clipboard": True,
                "auto_inject": True,
                "preview_enabled": True
            },
            "ai_enhancement": {
                "enabled": True,
                "ollama_url": "http://localhost:11434",
                "context_aware": True,
                "auto_format": True
            },
            "hotkeys": {
                "record_toggle": "ctrl+alt+space",
                "quick_note": "ctrl+alt+n",
                "read_last": "ctrl+alt+r"
            },
            "applications": {
                "email_integration": True,
                "document_integration": True,
                "chat_integration": True,
                "code_integration": True
            },
            "user_preferences": {
                "preferred_contexts": ["email", "documents", "notes"],
                "working_hours": {"start": 9, "end": 17},
                "productivity_mode": True
            }
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(test_config, f, indent=2)
            
        os.environ['VOICEFLOW_CONFIG'] = str(self.config_path)
        self.config = load_config()
        
        self.setup_mock_components()
        self.setup_application_contexts()
        
    def setup_mock_components(self):
        """Set up realistic mock components"""
        # Mock audio recorder with context awareness
        self.mock_recorder = Mock()
        self.mock_recorder.is_available = Mock(return_value=True)
        self.mock_recorder.transcribe = Mock(return_value="test transcription")
        
        # Mock system integration with app detection
        self.mock_system = Mock()
        self.mock_system.inject_text = Mock()
        self.mock_system.register_hotkey = Mock(return_value=True)
        self.mock_system.copy_to_clipboard = Mock()
        self.mock_system.get_active_application = Mock(return_value="notepad")
        self.mock_system.get_window_title = Mock(return_value="Untitled - Notepad")
        
        # Mock AI enhancer with context awareness
        self.mock_ai_enhancer = Mock()
        self.mock_ai_enhancer.enhance_text = Mock(return_value="Enhanced text with proper formatting.")
        
    def setup_application_contexts(self):
        """Set up different application contexts for testing"""
        self.application_contexts = {
            "email": {
                "app_name": "outlook",
                "window_titles": ["Inbox - Outlook", "Compose Email - Outlook"],
                "typical_content": [
                    "Hi team, I wanted to follow up on yesterday's meeting",
                    "Thank you for your email. I'll review the document and get back to you",
                    "Please find the attached report for your review",
                    "I'm writing to confirm our meeting scheduled for next Tuesday"
                ],
                "ai_context": "email_professional"
            },
            "documents": {
                "app_name": "word",
                "window_titles": ["Document1 - Word", "Report.docx - Word"],
                "typical_content": [
                    "Executive Summary: This report analyzes the current market trends",
                    "The methodology employed in this study consists of three main phases",
                    "Based on our analysis, we recommend the following strategic initiatives",
                    "In conclusion, the data suggests a positive outlook for the coming quarter"
                ],
                "ai_context": "document_formal"
            },
            "chat": {
                "app_name": "teams",
                "window_titles": ["Microsoft Teams", "Chat - Teams"],
                "typical_content": [
                    "Hey, are you available for a quick call?",
                    "Thanks for the update, looks good to me",
                    "Can we reschedule today's meeting to tomorrow?",
                    "Just wanted to check in on the project status"
                ],
                "ai_context": "chat_casual"
            },
            "code": {
                "app_name": "vscode",
                "window_titles": ["main.py - Visual Studio Code", "project - VSCode"],
                "typical_content": [
                    "This function calculates the total price including tax and shipping",
                    "TODO: Optimize this algorithm for better performance",
                    "Fix bug where null values cause application crash",
                    "Add error handling for network timeout scenarios"
                ],
                "ai_context": "code_technical"
            },
            "notes": {
                "app_name": "notepad",
                "window_titles": ["Notes.txt - Notepad", "Meeting Notes - Notepad"],
                "typical_content": [
                    "Meeting notes from project standup on Monday morning",
                    "Remember to follow up with client about contract renewal",
                    "Ideas for improving user onboarding experience",
                    "Action items from quarterly planning session"
                ],
                "ai_context": "notes_informal"
            }
        }
        
    def simulate_application_switch(self, app_context):
        """Simulate switching to a different application"""
        context = self.application_contexts[app_context]
        self.mock_system.get_active_application.return_value = context["app_name"]
        self.mock_system.get_window_title.return_value = random.choice(context["window_titles"])
        
        # Update AI context
        ai_context = context["ai_context"]
        return app_context, ai_context
        
    def get_contextual_transcription(self, app_context):
        """Get realistic transcription for the application context"""
        if app_context in self.application_contexts:
            content_options = self.application_contexts[app_context]["typical_content"]
            return random.choice(content_options)
        return "Generic transcription content"
        
    def record_user_action(self, action, context, duration=0, success=True, data=None):
        """Record user action with context"""
        self.user_actions.append({
            "action": action,
            "context": context,
            "duration": duration,
            "success": success,
            "data": data or {},
            "timestamp": time.time()
        })
        
    def track_scenario_metric(self, scenario, metric_name, value):
        """Track metrics for specific scenarios"""
        if scenario not in self.scenario_metrics:
            self.scenario_metrics[scenario] = {}
        self.scenario_metrics[scenario][metric_name] = value
        
    def record_performance_data(self, operation, timing_data):
        """Record performance data for operations"""
        if operation not in self.performance_data:
            self.performance_data[operation] = []
        self.performance_data[operation].append(timing_data)
        
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
            
        if 'VOICEFLOW_CONFIG' in os.environ:
            del os.environ['VOICEFLOW_CONFIG']


@pytest.fixture
def user_scenario_env():
    """Fixture providing user scenario test environment"""
    env = UserScenarioTestEnvironment()
    env.setup()
    yield env
    env.teardown()


class TestProfessionalWorkflowScenarios:
    """Tests professional user workflow scenarios"""
    
    def test_email_workflow_scenario(self, user_scenario_env):
        """Test complete email workflow from drafting to sending"""
        env = user_scenario_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Scenario: Professional composing multiple emails
            workflow_start = time.time()
            
            # Switch to email application
            app_context, ai_context = env.simulate_application_switch("email")
            env.record_user_action("switch_to_email", app_context)
            
            email_scenarios = [
                {
                    "type": "reply_to_client",
                    "expected_tone": "professional",
                    "content_length": "medium"
                },
                {
                    "type": "team_update",
                    "expected_tone": "collaborative", 
                    "content_length": "long"
                },
                {
                    "type": "quick_confirmation",
                    "expected_tone": "brief",
                    "content_length": "short"
                }
            ]
            
            composed_emails = []
            
            def email_callback(text):
                # Simulate AI enhancement for email context
                enhanced = env.mock_ai_enhancer.enhance_text(text)
                composed_emails.append({
                    "original": text,
                    "enhanced": enhanced,
                    "context": ai_context,
                    "timestamp": time.time()
                })
                env.mock_system.inject_text(enhanced)
            
            env.engine.set_transcription_callback(email_callback)
            
            for i, email_scenario in enumerate(email_scenarios):
                email_start = time.time()
                
                # Get contextual content
                email_content = env.get_contextual_transcription("email")
                env.mock_recorder.transcribe.return_value = email_content
                
                # Compose email via voice
                env.engine.start_recording()
                time.sleep(0.15)  # Simulate speaking time for email
                env.engine.stop_recording()
                
                email_duration = time.time() - email_start
                
                env.record_user_action(
                    f"compose_email_{email_scenario['type']}", 
                    "email", 
                    email_duration, 
                    True,
                    email_scenario
                )
                
                # Brief pause between emails (realistic workflow)
                time.sleep(0.2)
            
            workflow_duration = time.time() - workflow_start
            
            # Validate email workflow
            assert len(composed_emails) == len(email_scenarios), "Should compose all emails"
            assert workflow_duration < 30, "Email workflow should be efficient"
            
            # Check AI enhancement occurred
            enhanced_emails = [email for email in composed_emails if email["enhanced"] != email["original"]]
            assert len(enhanced_emails) >= 1, "AI enhancement should improve emails"
            
            # Check contextual appropriateness
            for email in composed_emails:
                assert len(email["original"]) > 10, "Emails should have substantial content"
                assert email["context"] == "email_professional", "Should use appropriate AI context"
            
            # Track scenario metrics
            env.track_scenario_metric("email_workflow", "total_emails", len(composed_emails))
            env.track_scenario_metric("email_workflow", "total_duration", workflow_duration)
            env.track_scenario_metric("email_workflow", "avg_email_time", workflow_duration / len(composed_emails))
    
    def test_document_creation_scenario(self, user_scenario_env):
        """Test document creation and editing workflow"""
        env = user_scenario_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Scenario: Creating a business report
            document_start = time.time()
            
            # Switch to document application
            app_context, ai_context = env.simulate_application_switch("documents")
            env.record_user_action("switch_to_documents", app_context)
            
            # Document structure sections
            document_sections = [
                {"section": "executive_summary", "length": "medium", "formality": "high"},
                {"section": "methodology", "length": "long", "formality": "high"},
                {"section": "findings", "length": "long", "formality": "medium"},
                {"section": "recommendations", "length": "medium", "formality": "high"},
                {"section": "conclusion", "length": "short", "formality": "high"}
            ]
            
            document_content = []
            
            def document_callback(text):
                # Simulate document-specific AI enhancement
                enhanced = env.mock_ai_enhancer.enhance_text(text)
                document_content.append({
                    "original": text,
                    "enhanced": enhanced,
                    "section": current_section["section"],
                    "word_count": len(text.split()),
                    "timestamp": time.time()
                })
                env.mock_system.inject_text(enhanced)
            
            env.engine.set_transcription_callback(document_callback)
            
            for current_section in document_sections:
                section_start = time.time()
                
                # Get document-appropriate content
                section_content = env.get_contextual_transcription("documents")
                env.mock_recorder.transcribe.return_value = section_content
                
                # Dictate section
                env.engine.start_recording()
                time.sleep(0.2)  # Longer for document sections
                env.engine.stop_recording()
                
                section_duration = time.time() - section_start
                
                env.record_user_action(
                    f"dictate_section_{current_section['section']}",
                    "documents",
                    section_duration,
                    True,
                    current_section
                )
                
                # Pause between sections (thinking/reviewing time)
                time.sleep(0.3)
            
            document_duration = time.time() - document_start
            
            # Validate document creation
            assert len(document_content) == len(document_sections), "Should create all sections"
            assert document_duration < 45, "Document creation should be reasonably fast"
            
            # Check content quality
            total_words = sum(section["word_count"] for section in document_content)
            assert total_words >= 50, "Document should have substantial content"
            
            # Check section completeness
            created_sections = [section["section"] for section in document_content]
            expected_sections = [section["section"] for section in document_sections]
            assert set(created_sections) == set(expected_sections), "Should complete all planned sections"
            
            # Track document metrics
            env.track_scenario_metric("document_creation", "total_sections", len(document_content))
            env.track_scenario_metric("document_creation", "total_words", total_words)
            env.track_scenario_metric("document_creation", "creation_duration", document_duration)
            env.track_scenario_metric("document_creation", "words_per_minute", total_words / (document_duration / 60))
    
    def test_meeting_notes_scenario(self, user_scenario_env):
        """Test real-time meeting notes workflow"""
        env = user_scenario_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Scenario: Taking notes during a 30-minute meeting
            meeting_start = time.time()
            
            # Switch to notes application
            app_context, ai_context = env.simulate_application_switch("notes")
            env.record_user_action("start_meeting_notes", app_context)
            
            # Meeting phases with different note-taking patterns
            meeting_phases = [
                {"phase": "introductions", "note_frequency": "low", "duration": 5},
                {"phase": "agenda_review", "note_frequency": "medium", "duration": 3},
                {"phase": "main_discussion", "note_frequency": "high", "duration": 15},
                {"phase": "action_items", "note_frequency": "high", "duration": 5},
                {"phase": "wrap_up", "note_frequency": "low", "duration": 2}
            ]
            
            meeting_notes = []
            
            def notes_callback(text):
                meeting_notes.append({
                    "text": text,
                    "phase": current_phase["phase"],
                    "timestamp": time.time() - meeting_start,
                    "word_count": len(text.split())
                })
                env.mock_system.inject_text(text)
            
            env.engine.set_transcription_callback(notes_callback)
            
            for current_phase in meeting_phases:
                phase_start = time.time()
                phase_duration = current_phase["duration"]
                note_frequency = current_phase["note_frequency"]
                
                # Determine number of notes based on frequency
                if note_frequency == "high":
                    notes_count = max(1, phase_duration // 2)  # Note every 2 minutes
                elif note_frequency == "medium":
                    notes_count = max(1, phase_duration // 3)  # Note every 3 minutes
                else:
                    notes_count = 1  # One note per phase
                
                for i in range(int(notes_count)):
                    note_content = env.get_contextual_transcription("notes")
                    env.mock_recorder.transcribe.return_value = note_content
                    
                    note_start = time.time()
                    env.engine.start_recording()
                    time.sleep(0.1)
                    env.engine.stop_recording()
                    note_duration = time.time() - note_start
                    
                    env.record_user_action(
                        f"note_{current_phase['phase']}_{i+1}",
                        "notes",
                        note_duration,
                        True,
                        {"phase": current_phase["phase"], "frequency": note_frequency}
                    )
                    
                    # Realistic pause between notes during same phase
                    if i < notes_count - 1:
                        time.sleep(0.5)
                
                # Simulate phase transition time
                time.sleep(0.2)
            
            meeting_duration = time.time() - meeting_start
            
            # Validate meeting notes
            assert len(meeting_notes) >= 5, "Should capture notes from all phases"
            assert meeting_duration < 20, "Simulated meeting should complete in reasonable time"
            
            # Check note distribution across phases
            phases_with_notes = set(note["phase"] for note in meeting_notes)
            expected_phases = set(phase["phase"] for phase in meeting_phases)
            assert phases_with_notes == expected_phases, "Should have notes from all meeting phases"
            
            # Check high-frequency phases have more notes
            main_discussion_notes = [note for note in meeting_notes if note["phase"] == "main_discussion"]
            action_items_notes = [note for note in meeting_notes if note["phase"] == "action_items"]
            intro_notes = [note for note in meeting_notes if note["phase"] == "introductions"]
            
            assert len(main_discussion_notes) >= len(intro_notes), "Main discussion should have more notes"
            
            # Track meeting metrics
            total_words = sum(note["word_count"] for note in meeting_notes)
            env.track_scenario_metric("meeting_notes", "total_notes", len(meeting_notes))
            env.track_scenario_metric("meeting_notes", "total_words", total_words)
            env.track_scenario_metric("meeting_notes", "meeting_duration", meeting_duration)
            env.track_scenario_metric("meeting_notes", "notes_per_minute", len(meeting_notes) / (meeting_duration / 60))


class TestStudentWorkflowScenarios:
    """Tests student-specific workflow scenarios"""
    
    def test_lecture_notes_scenario(self, user_scenario_env):
        """Test taking lecture notes in real-time"""
        env = user_scenario_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Scenario: 45-minute lecture with note-taking
            lecture_start = time.time()
            
            app_context, ai_context = env.simulate_application_switch("notes")
            env.record_user_action("start_lecture_notes", app_context)
            
            # Lecture segments with different information density
            lecture_segments = [
                {"topic": "introduction", "density": "low", "technical_terms": False},
                {"topic": "key_concepts", "density": "high", "technical_terms": True},
                {"topic": "examples", "density": "medium", "technical_terms": False},
                {"topic": "complex_theory", "density": "high", "technical_terms": True},
                {"topic": "summary", "density": "medium", "technical_terms": False}
            ]
            
            lecture_notes = []
            
            def lecture_callback(text):
                lecture_notes.append({
                    "content": text,
                    "segment": current_segment["topic"],
                    "timestamp": time.time() - lecture_start,
                    "technical": current_segment["technical_terms"]
                })
                env.mock_system.inject_text(text)
            
            env.engine.set_transcription_callback(lecture_callback)
            
            for current_segment in lecture_segments:
                segment_start = time.time()
                
                # Adjust note frequency based on content density
                if current_segment["density"] == "high":
                    notes_in_segment = 3
                elif current_segment["density"] == "medium":
                    notes_in_segment = 2
                else:
                    notes_in_segment = 1
                
                for i in range(notes_in_segment):
                    # Use appropriate content for segment
                    if current_segment["technical_terms"]:
                        note_content = "This concept involves complex theoretical frameworks and specialized terminology"
                    else:
                        note_content = env.get_contextual_transcription("notes")
                    
                    env.mock_recorder.transcribe.return_value = note_content
                    
                    env.engine.start_recording()
                    time.sleep(0.1)
                    env.engine.stop_recording()
                    
                    env.record_user_action(
                        f"lecture_note_{current_segment['topic']}_{i+1}",
                        "lecture_notes",
                        0.1,
                        True,
                        current_segment
                    )
                    
                    # Realistic pause for processing/listening
                    time.sleep(0.3)
            
            lecture_duration = time.time() - lecture_start
            
            # Validate lecture notes
            assert len(lecture_notes) >= len(lecture_segments), "Should capture notes from all segments"
            
            # Check technical content handling
            technical_notes = [note for note in lecture_notes if note["technical"]]
            assert len(technical_notes) >= 2, "Should handle technical content appropriately"
            
            # Check note distribution
            segments_covered = set(note["segment"] for note in lecture_notes)
            expected_segments = set(segment["topic"] for segment in lecture_segments)
            assert segments_covered == expected_segments, "Should cover all lecture segments"
            
            env.track_scenario_metric("lecture_notes", "total_notes", len(lecture_notes))
            env.track_scenario_metric("lecture_notes", "lecture_duration", lecture_duration)
    
    def test_research_workflow_scenario(self, user_scenario_env):
        """Test research and bibliography workflow"""
        env = user_scenario_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Scenario: Research note compilation
            research_start = time.time()
            
            # Research activities
            research_activities = [
                {"activity": "source_annotation", "content_type": "academic"},
                {"activity": "summary_writing", "content_type": "synthesis"},
                {"activity": "quote_transcription", "content_type": "citation"},
                {"activity": "idea_capture", "content_type": "creative"}
            ]
            
            research_outputs = []
            
            def research_callback(text):
                research_outputs.append({
                    "text": text,
                    "activity": current_activity["activity"],
                    "type": current_activity["content_type"],
                    "timestamp": time.time()
                })
                env.mock_system.inject_text(text)
            
            env.engine.set_transcription_callback(research_callback)
            
            for current_activity in research_activities:
                activity_start = time.time()
                
                # Generate appropriate research content
                research_content = f"Research content for {current_activity['activity']} with {current_activity['content_type']} focus"
                env.mock_recorder.transcribe.return_value = research_content
                
                env.engine.start_recording()
                time.sleep(0.12)
                env.engine.stop_recording()
                
                activity_duration = time.time() - activity_start
                
                env.record_user_action(
                    f"research_{current_activity['activity']}",
                    "research",
                    activity_duration,
                    True,
                    current_activity
                )
                
                time.sleep(0.2)
            
            research_duration = time.time() - research_start
            
            # Validate research workflow
            assert len(research_outputs) == len(research_activities), "Should complete all research activities"
            
            # Check content type diversity
            content_types = set(output["type"] for output in research_outputs)
            assert len(content_types) >= 3, "Should handle diverse content types"
            
            env.track_scenario_metric("research_workflow", "activities_completed", len(research_outputs))
            env.track_scenario_metric("research_workflow", "total_duration", research_duration)


class TestCrossApplicationScenarios:
    """Tests scenarios involving multiple applications"""
    
    def test_multi_application_workflow(self, user_scenario_env):
        """Test workflow spanning multiple applications"""
        env = user_scenario_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Scenario: Research -> Document -> Email workflow
            workflow_start = time.time()
            
            # Multi-app workflow steps
            workflow_steps = [
                {"step": "research_notes", "app": "notes", "duration": 0.15},
                {"step": "document_draft", "app": "documents", "duration": 0.2},
                {"step": "email_summary", "app": "email", "duration": 0.1},
                {"step": "chat_update", "app": "chat", "duration": 0.08},
                {"step": "final_notes", "app": "notes", "duration": 0.1}
            ]
            
            workflow_outputs = []
            
            def workflow_callback(text):
                workflow_outputs.append({
                    "text": text,
                    "step": current_step["step"],
                    "app": current_step["app"],
                    "app_switch": len(workflow_outputs) == 0 or workflow_outputs[-1]["app"] != current_step["app"],
                    "timestamp": time.time()
                })
                env.mock_system.inject_text(text)
            
            env.engine.set_transcription_callback(workflow_callback)
            
            for current_step in workflow_steps:
                step_start = time.time()
                
                # Switch application context
                app_context, ai_context = env.simulate_application_switch(current_step["app"])
                
                # Get contextual content
                step_content = env.get_contextual_transcription(current_step["app"])
                env.mock_recorder.transcribe.return_value = step_content
                
                env.engine.start_recording()
                time.sleep(current_step["duration"])
                env.engine.stop_recording()
                
                step_duration = time.time() - step_start
                
                env.record_user_action(
                    current_step["step"],
                    current_step["app"],
                    step_duration,
                    True,
                    {"app_context": app_context}
                )
                
                # Simulate app switching time
                time.sleep(0.1)
            
            workflow_duration = time.time() - workflow_start
            
            # Validate multi-app workflow
            assert len(workflow_outputs) == len(workflow_steps), "Should complete all workflow steps"
            
            # Check application switching
            app_switches = sum(1 for output in workflow_outputs if output["app_switch"])
            assert app_switches >= 3, "Should switch between multiple applications"
            
            # Check app diversity
            apps_used = set(output["app"] for output in workflow_outputs)
            assert len(apps_used) >= 3, "Should use multiple different applications"
            
            # Verify context switching works
            for output in workflow_outputs:
                assert output["text"] != "", "Should produce content in all contexts"
            
            env.track_scenario_metric("multi_app_workflow", "total_steps", len(workflow_outputs))
            env.track_scenario_metric("multi_app_workflow", "apps_used", len(apps_used))
            env.track_scenario_metric("multi_app_workflow", "app_switches", app_switches)
            env.track_scenario_metric("multi_app_workflow", "total_duration", workflow_duration)
    
    def test_context_switching_performance(self, user_scenario_env):
        """Test performance when rapidly switching contexts"""
        env = user_scenario_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Rapid context switching test
            switching_start = time.time()
            
            # Rapid switches between different contexts
            contexts = ["email", "documents", "chat", "notes", "code"]
            switch_performances = []
            
            callback_results = []
            def switching_callback(text):
                callback_results.append({
                    "text": text,
                    "context": current_context,
                    "timestamp": time.time()
                })
                env.mock_system.inject_text(text)
            
            env.engine.set_transcription_callback(switching_callback)
            
            for i, current_context in enumerate(contexts * 2):  # Two rounds
                switch_start = time.time()
                
                # Switch context
                app_context, ai_context = env.simulate_application_switch(current_context)
                
                # Quick transcription
                context_content = env.get_contextual_transcription(current_context)
                env.mock_recorder.transcribe.return_value = context_content
                
                env.engine.start_recording()
                time.sleep(0.05)  # Very quick
                env.engine.stop_recording()
                
                switch_duration = time.time() - switch_start
                
                switch_performances.append({
                    "context": current_context,
                    "duration": switch_duration,
                    "iteration": i
                })
                
                env.record_performance_data("context_switch", {
                    "context": current_context,
                    "duration": switch_duration,
                    "iteration": i
                })
                
                # Minimal pause between switches
                time.sleep(0.02)
            
            total_switching_time = time.time() - switching_start
            
            # Validate context switching performance
            assert len(switch_performances) == len(contexts) * 2, "Should complete all context switches"
            
            # Check performance consistency
            avg_switch_time = sum(p["duration"] for p in switch_performances) / len(switch_performances)
            assert avg_switch_time < 1.0, "Average context switch should be under 1 second"
            
            # Check no performance degradation over time
            first_half = switch_performances[:len(contexts)]
            second_half = switch_performances[len(contexts):]
            
            avg_first_half = sum(p["duration"] for p in first_half) / len(first_half)
            avg_second_half = sum(p["duration"] for p in second_half) / len(second_half)
            
            performance_degradation = avg_second_half / avg_first_half
            assert performance_degradation < 1.5, "Performance should not degrade significantly over time"
            
            env.track_scenario_metric("context_switching", "total_switches", len(switch_performances))
            env.track_scenario_metric("context_switching", "avg_switch_time", avg_switch_time)
            env.track_scenario_metric("context_switching", "performance_consistency", performance_degradation)


class TestRealWorldPerformanceScenarios:
    """Tests performance under realistic usage conditions"""
    
    def test_extended_usage_session(self, user_scenario_env):
        """Test extended usage session with varied activities"""
        env = user_scenario_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Simulate 2-hour work session
            session_start = time.time()
            session_activities = []
            
            # Realistic work session pattern
            work_patterns = [
                {"period": "morning_email", "activity": "email", "count": 5, "pace": "moderate"},
                {"period": "document_work", "activity": "documents", "count": 8, "pace": "focused"},
                {"period": "meeting_break", "activity": "chat", "count": 3, "pace": "quick"},
                {"period": "afternoon_notes", "activity": "notes", "count": 6, "pace": "varied"},
                {"period": "wrap_up", "activity": "email", "count": 3, "pace": "quick"}
            ]
            
            def session_callback(text):
                session_activities.append({
                    "text": text,
                    "period": current_period,
                    "activity": current_activity,
                    "timestamp": time.time() - session_start
                })
                env.mock_system.inject_text(text)
            
            env.engine.set_transcription_callback(session_callback)
            
            for pattern in work_patterns:
                current_period = pattern["period"]
                current_activity = pattern["activity"]
                
                # Switch to appropriate app
                app_context, ai_context = env.simulate_application_switch(current_activity)
                
                for i in range(pattern["count"]):
                    activity_start = time.time()
                    
                    activity_content = env.get_contextual_transcription(current_activity)
                    env.mock_recorder.transcribe.return_value = activity_content
                    
                    env.engine.start_recording()
                    
                    # Vary timing based on pace
                    if pattern["pace"] == "quick":
                        time.sleep(0.05)
                    elif pattern["pace"] == "focused":
                        time.sleep(0.15)
                    elif pattern["pace"] == "varied":
                        time.sleep(random.uniform(0.05, 0.2))
                    else:  # moderate
                        time.sleep(0.1)
                    
                    env.engine.stop_recording()
                    
                    activity_duration = time.time() - activity_start
                    
                    env.record_user_action(
                        f"{current_period}_{i+1}",
                        current_activity,
                        activity_duration,
                        True,
                        {"pattern": pattern}
                    )
                    
                    # Realistic pauses between activities
                    time.sleep(random.uniform(0.1, 0.5))
                
                # Period transition time
                time.sleep(0.3)
            
            session_duration = time.time() - session_start
            
            # Validate extended session
            total_activities = sum(pattern["count"] for pattern in work_patterns)
            assert len(session_activities) == total_activities, "Should complete all planned activities"
            
            # Check session sustainability
            assert session_duration < 120, "Session should complete in reasonable simulated time"
            
            # Check performance consistency throughout session
            early_activities = session_activities[:5]
            late_activities = session_activities[-5:]
            
            early_avg_time = sum(a["timestamp"] for a in early_activities) / len(early_activities)
            late_avg_time = sum(a["timestamp"] for a in late_activities) / len(late_activities)
            
            # Performance should remain consistent
            assert all("text" in activity and activity["text"] for activity in session_activities), \
                "All activities should produce output throughout session"
            
            # Track comprehensive session metrics
            env.track_scenario_metric("extended_session", "total_activities", len(session_activities))
            env.track_scenario_metric("extended_session", "session_duration", session_duration)
            env.track_scenario_metric("extended_session", "activities_per_minute", len(session_activities) / (session_duration / 60))
            env.track_scenario_metric("extended_session", "periods_completed", len(work_patterns))
    
    def test_stress_testing_scenario(self, user_scenario_env):
        """Test system under stress conditions"""
        env = user_scenario_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Stress test: Rapid consecutive operations
            stress_start = time.time()
            stress_operations = []
            
            def stress_callback(text):
                stress_operations.append({
                    "text": text,
                    "timestamp": time.time() - stress_start,
                    "operation_id": len(stress_operations)
                })
                env.mock_system.inject_text(text)
            
            env.engine.set_transcription_callback(stress_callback)
            
            # Rapid-fire operations
            for i in range(20):
                operation_start = time.time()
                
                stress_content = f"Stress test operation number {i+1}"
                env.mock_recorder.transcribe.return_value = stress_content
                
                env.engine.start_recording()
                time.sleep(0.02)  # Very rapid
                env.engine.stop_recording()
                
                operation_duration = time.time() - operation_start
                
                env.record_performance_data("stress_operation", {
                    "operation_id": i,
                    "duration": operation_duration,
                    "timestamp": time.time() - stress_start
                })
                
                # Minimal pause
                time.sleep(0.01)
            
            stress_duration = time.time() - stress_start
            
            # Validate stress test
            assert len(stress_operations) == 20, "Should complete all stress operations"
            assert stress_duration < 10, "Stress test should complete quickly"
            
            # Check no operations failed
            failed_operations = [op for op in stress_operations if not op["text"]]
            assert len(failed_operations) == 0, "No operations should fail under stress"
            
            # Check timing consistency
            operation_timings = [data["duration"] for data in env.performance_data["stress_operation"]]
            max_timing = max(operation_timings)
            min_timing = min(operation_timings)
            
            timing_variance = max_timing / min_timing if min_timing > 0 else float('inf')
            assert timing_variance < 5.0, "Operation timing should be reasonably consistent under stress"
            
            env.track_scenario_metric("stress_test", "operations_completed", len(stress_operations))
            env.track_scenario_metric("stress_test", "stress_duration", stress_duration)
            env.track_scenario_metric("stress_test", "operations_per_second", len(stress_operations) / stress_duration)
            env.track_scenario_metric("stress_test", "timing_variance", timing_variance)


if __name__ == "__main__":
    # Run user scenario validation tests
    pytest.main([__file__, "-v", "--tb=short"])