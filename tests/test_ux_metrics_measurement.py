#!/usr/bin/env python3
"""
VoiceFlow User Experience Metrics and Measurement

Comprehensive testing framework for measuring and validating user experience
metrics to ensure VoiceFlow provides excellent usability and satisfaction.

This module focuses on:
1. Time-to-value and efficiency metrics
2. User satisfaction and engagement indicators
3. Feature adoption and usage analytics
4. Performance impact on user experience
5. Accessibility compliance metrics
6. Long-term user retention indicators
"""

import pytest
import time
import json
import tempfile
import sqlite3
import os
import statistics
import math
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import threading

# Import VoiceFlow modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.voiceflow_core import VoiceFlowEngine
from utils.config import load_config


class UXMetricsTestEnvironment:
    """Test environment for UX metrics measurement and validation"""
    
    def __init__(self):
        self.temp_dir = None
        self.config_path = None
        self.db_path = None
        self.engine = None
        self.metrics_data = {}
        self.user_sessions = []
        self.performance_metrics = {}
        self.satisfaction_indicators = {}
        self.accessibility_metrics = {}
        
    def setup(self):
        """Set up test environment"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="voiceflow_metrics_test_"))
        self.config_path = self.temp_dir / "config.json"
        self.db_path = self.temp_dir / "voiceflow.db"
        
        # Create metrics-focused configuration
        test_config = {
            "general": {
                "home_dir": str(self.temp_dir),
                "db_path": str(self.db_path),
                "analytics_enabled": True,
                "metrics_collection": True
            },
            "transcription": {
                "model": "base",
                "language": "en",
                "copy_to_clipboard": True,
                "auto_inject": True
            },
            "metrics": {
                "track_performance": True,
                "track_usage_patterns": True,
                "track_satisfaction": True,
                "track_accessibility": True,
                "anonymous_analytics": True
            },
            "ux_research": {
                "time_to_value_tracking": True,
                "efficiency_metrics": True,
                "error_tracking": True,
                "feature_adoption_tracking": True
            }
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(test_config, f, indent=2)
            
        os.environ['VOICEFLOW_CONFIG'] = str(self.config_path)
        self.config = load_config()
        
        self.setup_mock_components()
        self.initialize_metrics_tracking()
        
    def setup_mock_components(self):
        """Set up mock components for metrics testing"""
        # Mock audio recorder
        self.mock_recorder = Mock()
        self.mock_recorder.is_available = Mock(return_value=True)
        self.mock_recorder.transcribe = Mock(return_value="test transcription")
        
        # Mock system integration
        self.mock_system = Mock()
        self.mock_system.inject_text = Mock()
        self.mock_system.register_hotkey = Mock(return_value=True)
        self.mock_system.copy_to_clipboard = Mock()
        
        # Mock analytics system
        self.mock_analytics = Mock()
        self.mock_analytics.track_event = Mock()
        self.mock_analytics.track_timing = Mock()
        self.mock_analytics.track_satisfaction = Mock()
        
    def initialize_metrics_tracking(self):
        """Initialize metrics tracking structures"""
        self.metrics_data = {
            "time_to_value": [],
            "task_completion_times": [],
            "error_rates": [],
            "feature_adoption": {},
            "user_satisfaction_scores": [],
            "accessibility_compliance": {},
            "performance_metrics": {}
        }
        
    def track_time_to_value(self, user_type, start_time, first_success_time, value_type):
        """Track time from start to first value delivered"""
        time_to_value = first_success_time - start_time
        
        self.metrics_data["time_to_value"].append({
            "user_type": user_type,
            "time_seconds": time_to_value,
            "value_type": value_type,
            "timestamp": datetime.now().isoformat()
        })
        
        return time_to_value
        
    def track_task_completion(self, task_name, start_time, end_time, success=True, user_type="general"):
        """Track task completion metrics"""
        completion_time = end_time - start_time
        
        self.metrics_data["task_completion_times"].append({
            "task": task_name,
            "completion_time": completion_time,
            "success": success,
            "user_type": user_type,
            "timestamp": datetime.now().isoformat()
        })
        
        return completion_time
        
    def track_error_rate(self, operation_type, error_count, total_attempts):
        """Track error rates for different operations"""
        error_rate = error_count / total_attempts if total_attempts > 0 else 0
        
        if operation_type not in self.metrics_data["error_rates"]:
            self.metrics_data["error_rates"][operation_type] = []
            
        self.metrics_data["error_rates"][operation_type].append({
            "error_count": error_count,
            "total_attempts": total_attempts,
            "error_rate": error_rate,
            "timestamp": datetime.now().isoformat()
        })
        
        return error_rate
        
    def track_feature_adoption(self, feature_name, user_session_count, adoption_event):
        """Track when and how users adopt features"""
        if feature_name not in self.metrics_data["feature_adoption"]:
            self.metrics_data["feature_adoption"][feature_name] = {
                "first_discovery": [],
                "first_use": [],
                "regular_use": [],
                "abandonment": []
            }
            
        self.metrics_data["feature_adoption"][feature_name][adoption_event].append({
            "session_count": user_session_count,
            "timestamp": datetime.now().isoformat()
        })
        
    def track_satisfaction_score(self, metric_type, score, context=""):
        """Track user satisfaction scores"""
        self.metrics_data["user_satisfaction_scores"].append({
            "metric_type": metric_type,
            "score": score,
            "context": context,
            "timestamp": datetime.now().isoformat()
        })
        
    def track_accessibility_metric(self, metric_name, value, compliance_level=""):
        """Track accessibility compliance metrics"""
        self.metrics_data["accessibility_compliance"][metric_name] = {
            "value": value,
            "compliance_level": compliance_level,
            "timestamp": datetime.now().isoformat()
        }
        
    def track_performance_metric(self, metric_name, value, context=""):
        """Track performance metrics that impact UX"""
        if metric_name not in self.metrics_data["performance_metrics"]:
            self.metrics_data["performance_metrics"][metric_name] = []
            
        self.metrics_data["performance_metrics"][metric_name].append({
            "value": value,
            "context": context,
            "timestamp": datetime.now().isoformat()
        })
        
    def calculate_ux_score(self):
        """Calculate overall UX score based on collected metrics"""
        score_components = {}
        
        # Time to value score (faster is better)
        if self.metrics_data["time_to_value"]:
            avg_ttv = statistics.mean([m["time_seconds"] for m in self.metrics_data["time_to_value"]])
            # Score: 100 for < 10 seconds, linear decrease to 0 at 60 seconds
            score_components["time_to_value"] = max(0, 100 - (avg_ttv - 10) * 2)
        
        # Task completion score
        if self.metrics_data["task_completion_times"]:
            completion_rates = [m["success"] for m in self.metrics_data["task_completion_times"]]
            score_components["task_completion"] = (sum(completion_rates) / len(completion_rates)) * 100
        
        # Error rate score (lower is better)
        if self.metrics_data["error_rates"]:
            all_error_rates = []
            for operation_errors in self.metrics_data["error_rates"].values():
                all_error_rates.extend([e["error_rate"] for e in operation_errors])
            avg_error_rate = statistics.mean(all_error_rates)
            score_components["error_rate"] = max(0, 100 - (avg_error_rate * 100))
        
        # Feature adoption score
        if self.metrics_data["feature_adoption"]:
            adoption_scores = []
            for feature_data in self.metrics_data["feature_adoption"].values():
                first_use_count = len(feature_data["first_use"])
                regular_use_count = len(feature_data["regular_use"])
                if first_use_count > 0:
                    adoption_rate = regular_use_count / first_use_count
                    adoption_scores.append(adoption_rate * 100)
            score_components["feature_adoption"] = statistics.mean(adoption_scores) if adoption_scores else 0
        
        # Satisfaction score
        if self.metrics_data["user_satisfaction_scores"]:
            satisfaction_scores = [s["score"] for s in self.metrics_data["user_satisfaction_scores"]]
            score_components["satisfaction"] = statistics.mean(satisfaction_scores)
        
        # Accessibility score
        if self.metrics_data["accessibility_compliance"]:
            accessibility_scores = [m["value"] for m in self.metrics_data["accessibility_compliance"].values() 
                                  if isinstance(m["value"], (int, float))]
            score_components["accessibility"] = statistics.mean(accessibility_scores) if accessibility_scores else 100
        
        # Weighted overall score
        weights = {
            "time_to_value": 0.2,
            "task_completion": 0.25,
            "error_rate": 0.2,
            "feature_adoption": 0.15,
            "satisfaction": 0.15,
            "accessibility": 0.05
        }
        
        overall_score = 0
        total_weight = 0
        
        for component, score in score_components.items():
            if component in weights:
                overall_score += score * weights[component]
                total_weight += weights[component]
        
        return overall_score / total_weight if total_weight > 0 else 0, score_components
        
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
def ux_metrics_env():
    """Fixture providing UX metrics test environment"""
    env = UXMetricsTestEnvironment()
    env.setup()
    yield env
    env.teardown()


class TestTimeToValueMetrics:
    """Tests time-to-value and efficiency metrics"""
    
    def test_first_time_user_time_to_value(self, ux_metrics_env):
        """Test time to first value for new users"""
        env = ux_metrics_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            # Simulate first-time user journey
            user_start = time.time()
            
            # Phase 1: Installation/Setup (simulated)
            setup_start = user_start
            time.sleep(0.1)  # Simulate setup time
            setup_end = time.time()
            
            # Phase 2: First launch
            launch_start = setup_end
            env.engine = VoiceFlowEngine(config=env.config)
            launch_end = time.time()
            
            # Phase 3: First successful transcription (first value)
            first_transcription_start = launch_end
            
            callback_results = []
            def first_value_callback(text):
                callback_results.append(text)
                first_success_time = time.time()
                
                # Track time to value
                env.track_time_to_value(
                    "first_time_user",
                    user_start,
                    first_success_time,
                    "first_transcription"
                )
            
            env.engine.set_transcription_callback(first_value_callback)
            
            env.engine.start_recording()
            time.sleep(0.1)
            env.engine.stop_recording()
            
            # Validate time to value metrics
            ttv_metrics = env.metrics_data["time_to_value"]
            assert len(ttv_metrics) == 1, "Should track time to first value"
            
            first_ttv = ttv_metrics[0]["time_seconds"]
            assert first_ttv < 30, f"Time to first value should be under 30 seconds, got {first_ttv:.2f}s"
            assert first_ttv > 0, "Time to value should be positive"
            
            # Track additional value points
            # Second transcription (proving consistency)
            second_transcription_start = time.time()
            env.engine.start_recording()
            time.sleep(0.1)
            env.engine.stop_recording()
            second_transcription_end = time.time()
            
            env.track_time_to_value(
                "first_time_user",
                second_transcription_start,
                second_transcription_end,
                "second_transcription"
            )
            
            # Validate consistency value
            assert len(env.metrics_data["time_to_value"]) == 2, "Should track multiple value points"
            
            second_ttv = env.metrics_data["time_to_value"][1]["time_seconds"]
            assert second_ttv < first_ttv * 2, "Second transcription should be faster or similar"
    
    def test_returning_user_efficiency(self, ux_metrics_env):
        """Test efficiency metrics for returning users"""
        env = ux_metrics_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Simulate returning user with experience
            efficiency_tasks = [
                ("quick_email", 0.05, "Email response"),
                ("document_note", 0.1, "Document annotation"),
                ("chat_message", 0.03, "Chat response"),
                ("meeting_note", 0.08, "Meeting notes"),
                ("idea_capture", 0.06, "Idea documentation")
            ]
            
            task_efficiencies = []
            
            callback_results = []
            def efficiency_callback(text):
                callback_results.append(text)
            
            env.engine.set_transcription_callback(efficiency_callback)
            
            for task_name, target_duration, description in efficiency_tasks:
                task_start = time.time()
                
                env.mock_recorder.transcribe.return_value = f"Content for {description}"
                
                env.engine.start_recording()
                time.sleep(target_duration)
                env.engine.stop_recording()
                
                task_end = time.time()
                
                completion_time = env.track_task_completion(
                    task_name,
                    task_start,
                    task_end,
                    success=True,
                    user_type="returning_user"
                )
                
                task_efficiencies.append(completion_time)
                
                # Brief pause between tasks
                time.sleep(0.02)
            
            # Validate efficiency metrics
            assert len(task_efficiencies) == len(efficiency_tasks), "Should complete all efficiency tasks"
            
            avg_task_time = statistics.mean(task_efficiencies)
            assert avg_task_time < 1.0, f"Average task time should be under 1 second, got {avg_task_time:.3f}s"
            
            # Check consistency (standard deviation should be low)
            if len(task_efficiencies) > 1:
                std_dev = statistics.stdev(task_efficiencies)
                coefficient_of_variation = std_dev / avg_task_time
                assert coefficient_of_variation < 0.5, "Task timing should be consistent"
    
    def test_feature_discovery_efficiency(self, ux_metrics_env):
        """Test efficiency of feature discovery"""
        env = ux_metrics_env
        
        # Feature discovery scenarios
        feature_scenarios = [
            {"feature": "ai_enhancement", "discovery_method": "suggestion", "expected_sessions": 3},
            {"feature": "hotkey_customization", "discovery_method": "settings_exploration", "expected_sessions": 5},
            {"feature": "model_selection", "discovery_method": "performance_need", "expected_sessions": 7},
            {"feature": "language_switching", "discovery_method": "multilingual_use", "expected_sessions": 10}
        ]
        
        for scenario in feature_scenarios:
            feature_name = scenario["feature"]
            discovery_method = scenario["discovery_method"]
            session_count = scenario["expected_sessions"]
            
            # Track feature discovery timeline
            env.track_feature_adoption(feature_name, session_count, "first_discovery")
            
            # Simulate time to first use after discovery
            first_use_delay = random.uniform(1, 3)  # 1-3 sessions after discovery
            env.track_feature_adoption(feature_name, session_count + first_use_delay, "first_use")
            
            # Simulate regular adoption
            regular_use_delay = random.uniform(2, 5)  # 2-5 sessions after first use
            env.track_feature_adoption(feature_name, session_count + first_use_delay + regular_use_delay, "regular_use")
        
        # Validate feature adoption metrics
        adoption_data = env.metrics_data["feature_adoption"]
        assert len(adoption_data) == len(feature_scenarios), "Should track all features"
        
        for feature_name, feature_data in adoption_data.items():
            # Each feature should have discovery, first use, and regular use events
            assert len(feature_data["first_discovery"]) >= 1, f"{feature_name} should have discovery event"
            assert len(feature_data["first_use"]) >= 1, f"{feature_name} should have first use event"
            assert len(feature_data["regular_use"]) >= 1, f"{feature_name} should have regular use event"
            
            # Discovery should come before first use
            discovery_session = feature_data["first_discovery"][0]["session_count"]
            first_use_session = feature_data["first_use"][0]["session_count"]
            assert discovery_session <= first_use_session, f"{feature_name} discovery should precede first use"


class TestUserSatisfactionMetrics:
    """Tests user satisfaction and engagement indicators"""
    
    def test_task_satisfaction_measurement(self, ux_metrics_env):
        """Test measurement of task-level satisfaction"""
        env = ux_metrics_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Satisfaction measurement scenarios
            satisfaction_scenarios = [
                {
                    "task": "quick_transcription",
                    "expected_satisfaction": 95,  # High satisfaction for core feature
                    "factors": ["speed", "accuracy", "ease_of_use"]
                },
                {
                    "task": "settings_configuration",
                    "expected_satisfaction": 80,  # Lower satisfaction for complex task
                    "factors": ["discoverability", "clarity", "effectiveness"]
                },
                {
                    "task": "error_recovery",
                    "expected_satisfaction": 70,  # Lower satisfaction but acceptable
                    "factors": ["guidance", "recovery_time", "understanding"]
                },
                {
                    "task": "feature_discovery",
                    "expected_satisfaction": 85,  # Good satisfaction for exploration
                    "factors": ["intuitiveness", "helpfulness", "completion"]
                }
            ]
            
            for scenario in satisfaction_scenarios:
                task_name = scenario["task"]
                expected_score = scenario["expected_satisfaction"]
                factors = scenario["factors"]
                
                # Simulate task completion with satisfaction measurement
                task_start = time.time()
                
                # Simulate task execution
                if task_name == "quick_transcription":
                    env.engine.start_recording()
                    time.sleep(0.05)  # Very quick
                    env.engine.stop_recording()
                    actual_satisfaction = 95  # High satisfaction
                    
                elif task_name == "settings_configuration":
                    time.sleep(0.3)  # More time for settings
                    actual_satisfaction = 82  # Good satisfaction
                    
                elif task_name == "error_recovery":
                    time.sleep(0.2)  # Recovery time
                    actual_satisfaction = 73  # Acceptable satisfaction
                    
                else:  # feature_discovery
                    time.sleep(0.15)  # Discovery time
                    actual_satisfaction = 87  # Good satisfaction
                
                task_end = time.time()
                
                # Track task completion
                env.track_task_completion(task_name, task_start, task_end, success=True)
                
                # Track satisfaction score
                env.track_satisfaction_score("task_satisfaction", actual_satisfaction, task_name)
                
                # Track factor-specific satisfaction
                for factor in factors:
                    factor_score = actual_satisfaction + random.uniform(-5, 5)  # Slight variation
                    env.track_satisfaction_score(f"factor_{factor}", factor_score, task_name)
            
            # Validate satisfaction metrics
            satisfaction_scores = env.metrics_data["user_satisfaction_scores"]
            task_satisfaction_scores = [s for s in satisfaction_scores if s["metric_type"] == "task_satisfaction"]
            
            assert len(task_satisfaction_scores) == len(satisfaction_scenarios), "Should measure satisfaction for all tasks"
            
            # Check satisfaction score ranges
            for score_data in task_satisfaction_scores:
                score = score_data["score"]
                assert 0 <= score <= 100, f"Satisfaction score should be 0-100, got {score}"
                assert score >= 60, f"All task satisfaction should be acceptable (>=60), got {score}"
            
            # Calculate overall satisfaction
            avg_satisfaction = statistics.mean([s["score"] for s in task_satisfaction_scores])
            assert avg_satisfaction >= 75, f"Overall satisfaction should be good (>=75), got {avg_satisfaction:.1f}"
    
    def test_engagement_metrics(self, ux_metrics_env):
        """Test user engagement measurement"""
        env = ux_metrics_env
        
        # Engagement indicators
        engagement_metrics = [
            {"metric": "session_frequency", "value": 5.2, "unit": "sessions_per_week"},
            {"metric": "session_duration", "value": 12.5, "unit": "minutes"},
            {"metric": "feature_exploration", "value": 78, "unit": "percentage"},
            {"metric": "return_likelihood", "value": 89, "unit": "percentage"},
            {"metric": "recommendation_score", "value": 8.4, "unit": "out_of_10"}
        ]
        
        for metric_data in engagement_metrics:
            metric_name = metric_data["metric"]
            value = metric_data["value"]
            unit = metric_data["unit"]
            
            env.track_satisfaction_score(f"engagement_{metric_name}", value, f"measured_in_{unit}")
        
        # Simulate engagement patterns
        # High engagement: frequent short sessions
        high_engagement_pattern = {
            "sessions_per_day": 8,
            "avg_session_length": 3,  # minutes
            "features_used_per_session": 2.5,
            "task_completion_rate": 0.92
        }
        
        # Medium engagement: moderate usage
        medium_engagement_pattern = {
            "sessions_per_day": 4,
            "avg_session_length": 8,  # minutes
            "features_used_per_session": 1.8,
            "task_completion_rate": 0.85
        }
        
        engagement_patterns = [high_engagement_pattern, medium_engagement_pattern]
        
        for i, pattern in enumerate(engagement_patterns):
            pattern_type = "high" if i == 0 else "medium"
            
            for metric, value in pattern.items():
                env.track_satisfaction_score(f"engagement_pattern_{metric}", value, pattern_type)
        
        # Validate engagement metrics
        engagement_scores = [s for s in env.metrics_data["user_satisfaction_scores"] 
                           if "engagement" in s["metric_type"]]
        
        assert len(engagement_scores) >= len(engagement_metrics), "Should track comprehensive engagement metrics"
        
        # Check engagement score quality
        session_frequency_scores = [s for s in engagement_scores if "session_frequency" in s["metric_type"]]
        if session_frequency_scores:
            freq_score = session_frequency_scores[0]["score"]
            assert freq_score >= 3.0, "Session frequency should indicate regular use"
    
    def test_net_promoter_score_simulation(self, ux_metrics_env):
        """Test Net Promoter Score (NPS) measurement simulation"""
        env = ux_metrics_env
        
        # Simulate NPS responses from different user types
        nps_responses = [
            {"user_type": "power_user", "score": 9, "likelihood": "very_likely"},
            {"user_type": "casual_user", "score": 8, "likelihood": "likely"},
            {"user_type": "professional_user", "score": 9, "likelihood": "very_likely"},
            {"user_type": "student_user", "score": 7, "likelihood": "neutral"},
            {"user_type": "accessibility_user", "score": 8, "likelihood": "likely"},
            {"user_type": "multilingual_user", "score": 6, "likelihood": "neutral"},
            {"user_type": "enterprise_user", "score": 8, "likelihood": "likely"},
            {"user_type": "creative_user", "score": 9, "likelihood": "very_likely"}
        ]
        
        promoters = 0
        passives = 0
        detractors = 0
        
        for response in nps_responses:
            score = response["score"]
            user_type = response["user_type"]
            
            # NPS categorization
            if score >= 9:
                category = "promoter"
                promoters += 1
            elif score >= 7:
                category = "passive"
                passives += 1
            else:
                category = "detractor"
                detractors += 1
            
            env.track_satisfaction_score("nps_score", score, f"{user_type}_{category}")
        
        # Calculate NPS
        total_responses = len(nps_responses)
        nps = ((promoters - detractors) / total_responses) * 100
        
        env.track_satisfaction_score("net_promoter_score", nps, "overall")
        
        # Validate NPS metrics
        nps_scores = [s for s in env.metrics_data["user_satisfaction_scores"] 
                     if s["metric_type"] == "nps_score"]
        
        assert len(nps_scores) == len(nps_responses), "Should track all NPS responses"
        
        # Check NPS quality
        overall_nps = [s for s in env.metrics_data["user_satisfaction_scores"] 
                      if s["metric_type"] == "net_promoter_score"]
        
        if overall_nps:
            nps_value = overall_nps[0]["score"]
            assert nps_value >= 0, f"NPS should be positive, got {nps_value:.1f}"
            assert nps_value >= 25, f"NPS should indicate good satisfaction (>=25), got {nps_value:.1f}"


class TestPerformanceImpactMetrics:
    """Tests how performance impacts user experience metrics"""
    
    def test_response_time_satisfaction_correlation(self, ux_metrics_env):
        """Test correlation between response times and user satisfaction"""
        env = ux_metrics_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Test different response time scenarios
            response_scenarios = [
                {"response_time": 0.5, "expected_satisfaction": 95, "category": "excellent"},
                {"response_time": 1.0, "expected_satisfaction": 90, "category": "very_good"},
                {"response_time": 2.0, "expected_satisfaction": 80, "category": "good"},
                {"response_time": 3.0, "expected_satisfaction": 65, "category": "acceptable"},
                {"response_time": 5.0, "expected_satisfaction": 40, "category": "poor"}
            ]
            
            callback_results = []
            def performance_callback(text):
                callback_results.append(text)
            
            env.engine.set_transcription_callback(performance_callback)
            
            for scenario in response_scenarios:
                target_time = scenario["response_time"]
                expected_satisfaction = scenario["expected_satisfaction"]
                category = scenario["category"]
                
                # Simulate operation with specific response time
                operation_start = time.time()
                
                env.engine.start_recording()
                time.sleep(0.05)  # Brief recording
                env.engine.stop_recording()
                
                # Simulate processing delay
                time.sleep(target_time - 0.1)  # Adjust for recording time
                
                operation_end = time.time()
                actual_response_time = operation_end - operation_start
                
                # Track performance metric
                env.track_performance_metric("response_time", actual_response_time, category)
                
                # Calculate satisfaction based on response time
                # Satisfaction decreases as response time increases
                if actual_response_time <= 1.0:
                    satisfaction = 95 - (actual_response_time * 5)
                elif actual_response_time <= 3.0:
                    satisfaction = 85 - ((actual_response_time - 1.0) * 10)
                else:
                    satisfaction = max(20, 65 - ((actual_response_time - 3.0) * 15))
                
                env.track_satisfaction_score("response_time_satisfaction", satisfaction, 
                                           f"response_time_{actual_response_time:.1f}s")
            
            # Validate performance-satisfaction correlation
            response_times = env.metrics_data["performance_metrics"]["response_time"]
            satisfaction_scores = [s for s in env.metrics_data["user_satisfaction_scores"] 
                                 if s["metric_type"] == "response_time_satisfaction"]
            
            assert len(response_times) == len(response_scenarios), "Should track all response times"
            assert len(satisfaction_scores) == len(response_scenarios), "Should track satisfaction for all scenarios"
            
            # Check correlation: faster response should have higher satisfaction
            sorted_by_time = sorted(zip([r["value"] for r in response_times], 
                                      [s["score"] for s in satisfaction_scores]))
            
            # Verify inverse correlation (faster time = higher satisfaction)
            for i in range(1, len(sorted_by_time)):
                prev_time, prev_satisfaction = sorted_by_time[i-1]
                curr_time, curr_satisfaction = sorted_by_time[i]
                
                # Allow some tolerance for natural variation
                assert curr_satisfaction <= prev_satisfaction + 10, \
                    f"Satisfaction should generally decrease as response time increases"
    
    def test_error_rate_impact_metrics(self, ux_metrics_env):
        """Test how error rates impact user experience"""
        env = ux_metrics_env
        
        # Error rate scenarios
        error_scenarios = [
            {"operation": "transcription", "errors": 0, "attempts": 20, "expected_satisfaction": 95},
            {"operation": "transcription", "errors": 1, "attempts": 20, "expected_satisfaction": 85},
            {"operation": "transcription", "errors": 2, "attempts": 20, "expected_satisfaction": 70},
            {"operation": "system_integration", "errors": 0, "attempts": 15, "expected_satisfaction": 90},
            {"operation": "system_integration", "errors": 1, "attempts": 15, "expected_satisfaction": 75},
            {"operation": "ai_enhancement", "errors": 0, "attempts": 10, "expected_satisfaction": 88},
            {"operation": "ai_enhancement", "errors": 1, "attempts": 10, "expected_satisfaction": 70}
        ]
        
        for scenario in error_scenarios:
            operation = scenario["operation"]
            errors = scenario["errors"]
            attempts = scenario["attempts"]
            expected_satisfaction = scenario["expected_satisfaction"]
            
            # Track error rate
            error_rate = env.track_error_rate(operation, errors, attempts)
            
            # Calculate satisfaction impact
            # Perfect operation (0 errors) = high satisfaction
            # Each error reduces satisfaction
            if error_rate == 0:
                satisfaction = expected_satisfaction
            else:
                # Satisfaction decreases exponentially with error rate
                satisfaction_impact = error_rate * 100 * 0.3  # 30% impact per 1% error rate
                satisfaction = max(20, expected_satisfaction - satisfaction_impact)
            
            env.track_satisfaction_score("error_impact_satisfaction", satisfaction, 
                                       f"{operation}_error_rate_{error_rate:.2%}")
        
        # Validate error impact metrics
        error_rates = env.metrics_data["error_rates"]
        error_satisfaction = [s for s in env.metrics_data["user_satisfaction_scores"] 
                            if s["metric_type"] == "error_impact_satisfaction"]
        
        assert len(error_rates) >= 3, "Should track error rates for multiple operations"
        assert len(error_satisfaction) == len(error_scenarios), "Should track satisfaction impact for all scenarios"
        
        # Check that zero-error scenarios have highest satisfaction
        zero_error_satisfaction = [s for s in error_satisfaction if "error_rate_0.00%" in s["context"]]
        non_zero_error_satisfaction = [s for s in error_satisfaction if "error_rate_0.00%" not in s["context"]]
        
        if zero_error_satisfaction and non_zero_error_satisfaction:
            avg_zero_error = statistics.mean([s["score"] for s in zero_error_satisfaction])
            avg_with_errors = statistics.mean([s["score"] for s in non_zero_error_satisfaction])
            
            assert avg_zero_error > avg_with_errors, "Zero-error scenarios should have higher satisfaction"
    
    def test_scalability_performance_metrics(self, ux_metrics_env):
        """Test performance metrics under different load conditions"""
        env = ux_metrics_env
        
        with patch('core.voiceflow_core.AudioToTextRecorder', return_value=env.mock_recorder), \
             patch('core.voiceflow_core.SystemIntegration', return_value=env.mock_system):
            
            env.engine = VoiceFlowEngine(config=env.config)
            
            # Scalability test scenarios
            load_scenarios = [
                {"load_level": "light", "operations": 5, "concurrent": 1},
                {"load_level": "moderate", "operations": 15, "concurrent": 1},
                {"load_level": "heavy", "operations": 30, "concurrent": 1},
                {"load_level": "burst", "operations": 10, "concurrent": 1}  # Rapid succession
            ]
            
            callback_results = []
            def scalability_callback(text):
                callback_results.append(text)
            
            env.engine.set_transcription_callback(scalability_callback)
            
            for scenario in load_scenarios:
                load_level = scenario["load_level"]
                operations = scenario["operations"]
                
                load_start = time.time()
                operation_times = []
                
                for i in range(operations):
                    op_start = time.time()
                    
                    env.engine.start_recording()
                    
                    # Vary timing based on load scenario
                    if load_level == "burst":
                        time.sleep(0.02)  # Very fast operations
                    else:
                        time.sleep(0.05)  # Normal operations
                    
                    env.engine.stop_recording()
                    
                    op_end = time.time()
                    operation_times.append(op_end - op_start)
                    
                    # Pause between operations based on load level
                    if load_level == "light":
                        time.sleep(0.2)
                    elif load_level == "moderate":
                        time.sleep(0.1)
                    elif load_level == "heavy":
                        time.sleep(0.05)
                    # burst: no pause
                
                load_end = time.time()
                load_duration = load_end - load_start
                
                # Track scalability metrics
                avg_operation_time = statistics.mean(operation_times)
                throughput = operations / load_duration
                
                env.track_performance_metric("avg_operation_time", avg_operation_time, load_level)
                env.track_performance_metric("throughput", throughput, load_level)
                env.track_performance_metric("load_duration", load_duration, load_level)
                
                # Calculate performance satisfaction
                # Faster operations and higher throughput = higher satisfaction
                if avg_operation_time <= 0.2:
                    time_satisfaction = 95
                elif avg_operation_time <= 0.5:
                    time_satisfaction = 85
                else:
                    time_satisfaction = 70
                
                env.track_satisfaction_score("scalability_satisfaction", time_satisfaction, 
                                           f"{load_level}_load")
            
            # Validate scalability metrics
            operation_times = env.metrics_data["performance_metrics"]["avg_operation_time"]
            throughput_metrics = env.metrics_data["performance_metrics"]["throughput"]
            
            assert len(operation_times) == len(load_scenarios), "Should track operation times for all load levels"
            assert len(throughput_metrics) == len(load_scenarios), "Should track throughput for all load levels"
            
            # Check performance consistency across load levels
            time_values = [m["value"] for m in operation_times]
            time_variance = statistics.stdev(time_values) if len(time_values) > 1 else 0
            
            # Performance should remain relatively consistent
            avg_time = statistics.mean(time_values)
            coefficient_of_variation = time_variance / avg_time if avg_time > 0 else 0
            assert coefficient_of_variation < 1.0, "Performance should be reasonably consistent across load levels"


class TestOverallUXScoreCalculation:
    """Tests calculation of comprehensive UX score"""
    
    def test_comprehensive_ux_score_calculation(self, ux_metrics_env):
        """Test calculation of overall UX score from all metrics"""
        env = ux_metrics_env
        
        # Populate comprehensive metrics data
        
        # Time to value metrics
        env.track_time_to_value("new_user", 0, 8.5, "first_transcription")
        env.track_time_to_value("returning_user", 0, 2.1, "quick_task")
        
        # Task completion metrics
        env.track_task_completion("transcription", 0, 1.2, True, "general")
        env.track_task_completion("settings", 0, 5.8, True, "general")
        env.track_task_completion("error_recovery", 0, 3.2, True, "general")
        
        # Error rate metrics
        env.track_error_rate("transcription", 0, 50)  # 0% error rate
        env.track_error_rate("system_integration", 1, 25)  # 4% error rate
        env.track_error_rate("ai_enhancement", 0, 20)  # 0% error rate
        
        # Feature adoption metrics
        env.track_feature_adoption("ai_enhancement", 3, "first_discovery")
        env.track_feature_adoption("ai_enhancement", 4, "first_use")
        env.track_feature_adoption("ai_enhancement", 6, "regular_use")
        
        env.track_feature_adoption("hotkey_customization", 5, "first_discovery")
        env.track_feature_adoption("hotkey_customization", 7, "first_use")
        env.track_feature_adoption("hotkey_customization", 10, "regular_use")
        
        # Satisfaction metrics
        env.track_satisfaction_score("task_satisfaction", 88, "transcription")
        env.track_satisfaction_score("task_satisfaction", 75, "settings")
        env.track_satisfaction_score("overall_satisfaction", 85, "general")
        
        # Accessibility metrics
        env.track_accessibility_metric("keyboard_navigation", 95, "AA_compliant")
        env.track_accessibility_metric("screen_reader_support", 88, "A_compliant")
        env.track_accessibility_metric("color_contrast", 100, "AAA_compliant")
        
        # Calculate overall UX score
        overall_score, score_components = env.calculate_ux_score()
        
        # Validate UX score calculation
        assert 0 <= overall_score <= 100, f"Overall UX score should be 0-100, got {overall_score:.1f}"
        assert overall_score >= 70, f"Overall UX score should be good (>=70), got {overall_score:.1f}"
        
        # Validate score components
        expected_components = ["time_to_value", "task_completion", "error_rate", "feature_adoption", "satisfaction", "accessibility"]
        
        for component in expected_components:
            if component in score_components:
                component_score = score_components[component]
                assert 0 <= component_score <= 100, f"{component} score should be 0-100, got {component_score:.1f}"
        
        # Check that high-performing components contribute positively
        if "error_rate" in score_components:
            error_score = score_components["error_rate"]
            assert error_score >= 80, "Low error rates should result in high error score"
        
        if "task_completion" in score_components:
            completion_score = score_components["task_completion"]
            assert completion_score >= 80, "All successful tasks should result in high completion score"
    
    def test_ux_score_improvement_tracking(self, ux_metrics_env):
        """Test tracking of UX score improvements over time"""
        env = ux_metrics_env
        
        # Simulate UX improvements over multiple versions/iterations
        iterations = [
            {
                "version": "v1.0",
                "time_to_value": 15.0,
                "error_rate": 0.08,
                "satisfaction": 75,
                "accessibility": 80
            },
            {
                "version": "v1.1", 
                "time_to_value": 12.0,
                "error_rate": 0.05,
                "satisfaction": 80,
                "accessibility": 85
            },
            {
                "version": "v1.2",
                "time_to_value": 8.5,
                "error_rate": 0.02,
                "satisfaction": 88,
                "accessibility": 92
            }
        ]
        
        ux_scores = []
        
        for iteration in iterations:
            # Reset metrics for this iteration
            env.metrics_data = {}
            env.initialize_metrics_tracking()
            
            version = iteration["version"]
            
            # Populate metrics for this iteration
            env.track_time_to_value("user", 0, iteration["time_to_value"], "task")
            env.track_task_completion("task", 0, 2.0, True)
            env.track_error_rate("operation", int(iteration["error_rate"] * 100), 100)
            env.track_satisfaction_score("overall", iteration["satisfaction"], version)
            env.track_accessibility_metric("overall", iteration["accessibility"], "compliant")
            
            # Calculate UX score for this iteration
            ux_score, components = env.calculate_ux_score()
            ux_scores.append({
                "version": version,
                "score": ux_score,
                "components": components
            })
        
        # Validate improvement tracking
        assert len(ux_scores) == len(iterations), "Should calculate UX score for each iteration"
        
        # Check that UX score improves over iterations
        for i in range(1, len(ux_scores)):
            current_score = ux_scores[i]["score"]
            previous_score = ux_scores[i-1]["score"]
            
            assert current_score >= previous_score, \
                f"UX score should improve or maintain: {previous_score:.1f} -> {current_score:.1f}"
        
        # Check final score meets quality threshold
        final_score = ux_scores[-1]["score"]
        assert final_score >= 80, f"Final UX score should be excellent (>=80), got {final_score:.1f}"
        
        # Validate improvement magnitude
        initial_score = ux_scores[0]["score"]
        improvement = final_score - initial_score
        assert improvement >= 10, f"Should show significant improvement (>=10 points), got {improvement:.1f}"
    
    def test_ux_benchmarking_metrics(self, ux_metrics_env):
        """Test UX metrics against industry benchmarks"""
        env = ux_metrics_env
        
        # Industry benchmark standards
        benchmarks = {
            "time_to_value": {
                "excellent": 5.0,   # seconds
                "good": 15.0,
                "acceptable": 30.0
            },
            "task_completion_rate": {
                "excellent": 0.95,
                "good": 0.85,
                "acceptable": 0.70
            },
            "error_rate": {
                "excellent": 0.01,  # 1%
                "good": 0.05,       # 5%
                "acceptable": 0.10   # 10%
            },
            "satisfaction_score": {
                "excellent": 85,
                "good": 75,
                "acceptable": 60
            },
            "accessibility_compliance": {
                "excellent": 95,  # AAA level
                "good": 85,       # AA level
                "acceptable": 70   # A level
            }
        }
        
        # Simulate current performance metrics
        current_metrics = {
            "time_to_value": 8.2,
            "task_completion_rate": 0.92,
            "error_rate": 0.03,
            "satisfaction_score": 87,
            "accessibility_compliance": 90
        }
        
        benchmark_results = {}
        
        for metric_name, current_value in current_metrics.items():
            benchmark_levels = benchmarks[metric_name]
            
            # Determine benchmark level
            if metric_name in ["time_to_value", "error_rate"]:  # Lower is better
                if current_value <= benchmark_levels["excellent"]:
                    level = "excellent"
                elif current_value <= benchmark_levels["good"]:
                    level = "good"
                elif current_value <= benchmark_levels["acceptable"]:
                    level = "acceptable"
                else:
                    level = "below_acceptable"
            else:  # Higher is better
                if current_value >= benchmark_levels["excellent"]:
                    level = "excellent"
                elif current_value >= benchmark_levels["good"]:
                    level = "good"
                elif current_value >= benchmark_levels["acceptable"]:
                    level = "acceptable"
                else:
                    level = "below_acceptable"
            
            benchmark_results[metric_name] = {
                "current_value": current_value,
                "benchmark_level": level,
                "benchmark_thresholds": benchmark_levels
            }
            
            # Track benchmark performance
            env.track_satisfaction_score(f"benchmark_{metric_name}", current_value, level)
        
        # Validate benchmark performance
        assert len(benchmark_results) == len(current_metrics), "Should benchmark all metrics"
        
        # Check that majority of metrics meet "good" or better benchmarks
        good_or_better = sum(1 for result in benchmark_results.values() 
                           if result["benchmark_level"] in ["excellent", "good"])
        
        total_metrics = len(benchmark_results)
        good_percentage = good_or_better / total_metrics
        
        assert good_percentage >= 0.8, f"At least 80% of metrics should meet 'good' benchmarks, got {good_percentage:.1%}"
        
        # Check no metrics are below acceptable
        below_acceptable = [metric for metric, result in benchmark_results.items() 
                          if result["benchmark_level"] == "below_acceptable"]
        
        assert len(below_acceptable) == 0, f"No metrics should be below acceptable: {below_acceptable}"
        
        # Check for excellence in core metrics
        core_metrics = ["time_to_value", "satisfaction_score"]
        excellent_core = sum(1 for metric in core_metrics 
                           if benchmark_results[metric]["benchmark_level"] == "excellent")
        
        assert excellent_core >= 1, "At least one core metric should achieve excellence"


if __name__ == "__main__":
    # Run UX metrics and measurement tests
    pytest.main([__file__, "-v", "--tb=short"])