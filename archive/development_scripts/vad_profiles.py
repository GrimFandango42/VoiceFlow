#!/usr/bin/env python3
"""
VoiceFlow VAD Profile Optimization System
========================================

Advanced VAD configuration system with user-customizable profiles and 
adaptive optimization for different conversation contexts and speech patterns.

Features:
- Pre-configured VAD profiles (conservative, balanced, aggressive)
- User-customizable pause sensitivity profiles
- Context-specific VAD optimization (coding, writing, chat, presentation)
- Performance monitoring and auto-tuning
- Cross-VAD engine validation
- Real-time adaptation based on speech patterns
"""

import json
import time
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from collections import deque, defaultdict
import threading


class VADProfile(Enum):
    """Pre-defined VAD profiles"""
    CONSERVATIVE = "conservative"     # Maximum speech capture, minimal cutoff
    BALANCED = "balanced"            # Optimized for general use
    AGGRESSIVE = "aggressive"        # Fast response, higher performance
    CUSTOM = "custom"               # User-defined profile


class PerformanceMetric(Enum):
    """VAD performance metrics to track"""
    CUTOFF_RATE = "cutoff_rate"                 # Speech getting cut off
    FALSE_POSITIVE_RATE = "false_positive_rate" # Noise detected as speech
    RESPONSE_TIME = "response_time"             # Time to detect speech start
    CONTINUATION_ACCURACY = "continuation_accuracy" # Proper speech continuation
    USER_SATISFACTION = "user_satisfaction"     # User feedback rating


@dataclass
class VADConfiguration:
    """Complete VAD configuration settings"""
    profile_name: str
    silero_sensitivity: float
    webrtc_sensitivity: int
    post_speech_silence_duration: float
    min_length_of_recording: float
    min_gap_between_recordings: float
    start_threshold: float = 0.3
    end_threshold: float = 0.2
    description: str = ""
    created_date: datetime = None
    last_modified: datetime = None
    performance_score: float = 0.0
    
    def __post_init__(self):
        if self.created_date is None:
            self.created_date = datetime.now()
        if self.last_modified is None:
            self.last_modified = datetime.now()


@dataclass
class PerformanceData:
    """VAD performance tracking data"""
    timestamp: float
    metric: PerformanceMetric
    value: float
    context: str = ""
    session_id: str = ""


class VADProfileManager:
    """Advanced VAD profile management system"""
    
    def __init__(self, user_id: str = "default"):
        self.user_id = user_id
        self.profiles_dir = Path.home() / ".voiceflow" / "vad_profiles"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        
        # Built-in profiles
        self.builtin_profiles = self._create_builtin_profiles()
        
        # User profiles
        self.user_profiles: Dict[str, VADConfiguration] = {}
        self.active_profile = "balanced"
        
        # Performance tracking
        self.performance_data = deque(maxlen=1000)  # Keep last 1000 data points
        self.session_metrics = defaultdict(list)
        
        # Adaptive tuning
        self.auto_tuning_enabled = False
        self.tuning_thread = None
        self.tuning_lock = threading.Lock()
        
        # Load user profiles
        self._load_user_profiles()
        
        print(f"[VAD] Profile manager initialized for user: {user_id}")
    
    def _create_builtin_profiles(self) -> Dict[str, VADConfiguration]:
        """Create built-in VAD profiles"""
        return {
            "conservative": VADConfiguration(
                profile_name="conservative",
                silero_sensitivity=0.2,
                webrtc_sensitivity=1,
                post_speech_silence_duration=2.0,
                min_length_of_recording=0.15,
                min_gap_between_recordings=0.1,
                start_threshold=0.2,
                end_threshold=0.15,
                description="Maximum speech capture with minimal cutoff risk. Best for important dictation."
            ),
            "balanced": VADConfiguration(
                profile_name="balanced",
                silero_sensitivity=0.3,
                webrtc_sensitivity=2,
                post_speech_silence_duration=1.2,
                min_length_of_recording=0.25,
                min_gap_between_recordings=0.2,
                start_threshold=0.3,
                end_threshold=0.2,
                description="Optimized balance between accuracy and responsiveness. Recommended for most users."
            ),
            "aggressive": VADConfiguration(
                profile_name="aggressive",
                silero_sensitivity=0.5,
                webrtc_sensitivity=3,
                post_speech_silence_duration=0.7,
                min_length_of_recording=0.3,
                min_gap_between_recordings=0.3,
                start_threshold=0.4,
                end_threshold=0.3,
                description="Fast response with higher performance. May have occasional cutoffs in noisy environments."
            ),
            "presentation": VADConfiguration(
                profile_name="presentation",
                silero_sensitivity=0.25,
                webrtc_sensitivity=1,
                post_speech_silence_duration=1.8,
                min_length_of_recording=0.2,
                min_gap_between_recordings=0.15,
                start_threshold=0.25,
                end_threshold=0.18,
                description="Optimized for formal speaking with longer natural pauses."
            ),
            "coding": VADConfiguration(
                profile_name="coding",
                silero_sensitivity=0.2,
                webrtc_sensitivity=1,
                post_speech_silence_duration=2.5,
                min_length_of_recording=0.2,
                min_gap_between_recordings=0.1,
                start_threshold=0.2,
                end_threshold=0.15,
                description="Extended pause tolerance for technical dictation and thinking time."
            ),
            "quiet_environment": VADConfiguration(
                profile_name="quiet_environment",
                silero_sensitivity=0.4,
                webrtc_sensitivity=3,
                post_speech_silence_duration=1.0,
                min_length_of_recording=0.2,
                min_gap_between_recordings=0.2,
                start_threshold=0.35,
                end_threshold=0.25,
                description="Optimized for quiet environments with minimal background noise."
            ),
            "noisy_environment": VADConfiguration(
                profile_name="noisy_environment",
                silero_sensitivity=0.15,
                webrtc_sensitivity=1,
                post_speech_silence_duration=1.5,
                min_length_of_recording=0.3,
                min_gap_between_recordings=0.15,
                start_threshold=0.15,
                end_threshold=0.12,
                description="Enhanced noise rejection for challenging audio environments."
            )
        }
    
    def _load_user_profiles(self):
        """Load user-defined profiles from disk"""
        profiles_file = self.profiles_dir / f"{self.user_id}_profiles.json"
        
        try:
            if profiles_file.exists():
                with open(profiles_file, 'r') as f:
                    data = json.load(f)
                
                for profile_name, profile_data in data.items():
                    # Convert datetime strings back to datetime objects
                    if 'created_date' in profile_data:
                        profile_data['created_date'] = datetime.fromisoformat(profile_data['created_date'])
                    if 'last_modified' in profile_data:
                        profile_data['last_modified'] = datetime.fromisoformat(profile_data['last_modified'])
                    
                    self.user_profiles[profile_name] = VADConfiguration(**profile_data)
                
                print(f"[VAD] Loaded {len(self.user_profiles)} user profiles")
        
        except Exception as e:
            print(f"[VAD] Warning: Could not load user profiles: {e}")
    
    def _save_user_profiles(self):
        """Save user-defined profiles to disk"""
        profiles_file = self.profiles_dir / f"{self.user_id}_profiles.json"
        
        try:
            data = {}
            for profile_name, profile in self.user_profiles.items():
                profile_dict = asdict(profile)
                # Convert datetime objects to strings for JSON serialization
                profile_dict['created_date'] = profile.created_date.isoformat()
                profile_dict['last_modified'] = profile.last_modified.isoformat()
                data[profile_name] = profile_dict
            
            with open(profiles_file, 'w') as f:
                json.dump(data, f, indent=2)
        
        except Exception as e:
            print(f"[VAD] Warning: Could not save user profiles: {e}")
    
    def get_profile(self, profile_name: str) -> Optional[VADConfiguration]:
        """Get VAD profile by name"""
        # Check user profiles first
        if profile_name in self.user_profiles:
            return self.user_profiles[profile_name]
        
        # Check built-in profiles
        if profile_name in self.builtin_profiles:
            return self.builtin_profiles[profile_name]
        
        return None
    
    def get_profile_config(self, profile_name: str = None) -> Dict[str, Any]:
        """Get VAD configuration dictionary for specified profile"""
        if profile_name is None:
            profile_name = self.active_profile
        
        profile = self.get_profile(profile_name)
        if not profile:
            print(f"[VAD] Profile '{profile_name}' not found, using balanced")
            profile = self.builtin_profiles["balanced"]
        
        return {
            "silero_sensitivity": profile.silero_sensitivity,
            "webrtc_sensitivity": profile.webrtc_sensitivity,
            "post_speech_silence_duration": profile.post_speech_silence_duration,
            "min_length_of_recording": profile.min_length_of_recording,
            "min_gap_between_recordings": profile.min_gap_between_recordings,
            "start_threshold": profile.start_threshold,
            "end_threshold": profile.end_threshold
        }
    
    def create_custom_profile(self, profile_name: str, base_profile: str = "balanced", 
                            modifications: Dict[str, float] = None) -> bool:
        """Create a custom VAD profile based on existing profile"""
        try:
            # Get base profile
            base = self.get_profile(base_profile)
            if not base:
                print(f"[VAD] Base profile '{base_profile}' not found")
                return False
            
            # Create new profile with modifications
            new_profile = VADConfiguration(
                profile_name=profile_name,
                silero_sensitivity=base.silero_sensitivity,
                webrtc_sensitivity=base.webrtc_sensitivity,
                post_speech_silence_duration=base.post_speech_silence_duration,
                min_length_of_recording=base.min_length_of_recording,
                min_gap_between_recordings=base.min_gap_between_recordings,
                start_threshold=base.start_threshold,
                end_threshold=base.end_threshold,
                description=f"Custom profile based on {base_profile}",
                created_date=datetime.now(),
                last_modified=datetime.now()
            )
            
            # Apply modifications
            if modifications:
                for param, value in modifications.items():
                    if hasattr(new_profile, param):
                        setattr(new_profile, param, value)
                        new_profile.last_modified = datetime.now()
            
            # Validate configuration
            if self._validate_profile(new_profile):
                self.user_profiles[profile_name] = new_profile
                self._save_user_profiles()
                print(f"[VAD] Created custom profile: {profile_name}")
                return True
            else:
                print(f"[VAD] Invalid profile configuration for: {profile_name}")
                return False
        
        except Exception as e:
            print(f"[VAD] Error creating custom profile: {e}")
            return False
    
    def _validate_profile(self, profile: VADConfiguration) -> bool:
        """Validate VAD profile configuration"""
        # Check reasonable value ranges
        checks = [
            (0.01 <= profile.silero_sensitivity <= 1.0, "silero_sensitivity out of range"),
            (1 <= profile.webrtc_sensitivity <= 5, "webrtc_sensitivity out of range"),
            (0.1 <= profile.post_speech_silence_duration <= 10.0, "post_speech_silence_duration out of range"),
            (0.05 <= profile.min_length_of_recording <= 2.0, "min_length_of_recording out of range"),
            (0.05 <= profile.min_gap_between_recordings <= 5.0, "min_gap_between_recordings out of range"),
            (0.01 <= profile.start_threshold <= 1.0, "start_threshold out of range"),
            (0.01 <= profile.end_threshold <= 1.0, "end_threshold out of range")
        ]
        
        for check, error_msg in checks:
            if not check:
                print(f"[VAD] Validation error: {error_msg}")
                return False
        
        return True
    
    def set_active_profile(self, profile_name: str) -> bool:
        """Set the active VAD profile"""
        if self.get_profile(profile_name):
            self.active_profile = profile_name
            print(f"[VAD] Active profile set to: {profile_name}")
            return True
        else:
            print(f"[VAD] Profile '{profile_name}' not found")
            return False
    
    def record_performance_data(self, metric: PerformanceMetric, value: float, 
                              context: str = "", session_id: str = ""):
        """Record VAD performance data point"""
        data_point = PerformanceData(
            timestamp=time.time(),
            metric=metric,
            value=value,
            context=context,
            session_id=session_id
        )
        
        self.performance_data.append(data_point)
        self.session_metrics[metric].append(value)
        
        # Trigger auto-tuning if enabled
        if self.auto_tuning_enabled:
            self._check_auto_tuning()
    
    def get_performance_statistics(self, metric: PerformanceMetric = None, 
                                 hours_back: int = 24) -> Dict[str, Any]:
        """Get performance statistics for specified metric and time period"""
        cutoff_time = time.time() - (hours_back * 3600)
        
        if metric:
            # Filter data for specific metric
            filtered_data = [
                d for d in self.performance_data 
                if d.metric == metric and d.timestamp > cutoff_time
            ]
            values = [d.value for d in filtered_data]
        else:
            # All metrics
            filtered_data = [d for d in self.performance_data if d.timestamp > cutoff_time]
            values = [d.value for d in filtered_data]
        
        if not values:
            return {"status": "no_data"}
        
        return {
            "metric": metric.value if metric else "all",
            "data_points": len(values),
            "average": statistics.mean(values),
            "median": statistics.median(values),
            "min": min(values),
            "max": max(values),
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0,
            "time_period_hours": hours_back
        }
    
    def analyze_profile_performance(self, profile_name: str = None) -> Dict[str, Any]:
        """Analyze performance of specified profile"""
        if profile_name is None:
            profile_name = self.active_profile
        
        profile = self.get_profile(profile_name)
        if not profile:
            return {"error": f"Profile '{profile_name}' not found"}
        
        # Get recent performance data
        recent_stats = {}
        for metric in PerformanceMetric:
            stats = self.get_performance_statistics(metric, hours_back=24)
            if stats.get("status") != "no_data":
                recent_stats[metric.value] = stats
        
        # Calculate overall performance score
        performance_score = self._calculate_performance_score(recent_stats)
        
        # Update profile performance score
        profile.performance_score = performance_score
        profile.last_modified = datetime.now()
        
        if profile_name in self.user_profiles:
            self._save_user_profiles()
        
        return {
            "profile_name": profile_name,
            "performance_score": performance_score,
            "recent_statistics": recent_stats,
            "recommendations": self._generate_recommendations(profile, recent_stats)
        }
    
    def _calculate_performance_score(self, stats: Dict[str, Any]) -> float:
        """Calculate overall performance score from metrics"""
        if not stats:
            return 0.5  # Neutral score with no data
        
        score = 0.0
        weight_sum = 0.0
        
        # Define metric weights and ideal values
        metric_weights = {
            "cutoff_rate": (0.3, 0.0),           # Weight 0.3, ideal value 0.0
            "false_positive_rate": (0.2, 0.0),   # Weight 0.2, ideal value 0.0
            "response_time": (0.2, 0.5),         # Weight 0.2, ideal value 0.5s
            "continuation_accuracy": (0.2, 1.0), # Weight 0.2, ideal value 1.0
            "user_satisfaction": (0.1, 1.0)      # Weight 0.1, ideal value 1.0
        }
        
        for metric_name, (weight, ideal_value) in metric_weights.items():
            if metric_name in stats:
                metric_stats = stats[metric_name]
                actual_value = metric_stats.get("average", 0.5)
                
                # Calculate normalized score (closer to ideal = higher score)
                if ideal_value == 0.0:
                    # Lower is better (cutoffs, false positives)
                    metric_score = max(0.0, 1.0 - actual_value)
                elif ideal_value == 1.0:
                    # Higher is better (accuracy, satisfaction)
                    metric_score = actual_value
                else:
                    # Optimal range (response time)
                    deviation = abs(actual_value - ideal_value)
                    metric_score = max(0.0, 1.0 - deviation)
                
                score += weight * metric_score
                weight_sum += weight
        
        # Normalize score
        return score / weight_sum if weight_sum > 0 else 0.5
    
    def _generate_recommendations(self, profile: VADConfiguration, 
                                stats: Dict[str, Any]) -> List[str]:
        """Generate optimization recommendations based on performance"""
        recommendations = []
        
        # Check cutoff rate
        if "cutoff_rate" in stats:
            cutoff_rate = stats["cutoff_rate"].get("average", 0)
            if cutoff_rate > 0.1:  # More than 10% cutoff rate
                recommendations.append(
                    f"High cutoff rate ({cutoff_rate:.1%}). Consider increasing "
                    f"post_speech_silence_duration from {profile.post_speech_silence_duration:.1f}s"
                )
        
        # Check false positive rate
        if "false_positive_rate" in stats:
            fp_rate = stats["false_positive_rate"].get("average", 0)
            if fp_rate > 0.15:  # More than 15% false positive rate
                recommendations.append(
                    f"High false positive rate ({fp_rate:.1%}). Consider decreasing "
                    f"silero_sensitivity from {profile.silero_sensitivity:.2f}"
                )
        
        # Check response time
        if "response_time" in stats:
            response_time = stats["response_time"].get("average", 0)
            if response_time > 1.0:  # Slower than 1 second
                recommendations.append(
                    f"Slow response time ({response_time:.1f}s). Consider decreasing "
                    f"min_length_of_recording from {profile.min_length_of_recording:.2f}s"
                )
        
        # General recommendations based on profile type
        if not recommendations:
            recommendations.append("Profile performance is good. No immediate changes needed.")
        
        return recommendations
    
    def enable_auto_tuning(self, min_data_points: int = 50):
        """Enable automatic profile tuning based on performance data"""
        self.auto_tuning_enabled = True
        self.min_data_points = min_data_points
        print("[VAD] Auto-tuning enabled")
    
    def disable_auto_tuning(self):
        """Disable automatic profile tuning"""
        self.auto_tuning_enabled = False
        if self.tuning_thread:
            self.tuning_thread.cancel()
        print("[VAD] Auto-tuning disabled")
    
    def _check_auto_tuning(self):
        """Check if auto-tuning should be triggered"""
        if not self.auto_tuning_enabled:
            return
        
        # Only tune if we have enough data
        if len(self.performance_data) < self.min_data_points:
            return
        
        # Schedule tuning (debounced)
        if self.tuning_thread:
            self.tuning_thread.cancel()
        
        self.tuning_thread = threading.Timer(30.0, self._perform_auto_tuning)
        self.tuning_thread.daemon = True
        self.tuning_thread.start()
    
    def _perform_auto_tuning(self):
        """Perform automatic profile tuning"""
        with self.tuning_lock:
            try:
                current_profile = self.get_profile(self.active_profile)
                if not current_profile or current_profile.profile_name in self.builtin_profiles:
                    return  # Don't auto-tune built-in profiles
                
                # Analyze current performance
                analysis = self.analyze_profile_performance(self.active_profile)
                performance_score = analysis.get("performance_score", 0.5)
                
                # Only tune if performance is below threshold
                if performance_score < 0.7:
                    print(f"[VAD] Auto-tuning triggered (score: {performance_score:.2f})")
                    
                    # Generate optimized profile
                    optimized_profile = self._optimize_profile(current_profile, analysis)
                    
                    if optimized_profile:
                        # Create new auto-tuned profile
                        tuned_name = f"{self.active_profile}_autotuned_{int(time.time())}"
                        self.user_profiles[tuned_name] = optimized_profile
                        self._save_user_profiles()
                        
                        print(f"[VAD] Created auto-tuned profile: {tuned_name}")
                        print(f"[VAD] To use: voiceflow.set_vad_profile('{tuned_name}')")
            
            except Exception as e:
                print(f"[VAD] Auto-tuning error: {e}")
    
    def _optimize_profile(self, profile: VADConfiguration, 
                         analysis: Dict[str, Any]) -> Optional[VADConfiguration]:
        """Generate optimized profile based on performance analysis"""
        try:
            # Start with current profile
            optimized = VADConfiguration(
                profile_name=f"{profile.profile_name}_optimized",
                silero_sensitivity=profile.silero_sensitivity,
                webrtc_sensitivity=profile.webrtc_sensitivity,
                post_speech_silence_duration=profile.post_speech_silence_duration,
                min_length_of_recording=profile.min_length_of_recording,
                min_gap_between_recordings=profile.min_gap_between_recordings,
                start_threshold=profile.start_threshold,
                end_threshold=profile.end_threshold,
                description=f"Auto-optimized from {profile.profile_name}",
                created_date=datetime.now(),
                last_modified=datetime.now()
            )
            
            stats = analysis.get("recent_statistics", {})
            
            # Optimize based on performance metrics
            if "cutoff_rate" in stats:
                cutoff_rate = stats["cutoff_rate"].get("average", 0)
                if cutoff_rate > 0.1:
                    # Increase silence duration to reduce cutoffs
                    optimized.post_speech_silence_duration *= 1.3
                    optimized.end_threshold *= 0.8
            
            if "false_positive_rate" in stats:
                fp_rate = stats["false_positive_rate"].get("average", 0)
                if fp_rate > 0.15:
                    # Decrease sensitivity to reduce false positives
                    optimized.silero_sensitivity *= 0.85
                    optimized.start_threshold *= 1.1
            
            if "response_time" in stats:
                response_time = stats["response_time"].get("average", 0)
                if response_time > 1.0:
                    # Decrease recording length for faster response
                    optimized.min_length_of_recording *= 0.9
            
            # Validate optimized profile
            if self._validate_profile(optimized):
                return optimized
            else:
                return None
        
        except Exception as e:
            print(f"[VAD] Profile optimization error: {e}")
            return None
    
    def list_profiles(self) -> Dict[str, Any]:
        """List all available VAD profiles"""
        profiles = {}
        
        # Built-in profiles
        for name, profile in self.builtin_profiles.items():
            profiles[name] = {
                "type": "built-in",
                "description": profile.description,
                "performance_score": profile.performance_score,
                "is_active": name == self.active_profile
            }
        
        # User profiles
        for name, profile in self.user_profiles.items():
            profiles[name] = {
                "type": "user",
                "description": profile.description,
                "performance_score": profile.performance_score,
                "created": profile.created_date.strftime("%Y-%m-%d"),
                "is_active": name == self.active_profile
            }
        
        return {
            "active_profile": self.active_profile,
            "auto_tuning_enabled": self.auto_tuning_enabled,
            "profiles": profiles
        }
    
    def delete_user_profile(self, profile_name: str) -> bool:
        """Delete a user-defined profile"""
        if profile_name in self.user_profiles:
            del self.user_profiles[profile_name]
            self._save_user_profiles()
            
            # Switch to balanced if deleted profile was active
            if self.active_profile == profile_name:
                self.active_profile = "balanced"
                print(f"[VAD] Switched to balanced profile after deleting {profile_name}")
            
            print(f"[VAD] Deleted user profile: {profile_name}")
            return True
        else:
            print(f"[VAD] Profile '{profile_name}' not found or is built-in")
            return False
    
    def export_profile(self, profile_name: str, file_path: str) -> bool:
        """Export profile configuration to file"""
        try:
            profile = self.get_profile(profile_name)
            if not profile:
                print(f"[VAD] Profile '{profile_name}' not found")
                return False
            
            export_data = {
                "profile": asdict(profile),
                "exported_by": self.user_id,
                "export_date": datetime.now().isoformat(),
                "voiceflow_version": "2.0"
            }
            
            # Convert datetime objects to strings
            export_data["profile"]["created_date"] = profile.created_date.isoformat()
            export_data["profile"]["last_modified"] = profile.last_modified.isoformat()
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"[VAD] Exported profile '{profile_name}' to {file_path}")
            return True
        
        except Exception as e:
            print(f"[VAD] Export error: {e}")
            return False
    
    def import_profile(self, file_path: str, new_name: str = None) -> bool:
        """Import profile configuration from file"""
        try:
            with open(file_path, 'r') as f:
                import_data = json.load(f)
            
            profile_data = import_data.get("profile", {})
            
            # Convert datetime strings back to datetime objects
            if 'created_date' in profile_data:
                profile_data['created_date'] = datetime.fromisoformat(profile_data['created_date'])
            if 'last_modified' in profile_data:
                profile_data['last_modified'] = datetime.fromisoformat(profile_data['last_modified'])
            
            # Use new name if provided
            if new_name:
                profile_data['profile_name'] = new_name
            
            profile = VADConfiguration(**profile_data)
            
            if self._validate_profile(profile):
                self.user_profiles[profile.profile_name] = profile
                self._save_user_profiles()
                print(f"[VAD] Imported profile: {profile.profile_name}")
                return True
            else:
                print(f"[VAD] Invalid profile configuration in import file")
                return False
        
        except Exception as e:
            print(f"[VAD] Import error: {e}")
            return False


# Factory function for easy integration
def create_vad_profile_manager(user_id: str = "default") -> VADProfileManager:
    """Create configured VAD profile manager"""
    return VADProfileManager(user_id)