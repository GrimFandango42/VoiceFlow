"""
Configuration Management

Consolidated configuration handling for VoiceFlow.
Supports environment variables, config files, and runtime overrides.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional


class VoiceFlowConfig:
    """
    Centralized configuration management for VoiceFlow.
    
    Priority order:
    1. Runtime overrides
    2. Environment variables  
    3. Config file (.voiceflow/config.json)
    4. Default values
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration manager."""
        self.config_dir = Path.home() / ".voiceflow"
        self.config_dir.mkdir(exist_ok=True)
        
        self.config_file = config_path or (self.config_dir / "config.json")
        self._config = {}
        self._load_defaults()
        self._load_config_file()
        self._load_environment_variables()
    
    def _load_defaults(self):
        """Load default configuration values."""
        self._config = {
            # Audio Configuration - UPDATED with cutoff fix
            'audio': {
                'model': 'base',
                'device': 'auto',
                'language': 'en',
                
                # FIXED: VAD parameters to prevent audio tail-end cutoff
                'post_speech_silence_duration': 1.3,  # Increased from 0.8 to capture speech tails
                'min_length_of_recording': 0.15,      # Optimized for responsiveness
                'silero_sensitivity': 0.3,            # Reduced from 0.4 for less aggressive detection
                'webrtc_sensitivity': 2,              # Reduced from 3 for better tail capture
                'min_gap_between_recordings': 0.25,   # Optimized gap between recordings
                
                # VAD Profile Configuration
                'vad_profile': 'balanced',             # Default to balanced (cutoff fix applied)
                'enable_vad_debugging': False,         # Enable VAD debugging output
                'adaptive_vad': False,                 # Enable adaptive VAD adjustments
            },
            
            # AI Enhancement
            'ai': {
                'enabled': True,
                'model': 'llama3.3:latest',
                'temperature': 0.3,
                'timeout': 10,
                'ollama_host': 'localhost',
                'ollama_port': '11434',
                'ollama_use_https': False
            },
            
            # Text Injection
            'text_injection': {
                'enabled': True,
                'method': 'pyautogui',
                'require_confirmation': False,
                'enable_failsafe': True
            },
            
            # Hotkeys
            'hotkeys': {
                'record_and_inject': 'ctrl+alt',
                'record_only': 'ctrl+shift+alt',
                'stop_recording': 'esc'
            },
            
            # Database
            'database': {
                'path': str(self.config_dir / "transcriptions.db"),
                'encrypt': False,
                'retention_days': 30
            },
            
            # Security
            'security': {
                'log_transcriptions': False,
                'enable_debug_logging': False,
                'max_audio_duration': 30,
                'max_audio_file_size': 10485760  # 10MB
            },
            
            # Performance
            'performance': {
                'use_gpu': True,
                'max_concurrent_requests': 5,
                'enable_caching': True
            }
        }
    
    def _load_config_file(self):
        """Load configuration from JSON file if it exists."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                self._merge_config(file_config)
                print(f"[CONFIG] Loaded from {self.config_file}")
            except Exception as e:
                print(f"[CONFIG] Failed to load {self.config_file}: {e}")
    
    def _load_environment_variables(self):
        """Load configuration from environment variables."""
        env_mappings = {
            # Audio
            'VOICEFLOW_MODEL': ('audio', 'model'),
            'VOICEFLOW_DEVICE': ('audio', 'device'),
            'VOICEFLOW_LANGUAGE': ('audio', 'language'),
            
            # VAD Configuration - NEW environment variables for cutoff fix
            'VOICEFLOW_VAD_PROFILE': ('audio', 'vad_profile'),
            'VOICEFLOW_POST_SPEECH_SILENCE': ('audio', 'post_speech_silence_duration', float),
            'VOICEFLOW_SILERO_SENSITIVITY': ('audio', 'silero_sensitivity', float),
            'VOICEFLOW_WEBRTC_SENSITIVITY': ('audio', 'webrtc_sensitivity', int),
            'VOICEFLOW_MIN_RECORDING_LENGTH': ('audio', 'min_length_of_recording', float),
            'VOICEFLOW_MIN_GAP_RECORDINGS': ('audio', 'min_gap_between_recordings', float),
            'VOICEFLOW_ENABLE_VAD_DEBUG': ('audio', 'enable_vad_debugging', bool),
            'VOICEFLOW_ADAPTIVE_VAD': ('audio', 'adaptive_vad', bool),
            
            # AI
            'ENABLE_AI_ENHANCEMENT': ('ai', 'enabled', bool),
            'AI_MODEL': ('ai', 'model'),
            'AI_TEMPERATURE': ('ai', 'temperature', float),
            'AI_TIMEOUT': ('ai', 'timeout', int),
            'OLLAMA_HOST': ('ai', 'ollama_host'),
            'OLLAMA_PORT': ('ai', 'ollama_port'),
            'OLLAMA_USE_HTTPS': ('ai', 'ollama_use_https', bool),
            
            # Text Injection
            'ENABLE_TEXT_INJECTION': ('text_injection', 'enabled', bool),
            'REQUIRE_USER_CONFIRMATION': ('text_injection', 'require_confirmation', bool),
            'ENABLE_FAILSAFE': ('text_injection', 'enable_failsafe', bool),
            
            # Security
            'LOG_LEVEL': ('security', 'log_level'),
            'ENABLE_DEBUG_LOGGING': ('security', 'enable_debug_logging', bool),
            'MAX_AUDIO_DURATION': ('security', 'max_audio_duration', int),
            'MAX_AUDIO_FILE_SIZE': ('security', 'max_audio_file_size', int),
            
            # Performance
            'USE_GPU': ('performance', 'use_gpu', bool),
        }
        
        for env_var, config_path in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                section = config_path[0]
                key = config_path[1]
                value_type = config_path[2] if len(config_path) > 2 else str
                
                # Convert value to appropriate type
                try:
                    if value_type == bool:
                        value = env_value.lower() in ('true', '1', 'yes', 'on')
                    elif value_type == int:
                        value = int(env_value)
                    elif value_type == float:
                        value = float(env_value)
                    else:
                        value = env_value
                    
                    self._config[section][key] = value
                except (ValueError, TypeError) as e:
                    print(f"[CONFIG] Invalid value for {env_var}: {env_value} ({e})")
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """Merge new configuration with existing config."""
        for section, values in new_config.items():
            if section in self._config and isinstance(values, dict):
                self._config[section].update(values)
            else:
                self._config[section] = values
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self._config.get(section, {}).get(key, default)
    
    def set(self, section: str, key: str, value: Any):
        """Set configuration value at runtime."""
        if section not in self._config:
            self._config[section] = {}
        self._config[section][key] = value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section."""
        return self._config.get(section, {}).copy()
    
    def save(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self._config, f, indent=2)
            print(f"[CONFIG] Saved to {self.config_file}")
        except Exception as e:
            print(f"[CONFIG] Failed to save: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Get complete configuration as dictionary."""
        import copy
        return copy.deepcopy(self._config)
    
    def create_example_config(self):
        """Create example configuration file."""
        example_file = self.config_dir / "config.example.json"
        try:
            with open(example_file, 'w') as f:
                json.dump(self._config, f, indent=2)
            print(f"[CONFIG] Example config created: {example_file}")
        except Exception as e:
            print(f"[CONFIG] Failed to create example: {e}")


# Global configuration instance
_global_config = None


def get_config() -> VoiceFlowConfig:
    """Get global configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = VoiceFlowConfig()
    return _global_config


def load_config(config_path: Optional[Path] = None) -> VoiceFlowConfig:
    """Load configuration from specific path."""
    global _global_config
    _global_config = VoiceFlowConfig(config_path)
    return _global_config


def get_audio_config() -> Dict[str, Any]:
    """Get audio configuration section."""
    return get_config().get_section('audio')


def get_ai_config() -> Dict[str, Any]:
    """Get AI configuration section."""
    return get_config().get_section('ai')


def get_security_config() -> Dict[str, Any]:
    """Get security configuration section."""
    return get_config().get_section('security')


def get_vad_config() -> Dict[str, Any]:
    """Get VAD configuration section with cutoff fix applied."""
    return get_config().get_section('audio')


def set_vad_profile(profile: str) -> bool:
    """
    Set VAD profile in configuration.
    
    Args:
        profile: VAD profile ('conservative', 'balanced', 'aggressive')
        
    Returns:
        True if profile is valid and set, False otherwise
    """
    if profile not in ['conservative', 'balanced', 'aggressive']:
        return False
    
    config = get_config()
    config.set('audio', 'vad_profile', profile)
    return True


def get_vad_profile_settings(profile: str) -> Optional[Dict[str, Any]]:
    """
    Get VAD settings for a specific profile.
    
    Args:
        profile: VAD profile name
        
    Returns:
        Dictionary of VAD settings or None if invalid profile
    """
    profiles = {
        'conservative': {
            'description': 'Maximum speech capture, minimal cutoff risk',
            'silero_sensitivity': 0.2,
            'webrtc_sensitivity': 1,
            'post_speech_silence_duration': 1.8,
            'min_length_of_recording': 0.1,
            'min_gap_between_recordings': 0.1,
        },
        'balanced': {
            'description': 'Optimized for general use (fixes cutoff issue)',
            'silero_sensitivity': 0.3,
            'webrtc_sensitivity': 2,
            'post_speech_silence_duration': 1.3,
            'min_length_of_recording': 0.15,
            'min_gap_between_recordings': 0.25,
        },
        'aggressive': {
            'description': 'Fast response, higher performance',
            'silero_sensitivity': 0.5,
            'webrtc_sensitivity': 4,
            'post_speech_silence_duration': 0.6,
            'min_length_of_recording': 0.3,
            'min_gap_between_recordings': 0.4,
        }
    }
    
    return profiles.get(profile)