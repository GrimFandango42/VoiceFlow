#!/usr/bin/env python3
"""
VoiceFlow - Unified AI Voice Transcription Tool

A fast, accurate, and privacy-focused speech-to-text application with local processing.
Supports both full-featured mode and lightweight mode via command-line flags.

Usage:
    python voiceflow.py                    # Full VoiceFlow
    python voiceflow.py --lite            # VoiceFlow Lite
    python voiceflow.py --model=base.en   # Custom model
    python voiceflow.py --profile=speed   # Speed profile
"""

import sys
import logging
import argparse
import os
from typing import Dict, Any

# Configuration profiles
PROFILES = {
    "speed": {
        "model_name": "base.en",
        "device": "cuda",
        "beam_size": 1,
        "temperature": 0.0,
        "enable_batching": True,
        "max_batch_size": 32,
    },
    "accuracy": {
        "model_name": "large-v3-turbo", 
        "device": "cuda",
        "beam_size": 5,
        "temperature": 0.2,
        "enable_batching": True,
        "max_batch_size": 8,
    },
    "balanced": {
        "model_name": "large-v3-turbo",
        "device": "cuda", 
        "beam_size": 1,
        "temperature": 0.0,
        "enable_batching": True,
        "max_batch_size": 16,
    }
}

DEFAULT_CONFIG = {
    "model_name": "large-v3-turbo",
    "device": "cuda",
    "compute_type": "float16",
    "enable_tray": True,
    "enable_streaming": True,
    "enable_batching": True,
    "beam_size": 1,
    "temperature": 0.0,
}

LITE_CONFIG = {
    "model_name": "base.en",
    "device": "cpu",
    "compute_type": "int8", 
    "enable_tray": False,
    "enable_streaming": False,
    "enable_batching": False,
    "beam_size": 1,
    "temperature": 0.0,
}


def create_config(args) -> Dict[str, Any]:
    """Create configuration based on command-line arguments."""
    # Start with base config
    if args.lite:
        config = LITE_CONFIG.copy()
        mode = "Lite"
    else:
        config = DEFAULT_CONFIG.copy()
        mode = "Full"
    
    # Apply profile if specified
    if args.profile:
        if args.profile in PROFILES:
            config.update(PROFILES[args.profile])
            mode += f" ({args.profile.title()})"
        else:
            print(f"Warning: Unknown profile '{args.profile}'. Using default.")
    
    # Apply individual overrides
    if args.model:
        config["model_name"] = args.model
    if args.device:
        config["device"] = args.device
    if args.no_tray:
        config["enable_tray"] = False
        
    print(f"VoiceFlow {mode} Mode - Model: {config['model_name']} - Device: {config['device']}")
    return config


def main():
    """Main entry point for unified VoiceFlow application."""
    parser = argparse.ArgumentParser(
        description="VoiceFlow - AI Voice Transcription Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Full VoiceFlow
  %(prog)s --lite                       # VoiceFlow Lite  
  %(prog)s --model=tiny.en --device=cpu # Ultra-light mode
  %(prog)s --profile=speed              # Speed-optimized
  %(prog)s --profile=accuracy           # Accuracy-optimized
        """
    )
    
    # Mode selection
    parser.add_argument('--lite', action='store_true',
                       help='Enable lite mode (minimal features, CPU-optimized)')
    
    # Model and device options
    parser.add_argument('--model', type=str,
                       help='Whisper model (tiny.en, base.en, small.en, medium.en, large-v3-turbo)')
    parser.add_argument('--device', type=str, choices=['auto', 'cpu', 'cuda'],
                       help='Processing device (auto=detect, cpu, cuda)')
    
    # Profile presets
    parser.add_argument('--profile', type=str, choices=list(PROFILES.keys()),
                       help='Preset configuration profile')
    
    # UI options
    parser.add_argument('--no-tray', action='store_true',
                       help='Disable system tray (command-line only)')
    parser.add_argument('--tray', action='store_true',
                       help='Start in system tray mode')
    
    # Configuration
    parser.add_argument('--config', type=str,
                       help='Path to custom configuration file')
    parser.add_argument('--hotkey', type=str, default='ctrl+shift+space',
                       help='Custom hotkey combination (default: ctrl+shift+space)')
    
    # Audio processing
    parser.add_argument('--audio-input', type=str,
                       help='Process audio file and exit')
    
    # Utility
    parser.add_argument('--version', action='version', version='VoiceFlow 2.0.0')
    
    args = parser.parse_args()
    
    # Create configuration
    config = create_config(args)
    
    # Setup logging
    log_level = logging.INFO if args.lite else logging.DEBUG
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("VoiceFlow v2.0.0 - AI Voice Transcription")
    print("Optimized for speed and accuracy with local processing")
    print("=" * 60)
    
    try:
        # Import and run based on mode
        if args.audio_input:
            # Process single audio file
            if not os.path.exists(args.audio_input):
                print(f"Error: Audio file not found: {args.audio_input}")
                sys.exit(1)
            
            # Use lite mode for file processing
            from voiceflow.core.file_processor import process_audio_file
            result = process_audio_file(args.audio_input, config)
            print(f"Transcription: {result}")
            
        elif args.tray:
            # Start in tray mode
            import sys
            import os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
            from voiceflow.ui.enhanced_tray import EnhancedTrayController
            from voiceflow.ui.cli_enhanced import EnhancedApp
            from voiceflow.core.config import Config

            print("Starting VoiceFlow Enhanced Tray Mode...")
            config_obj = Config()
            app = EnhancedApp(config_obj)
            tray = EnhancedTrayController(app)
            tray.start()
            tray.run_forever()
            
        else:
            # Start main application
            if config.get("enable_tray", True) and not args.no_tray:
                # Use tray mode
                import sys
                import os
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
                from voiceflow.ui.enhanced_tray import EnhancedTrayController
                from voiceflow.ui.cli_enhanced import EnhancedApp
                from voiceflow.core.config import Config

                print("Starting VoiceFlow Enhanced Tray Mode...")
                config_obj = Config()
                app = EnhancedApp(config_obj)
                tray = EnhancedTrayController(app)
                tray.start()
                tray.run_forever()
            else:
                # Use enhanced VoiceFlow core for better performance
                import sys
                import os
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

                if args.lite:
                    print("Starting VoiceFlow Lite (Enhanced VoiceFlow core)...")
                    from voiceflow.ui.cli_enhanced import main as enhanced_main
                    enhanced_main()
                else:
                    print("🚀 Starting VoiceFlow ULTRA PERFORMANCE (Phase 2 Optimizations + Fixed Visual Indicators)...")
                    try:
                        from voiceflow.ui.cli_ultra_performance import main as ultra_main
                        ultra_main()
                    except ImportError:
                        print("⚡ Fallback to Enhanced VoiceFlow core...")
                        from voiceflow.ui.cli_enhanced import main as enhanced_main
                        enhanced_main()
                    
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except ImportError as e:
        print(f"Missing dependencies: {e}")
        print(f"\nInstall dependencies:")
        if args.lite:
            print("pip install -r requirements-localflow.txt")
        else:
            print("pip install -r requirements_windows.txt")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()