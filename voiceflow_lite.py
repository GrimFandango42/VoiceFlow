#!/usr/bin/env python3
"""
VoiceFlow Lite - Lightweight Version
Minimal dependencies version for systems with limited resources.
"""

import sys
import logging
from voiceflow.app import VoiceFlowApp
from voiceflow.core.config import VoiceFlowConfig


def main():
    """Main entry point for VoiceFlow lite version."""
    print("VoiceFlow Lite v2.0.0 - Lightweight Transcription")
    print("=" * 60)
    
    # Setup minimal logging
    logging.basicConfig(
        level=logging.ERROR,  # Minimal logging
        format='%(levelname)s: %(message)s'
    )
    
    try:
        # Create lightweight configuration (construct with kwargs so tests can assert)
        config = VoiceFlowConfig(
            model_name="tiny.en",
            compute_type="int8",
            device="cpu",
            enable_realtime_transcription=False,
            spinner=False,
        )
        config.validate()  # Validate configuration
        
        # Create and run application with minimal dependencies
        app = VoiceFlowApp(
            config=config,
            audio_recorder_type=config.audio_recorder_type,
            transcription_engine_type=config.transcription_engine_type
        )
        
        app.start()
        
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"Error: {e}")
        print("\nInstall lite dependencies: pip install -r requirements_light.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()
