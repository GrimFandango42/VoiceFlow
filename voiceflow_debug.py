#!/usr/bin/env python3
"""
VoiceFlow Debug - Development Version
Enhanced logging and debugging features for development and troubleshooting.
"""

import sys
import logging
from voiceflow.app import VoiceFlowApp
from voiceflow.core.config import VoiceFlowConfig


def setup_debug_logging():
    """Setup comprehensive debug logging."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('voiceflow_debug.log')
        ]
    )


def main():
    """Main entry point for VoiceFlow debug version."""
    print("🔧 VoiceFlow Debug v2.0.0 - Development & Troubleshooting")
    print("=" * 60)
    
    # Setup debug logging
    setup_debug_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Create debug configuration (kwargs for test assertions)
        config = VoiceFlowConfig(
            model_name="base.en",
            compute_type="int8",
            device="cpu",
            enable_realtime_transcription=True,
            spinner=True,
        )
        config.validate()  # Validate configuration

        logger.info("Starting VoiceFlow in debug mode")
        logger.debug(f"Configuration: {config}")
        
        # Create and run application
        app = VoiceFlowApp(
            config=config,
            audio_recorder_type=config.audio_recorder_type,
            transcription_engine_type=config.transcription_engine_type
        )
        
        app.start()
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        print("\n👋 Debug session ended")
    except Exception as e:
        logger.exception("Application error occurred")
        print(f"❌ Error: {e}")
        print("🔍 Check voiceflow_debug.log for detailed information")
        sys.exit(1)


if __name__ == "__main__":
    main()
