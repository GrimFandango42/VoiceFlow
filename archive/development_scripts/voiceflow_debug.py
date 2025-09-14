#!/usr/bin/env python3
"""
VoiceFlow Debug - Development Version
Enhanced logging and debugging features for development and troubleshooting.
"""

import sys
import logging
from voiceflow.app import VoiceFlowApp
from voiceflow.core.config import VoiceFlowConfig
try:
    from voiceflow.voiceflow_core import create_engine  # compat for tests
except Exception:  # pragma: no cover
    def create_engine(config=None):  # type: ignore
        class _E:
            def __init__(self, config=None):
                self.config = config or {}
            def start(self):
                pass
        return _E(config)


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
        # Compose debug engine config for tests
        dbg_cfg = {
            "model": "base.en",
            "device": "cpu",
            "enable_realtime_transcription": True,
        }
        engine = create_engine(config=dbg_cfg)
        logger.info("Starting VoiceFlow in debug mode")
        app = VoiceFlowApp(engine=engine)
        engine.start()
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
