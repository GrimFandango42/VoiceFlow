#!/usr/bin/env python3
"""
VoiceFlow Lite - Lightweight Version
Minimal dependencies version for systems with limited resources.
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
        # Compose config dict for engine (compat for tests)
        lite_cfg = {
            "model": "tiny.en",
            "device": "cpu",
            "enable_realtime_transcription": False,
        }
        engine = create_engine(config=lite_cfg)
        app = VoiceFlowApp(engine=engine)
        
        engine.start()
        app.start()
        
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"Error: {e}")
        print("\nInstall lite dependencies: pip install -r requirements_light.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()
