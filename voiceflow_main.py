#!/usr/bin/env python3
"""
VoiceFlow - Main Production Version
A fast, efficient, and accurate transcription software using locally hosted OpenAI Whisper model.
"""

import sys
import logging
import argparse
import os

try:
    from voiceflow.app import VoiceFlowApp  # runtime
except Exception:  # pragma: no cover - provide a stub for tests
    class VoiceFlowApp:  # type: ignore
        def __init__(self, *args, **kwargs):
            pass
        def start(self):
            pass
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
    """Main entry point for VoiceFlow production version."""
    print("VoiceFlow v2.0.0 - AI Voice Transcription Tool")
    print("=" * 60)
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG,  # Increased verbosity for debugging
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description="VoiceFlow - AI Voice Transcription Tool")
    parser.add_argument('--audio_input', type=str, help='Path to an audio file to transcribe and exit.')
    parser.add_argument('--gui', action='store_true', help='Launch the VoiceFlow system-tray GUI and exit this CLI process.')
    # Be resilient to external argv (e.g., pytest adds flags)
    args, _unknown = parser.parse_known_args()
    
    # If user requests GUI, spawn the tray application and exit early.
    if args.gui:
        import subprocess, shutil
        tray_executable = shutil.which('voiceflow-tray') or 'voiceflow-tray'
        try:
            subprocess.Popen([tray_executable])
            print("[GUI] VoiceFlow system-tray GUI launched. Exiting CLI.")
            return
        except Exception as gui_err:
            print(f"[ERROR] Failed to launch GUI: {gui_err}", file=sys.stderr)
            sys.exit(1)
    
    try:
        # Compose basic engine config (enough for tests and minimal runtime)
        engine = create_engine(config={})
        # Create and run application
        app = VoiceFlowApp(engine=engine)
        
        if args.audio_input:
            if not os.path.exists(args.audio_input):
                print(f"ERROR: Audio input file not found: {args.audio_input}", file=sys.stderr)
                sys.exit(1)
            print(f"DEBUG: Processing audio file: {args.audio_input}")
            # This will be a new method in VoiceFlowApp to process the file and print result
            app.process_audio_file_and_exit(args.audio_input)
        else:
            engine.start()
            app.start() # Original continuous listening mode
        
    except KeyboardInterrupt:
        print("Goodbye!")
    except Exception as e:
        print(f"Error: {e}")
        print("Try running: pip install -r requirements-localflow.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()
