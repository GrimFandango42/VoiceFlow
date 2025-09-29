#!/usr/bin/env python3
"""
Force cleanup stuck VoiceFlow visual indicators and reset system state
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

def force_cleanup():
    """Force cleanup all stuck visual indicators"""
    print("[CLEANUP] Starting force cleanup of VoiceFlow visual indicators...")

    try:
        from voiceflow.ui.visual_indicators import force_cleanup_all
        force_cleanup_all()
        print("[CLEANUP] Force cleanup completed successfully")

        # Also try to cleanup any tray icons
        try:
            from voiceflow.ui.enhanced_tray import cleanup_tray
            cleanup_tray()
            print("[CLEANUP] Tray cleanup completed")
        except ImportError:
            print("[CLEANUP] No tray cleanup function available")
        except Exception as e:
            print(f"[CLEANUP] Tray cleanup error: {e}")

    except Exception as e:
        print(f"[CLEANUP] Force cleanup error: {e}")
        import traceback
        traceback.print_exc()

    # Try to clean up any hanging processes
    try:
        import psutil
        import os
        current_pid = os.getpid()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['pid'] == current_pid:
                    continue

                cmdline = proc.info['cmdline'] or []
                if any('voiceflow' in str(arg).lower() for arg in cmdline):
                    print(f"[CLEANUP] Found VoiceFlow process: PID {proc.info['pid']}")
                    # Don't kill - just report
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    except ImportError:
        print("[CLEANUP] psutil not available for process cleanup")
    except Exception as e:
        print(f"[CLEANUP] Process check error: {e}")

if __name__ == "__main__":
    force_cleanup()
    print("[CLEANUP] Cleanup completed. VoiceFlow should now work properly.")