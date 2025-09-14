#!/usr/bin/env python3
"""Test the new project structure."""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

def test_imports():
    """Test that new structure imports work."""
    try:
        print("Testing VoiceFlow 2.0 structure...")

        # Test main package import
        import voiceflow
        print(f"[OK] Main package: v{voiceflow.__version__}")

        # Test core imports
        from voiceflow.core import Config
        print("[OK] Core config import")

        # Test UI imports
        from voiceflow.ui import TrayController, EnhancedTrayController
        print("[OK] UI imports")

        # Test utilities
        from voiceflow.utils import settings
        print("[OK] Utils imports")

        # Test integrations
        from voiceflow.integrations import inject
        print("[OK] Integration imports")

        print("\n[SUCCESS] All core imports successful!")
        print("VoiceFlow 2.0 structure is working correctly.")
        return True

    except Exception as e:
        print(f"\n[ERROR] Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)