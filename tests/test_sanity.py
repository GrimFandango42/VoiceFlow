"""
Sanity tests to verify test infrastructure is working correctly.
"""

import pytest
import sys
from pathlib import Path

# Ensure imports work
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_imports():
    """Test that all core modules can be imported."""
    # Core modules
    from core import voiceflow_core
    from core import ai_enhancement
    from utils import config
    
    assert voiceflow_core is not None
    assert ai_enhancement is not None
    assert config is not None


def test_pytest_working():
    """Basic test to ensure pytest is working."""
    assert True
    assert 1 + 1 == 2
    assert "hello".upper() == "HELLO"


def test_fixtures_available(temp_home_dir, mock_requests):
    """Test that common fixtures are available."""
    assert temp_home_dir.exists()
    assert mock_requests is not None


@pytest.mark.slow
def test_marker_slow():
    """Test that slow marker works."""
    import time
    time.sleep(0.1)
    assert True


@pytest.mark.integration
def test_marker_integration():
    """Test that integration marker works."""
    assert True


@pytest.mark.requires_audio
def test_marker_audio():
    """Test that requires_audio marker works."""
    assert True


@pytest.mark.requires_ollama
def test_marker_ollama():
    """Test that requires_ollama marker works."""
    assert True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])