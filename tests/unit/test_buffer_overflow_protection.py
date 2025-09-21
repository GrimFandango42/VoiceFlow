"""Tests for buffer overflow protection and repetition detection"""

import numpy as np
import pytest
from voiceflow.utils.buffer_overflow_protection import BufferOverflowProtection


class TestBufferOverflowProtection:
    """Test buffer overflow protection guardrails"""

    def setup_method(self):
        self.protector = BufferOverflowProtection()

    def test_validate_good_audio_buffer(self):
        """Test validation of normal audio buffer"""
        # Create normal audio buffer
        audio = np.random.normal(0, 0.1, 16000).astype(np.float32)

        is_valid, error_msg = self.protector.validate_audio_buffer(audio)
        assert is_valid is True
        assert error_msg is None

    def test_validate_corrupted_audio_buffer(self):
        """Test validation catches corrupted buffers"""
        # Test None buffer
        is_valid, error_msg = self.protector.validate_audio_buffer(None)
        assert is_valid is False
        assert "None" in error_msg

        # Test empty buffer
        audio = np.array([], dtype=np.float32)
        is_valid, error_msg = self.protector.validate_audio_buffer(audio)
        assert is_valid is False
        assert "empty" in error_msg

        # Test buffer with NaN values
        audio = np.array([1.0, 2.0, np.nan, 4.0], dtype=np.float32)
        is_valid, error_msg = self.protector.validate_audio_buffer(audio)
        assert is_valid is False
        assert "NaN" in error_msg

        # Test buffer with infinite values
        audio = np.array([1.0, 2.0, np.inf, 4.0], dtype=np.float32)
        is_valid, error_msg = self.protector.validate_audio_buffer(audio)
        assert is_valid is False
        assert "infinite" in error_msg

        # Test all-zero buffer (dead buffer)
        audio = np.zeros(1000, dtype=np.float32)
        is_valid, error_msg = self.protector.validate_audio_buffer(audio)
        assert is_valid is False
        assert "zeros" in error_msg

    def test_clean_transcription_removes_garbage(self):
        """Test cleaning removes garbage patterns"""
        # Test excessive repetition
        text = "hello hello hello hello hello hello hello"
        cleaned = self.protector.clean_transcription(text)
        # Should reduce repetitions
        assert cleaned.count("hello") < 7

        # Test control characters
        text = "hello\x00\x01world"
        cleaned = self.protector.clean_transcription(text)
        assert "\x00" not in cleaned
        assert "\x01" not in cleaned

        # Test same character repeated many times
        text = "helloooooooooooooooo world"
        cleaned = self.protector.clean_transcription(text)
        assert "ooooooooooo" not in cleaned

    def test_clean_transcription_removes_hallucinations(self):
        """Test cleaning removes common Whisper hallucinations"""
        # Test YouTube-style endings
        text = "This is my content thank you for watching please subscribe and like"
        cleaned = self.protector.clean_transcription(text)
        assert "subscribe" not in cleaned or "thank you" not in cleaned

        # Test repetitive patterns
        text = "you you you the the the and and and"
        cleaned = self.protector.clean_transcription(text)
        assert cleaned.count("you") <= 2
        assert cleaned.count("the") <= 2
        assert cleaned.count("and") <= 2

    def test_detect_trailing_garbage(self):
        """Test detection and removal of trailing garbage"""
        # Test good text (should remain unchanged)
        text = "This is a normal sentence about something interesting."
        result = self.protector.detect_trailing_garbage(text)
        assert result == text

        # Test with repetitive garbage at end
        text = "This is good content. But then garbage garbage garbage garbage."
        result = self.protector.detect_trailing_garbage(text)
        assert "garbage garbage garbage" not in result
        assert "This is good content" in result

        # Test with YouTube-style ending
        text = "This is my video content. Thank you for watching and please subscribe."
        result = self.protector.detect_trailing_garbage(text)
        assert "please subscribe" not in result
        assert "This is my video content" in result

    def test_max_length_truncation(self):
        """Test truncation of extremely long transcriptions"""
        # Create very long text
        long_text = "word " * 3000  # Much longer than max_transcription_length
        cleaned = self.protector.clean_transcription(long_text)
        assert len(cleaned) <= self.protector.max_transcription_length

    def test_preserves_good_content(self):
        """Test that good content is preserved"""
        good_text = "Hello, this is a normal transcription with good content."
        cleaned = self.protector.clean_transcription(good_text)
        assert cleaned == good_text

        # Test with trailing garbage detection
        result = self.protector.detect_trailing_garbage(good_text)
        assert result == good_text

    def test_handles_empty_input(self):
        """Test handling of empty or None input"""
        assert self.protector.clean_transcription("") == ""
        assert self.protector.clean_transcription(None) is None
        assert self.protector.detect_trailing_garbage("") == ""

    def test_remove_repetitions_function(self):
        """Test the repetition removal function specifically"""
        # Test word repetitions
        text = "the the the cat sat on the mat"
        cleaned = self.protector._remove_repetitions(text)
        # Should keep some repetition but not excessive
        assert cleaned.count("the") < text.count("the")
        assert "cat sat on" in cleaned

        # Test phrase repetitions
        text = "hello world hello world hello world test"
        cleaned = self.protector._remove_repetitions(text)
        assert cleaned.count("hello world") <= self.protector.max_phrase_repetitions
        assert "test" in cleaned

    def test_buffer_overflow_simulation(self):
        """Test with patterns that might indicate buffer overflow"""
        # Simulate corrupted buffer with repeating pattern
        corrupted_audio = np.tile(np.array([0.1, 0.2, 0.3]), 1000)
        is_valid, error_msg = self.protector.validate_audio_buffer(corrupted_audio)
        # This should be detected as corruption
        assert is_valid is False
        assert "corruption" in error_msg

        # Simulate transcription that might result from buffer overflow
        garbage_text = "hello world world world world world world end end end end"
        cleaned = self.protector.clean_transcription(garbage_text)
        # Should clean up the repetitive garbage
        assert cleaned.count("world") < 6
        assert cleaned.count("end") < 4