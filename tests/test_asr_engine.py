"""
Test suite for the unified ASR Engine

Tests:
1. Engine initialization
2. Model listing
3. Basic transcription with tiny model (fast test)
4. Model switching
5. Statistics tracking
"""

import numpy as np
import pytest
import logging
import time

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestASREngineBasics:
    """Test basic ASR engine functionality"""

    def test_import(self):
        """Test that the module can be imported"""
        from voiceflow.core.asr_engine import (
            ASREngine,
            ModelTier,
            MODEL_CONFIGS,
            TIER_MODELS,
        )
        assert ASREngine is not None
        assert ModelTier is not None
        assert len(MODEL_CONFIGS) > 0
        assert len(TIER_MODELS) > 0

    def test_list_models(self):
        """Test model listing"""
        from voiceflow.core.asr_engine import ASREngine

        models = ASREngine.list_models()
        logger.info(f"Available models: {list(models.keys())}")

        assert "tiny.en" in models
        assert "distil-large-v3" in models
        assert "large-v3" in models

        # Check model info structure
        tiny = models["tiny.en"]
        assert "name" in tiny
        assert "backend" in tiny
        assert "size_mb" in tiny

    def test_list_tiers(self):
        """Test tier listing"""
        from voiceflow.core.asr_engine import ASREngine

        tiers = ASREngine.list_tiers()
        logger.info(f"Available tiers: {list(tiers.keys())}")

        assert "tiny" in tiers
        assert "quick" in tiers
        assert "balanced" in tiers
        assert "quality" in tiers
        assert "voxtral" in tiers

    def test_engine_init_with_tier(self):
        """Test engine initialization with tier"""
        from voiceflow.core.asr_engine import ASREngine, ModelTier

        engine = ASREngine(tier=ModelTier.TINY)
        assert engine.model_config.model_id == "tiny.en"
        assert not engine.is_loaded()

    def test_engine_init_with_model_name(self):
        """Test engine initialization with specific model"""
        from voiceflow.core.asr_engine import ASREngine

        engine = ASREngine(model_name="tiny.en")
        assert engine.model_config.model_id == "tiny.en"

    def test_engine_default_init(self):
        """Test default engine initialization"""
        from voiceflow.core.asr_engine import ASREngine

        engine = ASREngine()
        # Default is QUICK tier (distil-large-v3)
        assert "distil" in engine.model_config.model_id.lower()


class TestASREngineTranscription:
    """Test ASR engine transcription functionality"""

    @pytest.fixture
    def engine(self):
        """Create engine with tiny model for fast testing"""
        from voiceflow.core.asr_engine import ASREngine, ModelTier

        engine = ASREngine(tier=ModelTier.TINY, device="cpu", compute_type="int8")
        yield engine
        engine.cleanup()

    def test_load_model(self, engine):
        """Test model loading"""
        assert not engine.is_loaded()

        start_time = time.time()
        engine.load()
        load_time = time.time() - start_time

        assert engine.is_loaded()
        logger.info(f"Model loaded in {load_time:.2f}s")

    def test_transcribe_empty_audio(self, engine):
        """Test transcription with empty audio"""
        from voiceflow.core.asr_engine import TranscriptionResult

        result = engine.transcribe(np.array([], dtype=np.float32))
        assert isinstance(result, TranscriptionResult) or isinstance(result, str)

    def test_transcribe_silence(self, engine):
        """Test transcription with silent audio"""
        # 1 second of silence
        silence = np.zeros(16000, dtype=np.float32)

        result = engine.transcribe(silence)
        # Should return empty or very short text for silence
        if hasattr(result, 'text'):
            assert len(result.text) < 50  # No hallucination on silence
        else:
            assert len(result) < 50

    def test_transcribe_tone(self, engine):
        """Test transcription with a tone (non-speech)"""
        # Generate a 440Hz tone for 1 second
        t = np.linspace(0, 1, 16000, dtype=np.float32)
        tone = 0.3 * np.sin(2 * np.pi * 440 * t)

        engine.load()
        result = engine.transcribe(tone)

        # Should handle non-speech audio gracefully
        logger.info(f"Tone transcription result: {result}")

    def test_transcribe_speech_like(self, engine):
        """Test transcription with speech-like audio (noise)"""
        # Generate some random noise that might trigger speech detection
        np.random.seed(42)
        audio = 0.1 * np.random.randn(32000).astype(np.float32)  # 2 seconds

        engine.load()
        start_time = time.time()
        result = engine.transcribe(audio)
        transcribe_time = time.time() - start_time

        logger.info(f"Transcription took {transcribe_time:.2f}s")
        logger.info(f"Result: {result}")

    def test_statistics(self, engine):
        """Test statistics tracking"""
        engine.load()

        # Do a few transcriptions
        for _ in range(3):
            audio = np.random.randn(16000).astype(np.float32) * 0.1
            engine.transcribe(audio)

        stats = engine.get_stats()
        logger.info(f"Stats: {stats}")

        assert stats["transcription_count"] >= 3
        assert stats["model_loaded"] is True
        assert "avg_processing_time" in stats


class TestBackwardsCompatibility:
    """Test backwards compatibility with legacy code"""

    def test_modern_whisper_asr_alias(self):
        """Test ModernWhisperASR alias"""
        from voiceflow.core.asr_engine import ModernWhisperASR
        from voiceflow.core.config import Config

        cfg = Config()
        cfg.model_name = "tiny.en"
        cfg.device = "cpu"
        cfg.compute_type = "int8"

        asr = ModernWhisperASR(cfg)
        assert asr is not None
        assert hasattr(asr, 'transcribe')

    def test_buffer_safe_asr_alias(self):
        """Test BufferSafeWhisperASR alias"""
        from voiceflow.core.asr_engine import BufferSafeWhisperASR
        from voiceflow.core.config import Config

        cfg = Config()
        asr = BufferSafeWhisperASR(cfg)
        assert asr is not None

    def test_legacy_transcribe_returns_string(self):
        """Test that legacy interface returns string"""
        from voiceflow.core.asr_engine import ModernWhisperASR
        from voiceflow.core.config import Config

        cfg = Config()
        cfg.model_name = "tiny.en"
        cfg.device = "cpu"

        asr = ModernWhisperASR(cfg)
        asr.load()

        audio = np.zeros(16000, dtype=np.float32)
        result = asr.transcribe(audio)

        # Legacy interface should return string
        assert isinstance(result, str)


class TestDistilWhisperModel:
    """Test Distil-Whisper model support"""

    def test_distil_model_config_exists(self):
        """Test that Distil model configs exist"""
        from voiceflow.core.asr_engine import MODEL_CONFIGS

        assert "distil-large-v3" in MODEL_CONFIGS
        assert "distil-large-v3.5" in MODEL_CONFIGS

        config = MODEL_CONFIGS["distil-large-v3"]
        assert "Systran" in config.model_id or "distil" in config.model_id.lower()

    def test_quick_tier_uses_distil(self):
        """Test that QUICK tier uses Distil model"""
        from voiceflow.core.asr_engine import ASREngine, ModelTier

        engine = ASREngine(tier=ModelTier.QUICK)
        assert "distil" in engine.model_config.model_id.lower()


def run_quick_test():
    """Quick test that can be run standalone"""
    from voiceflow.core.asr_engine import ASREngine, ModelTier

    print("=" * 60)
    print("VoiceFlow ASR Engine Quick Test")
    print("=" * 60)

    # List models
    print("\nAvailable models:")
    for name, info in ASREngine.list_models().items():
        print(f"  {name}: {info['description']}")

    print("\nAvailable tiers:")
    for tier, desc in ASREngine.list_tiers().items():
        print(f"  {tier}: {desc}")

    # Test with tiny model
    print("\n" + "-" * 60)
    print("Testing with tiny.en model...")
    print("-" * 60)

    engine = ASREngine(tier=ModelTier.TINY)
    print(f"Model: {engine.model_config.name}")
    print(f"Model ID: {engine.model_config.model_id}")
    print(f"Backend: {engine.model_config.backend}")

    print("\nLoading model...")
    start = time.time()
    engine.load()
    print(f"Loaded in {time.time() - start:.2f}s")

    # Test transcription
    print("\nTranscribing 2 seconds of noise...")
    np.random.seed(42)
    audio = 0.1 * np.random.randn(32000).astype(np.float32)

    start = time.time()
    result = engine.transcribe(audio)
    elapsed = time.time() - start

    print(f"Transcription time: {elapsed:.3f}s")
    print(f"Audio duration: {result.duration:.2f}s")
    print(f"Speed: {result.duration / elapsed:.1f}x realtime")
    print(f"Result text: '{result.text}'")

    # Stats
    print("\nStatistics:")
    stats = engine.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Cleanup
    engine.cleanup()
    print("\nTest completed successfully!")


if __name__ == "__main__":
    run_quick_test()
