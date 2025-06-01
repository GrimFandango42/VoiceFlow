"""
VoiceFlow Native - Speech Processing Integration
Integrates existing Whisper + DeepSeek pipeline with native Windows application.
"""

import sys
import os
import time
import logging
import tempfile
import requests
import json
from pathlib import Path

# Add parent directory to path to import existing modules
sys.path.append(str(Path(__file__).parent.parent))

logger = logging.getLogger(__name__)

class SpeechProcessor:
    """
    Integrates existing VoiceFlow speech processing pipeline.
    Handles local Whisper transcription and DeepSeek enhancement.
    """
    
    def __init__(self):
        self.whisper_model = None
        self.deepseek_url = "http://localhost:11434/api/generate"
        self.deepseek_model = "llama3.3:latest"
        self.whisper_model_size = "base"  # Start with base for speed
        
        # Initialize Whisper model
        self.init_whisper_model()
        
        # Test DeepSeek connection
        self.test_deepseek_connection()
    
    def init_whisper_model(self):
        """Initialize local Whisper model for transcription."""
        try:
            import faster_whisper
            
            # Try GPU first, fallback to CPU
            try:
                self.whisper_model = faster_whisper.WhisperModel(
                    self.whisper_model_size,
                    device="cuda",
                    compute_type="int8"
                )
                logger.info(f"Whisper model loaded on GPU: {self.whisper_model_size}")
            except Exception as e:
                logger.warning(f"GPU loading failed: {e}. Trying CPU...")
                self.whisper_model = faster_whisper.WhisperModel(
                    self.whisper_model_size,
                    device="cpu",
                    compute_type="int8"
                )
                logger.info(f"Whisper model loaded on CPU: {self.whisper_model_size}")
                
        except ImportError:
            logger.error("faster_whisper not available. Using mock transcription.")
            self.whisper_model = None
        except Exception as e:
            logger.error(f"Failed to initialize Whisper model: {e}")
            self.whisper_model = None
    
    def test_deepseek_connection(self):
        """Test connection to local DeepSeek/Ollama instance."""
        try:
            test_url = self.deepseek_url.replace('/generate', '/tags')
            response = requests.get(test_url, timeout=2)
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m.get('name', '') for m in models]
                if self.deepseek_model in model_names:
                    logger.info(f"DeepSeek connected: {self.deepseek_model}")
                    return True
                else:
                    logger.warning(f"Model {self.deepseek_model} not found. Available: {model_names}")
                    if model_names:
                        self.deepseek_model = model_names[0]
                        logger.info(f"Using {self.deepseek_model} instead")
                        return True
        except Exception as e:
            logger.warning(f"DeepSeek not available: {e}")
        
        return False
    
    def transcribe_audio(self, audio_file_path):
        """
        Transcribe audio file using local Whisper model.
        Returns transcribed text or None if failed.
        """
        if not self.whisper_model:
            # Mock transcription for testing
            logger.info("Using mock transcription (Whisper not available)")
            time.sleep(0.5)  # Simulate processing time
            return "This is a mock transcription from VoiceFlow Native."
        
        try:
            start_time = time.time()
            
            # Transcribe using Whisper
            segments, info = self.whisper_model.transcribe(
                audio_file_path,
                language="en",
                vad_filter=True,
                vad_parameters=dict(min_silence_duration_ms=500)
            )
            
            # Combine segments into full text
            transcribed_text = " ".join([segment.text for segment in segments])
            
            processing_time = (time.time() - start_time) * 1000
            logger.info(f"Whisper transcription: '{transcribed_text}' ({processing_time:.0f}ms)")
            
            return transcribed_text.strip()
            
        except Exception as e:
            logger.error(f"Whisper transcription failed: {e}")
            return None
    
    def enhance_with_deepseek(self, text, context='general'):
        """
        Enhance transcribed text using local DeepSeek model.
        Applies context-aware formatting and corrections.
        """
        if not text or not text.strip():
            return text
        
        try:
            # Create context-appropriate prompt
            if context == 'email':
                prompt = f"""You are a professional writing assistant. Format this spoken text into a professional email-appropriate message. Fix any grammar errors, add proper punctuation, and ensure professional tone. Remove filler words like 'um', 'uh', 'like'. Keep the meaning exactly the same.

Spoken text: {text}

Professional formatted text:"""
            
            elif context == 'chat':
                prompt = f"""You are a casual writing assistant. Format this spoken text into a casual chat message. Fix obvious errors but keep the casual tone. Remove excessive filler words but maintain natural speech patterns.

Spoken text: {text}

Casual formatted text:"""
            
            elif context == 'code':
                prompt = f"""You are a technical writing assistant. Format this spoken text for technical documentation or code comments. Preserve technical terms exactly. Fix grammar and punctuation but maintain technical accuracy.

Spoken text: {text}

Technical formatted text:"""
            
            else:  # general
                prompt = f"""You are a writing assistant. Clean up this spoken text by fixing grammar, adding proper punctuation, and removing filler words. Keep the original meaning and tone.

Spoken text: {text}

Cleaned text:"""
            
            # Call DeepSeek API
            response = requests.post(self.deepseek_url, json={
                "model": self.deepseek_model,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.3,
                "max_tokens": len(text) * 2
            }, timeout=5)
            
            if response.status_code == 200:
                enhanced = response.json().get('response', text).strip()
                
                # Clean up response (remove quotes if AI added them)
                if enhanced.startswith('"') and enhanced.endswith('"'):
                    enhanced = enhanced[1:-1]
                
                logger.info(f"DeepSeek enhancement: '{text}' -> '{enhanced}'")
                return enhanced
            else:
                logger.warning(f"DeepSeek API error: {response.status_code}")
                return self.basic_cleanup(text, context)
                
        except Exception as e:
            logger.warning(f"DeepSeek enhancement failed: {e}")
            return self.basic_cleanup(text, context)
    
    def basic_cleanup(self, text, context='general'):
        """
        Basic text cleanup when DeepSeek is not available.
        Applies simple formatting rules based on context.
        """
        if not text:
            return text
        
        # Basic cleanup
        cleaned = text.strip()
        
        # Capitalize first letter
        if cleaned and not cleaned[0].isupper():
            cleaned = cleaned[0].upper() + cleaned[1:]
        
        # Context-specific formatting
        if context == 'email':
            # Professional - ensure proper punctuation
            if not cleaned.endswith(('.', '!', '?')):
                cleaned += '.'
            # Remove common filler words
            fillers = ['um', 'uh', 'like', 'you know']
            words = cleaned.split()
            cleaned_words = [w for w in words if w.lower().strip('.,!?') not in fillers]
            cleaned = ' '.join(cleaned_words)
        
        elif context == 'chat':
            # Casual - minimal punctuation
            if len(cleaned) > 50 and not cleaned.endswith(('.', '!', '?')):
                cleaned += '.'
        
        elif context == 'code':
            # Technical - preserve as-is mostly
            pass
        
        else:
            # General - add period if missing
            if not cleaned.endswith(('.', '!', '?')):
                cleaned += '.'
        
        return cleaned
    
    def process_audio_file(self, audio_file_path, context='general'):
        """
        Complete processing pipeline: audio -> transcription -> enhancement.
        Returns enhanced text and processing metadata.
        """
        start_time = time.time()
        
        try:
            # Step 1: Transcribe audio
            transcription_start = time.time()
            transcribed_text = self.transcribe_audio(audio_file_path)
            transcription_time = (time.time() - transcription_start) * 1000
            
            if not transcribed_text:
                return None, {'error': 'Transcription failed'}
            
            # Step 2: Enhance with AI
            enhancement_start = time.time()
            enhanced_text = self.enhance_with_deepseek(transcribed_text, context)
            enhancement_time = (time.time() - enhancement_start) * 1000
            
            total_time = (time.time() - start_time) * 1000
            
            metadata = {
                'transcription_time_ms': transcription_time,
                'enhancement_time_ms': enhancement_time,
                'total_time_ms': total_time,
                'raw_text': transcribed_text,
                'enhanced_text': enhanced_text,
                'context': context,
                'word_count': len(enhanced_text.split()) if enhanced_text else 0
            }
            
            logger.info(f"Processing complete: {total_time:.0f}ms total")
            return enhanced_text, metadata
            
        except Exception as e:
            logger.error(f"Audio processing pipeline failed: {e}")
            return None, {'error': str(e)}

# Global speech processor instance
speech_processor = None

def get_speech_processor():
    """Get the global speech processor instance."""
    global speech_processor
    if speech_processor is None:
        speech_processor = SpeechProcessor()
    return speech_processor

def process_audio_file_wrapper(audio_file_path, context='general'):
    """Wrapper function for use by the main native application."""
    processor = get_speech_processor()
    return processor.process_audio_file(audio_file_path, context)
