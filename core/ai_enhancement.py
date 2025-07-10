"""
AI Enhancement Module

Consolidated DeepSeek/Ollama integration extracted from duplicate implementations.
Combines functionality from stt_server.py, speech_processor.py, and voiceflow_mcp_server.py.
"""

import os
import requests
import time
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import validation utilities
try:
    from utils.validation import InputValidator, ValidationError
    VALIDATION_AVAILABLE = True
except ImportError:
    VALIDATION_AVAILABLE = False


class AIEnhancer:
    """
    AI text enhancement using Ollama/DeepSeek integration.
    
    Consolidated from duplicate implementations in:
    - stt_server.py
    - speech_processor.py
    - voiceflow_mcp_server.py
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize AI enhancer with configuration."""
        self.config = config or {}
        
        # Ollama configuration with environment variable support
        ollama_host = os.getenv('OLLAMA_HOST', 'localhost')
        ollama_port = os.getenv('OLLAMA_PORT', '11434')
        ollama_protocol = 'https' if os.getenv('OLLAMA_USE_HTTPS', 'false').lower() == 'true' else 'http'
        
        self.ollama_urls = [
            f"{ollama_protocol}://{ollama_host}:{ollama_port}/api/generate",
            "http://localhost:11434/api/generate",
            "http://127.0.0.1:11434/api/generate"
        ]
        
        self.ollama_url = None
        self.deepseek_model = self.config.get('model', os.getenv('AI_MODEL', 'llama3.3:latest'))
        self.use_ai_enhancement = self.config.get('enabled', 
                                                   os.getenv('ENABLE_AI_ENHANCEMENT', 'true').lower() == 'true')
        
        # Test connection on initialization
        if self.use_ai_enhancement:
            self.test_ollama_connection()
    
    def test_ollama_connection(self) -> bool:
        """
        Test Ollama connectivity and find working endpoint.
        Consolidated from multiple identical implementations.
        """
        print("[AI] Testing Ollama connection...")
        
        for url in self.ollama_urls:
            try:
                # Test with /tags endpoint first
                test_url = url.replace('/generate', '/tags')
                response = requests.get(test_url, timeout=3)
                
                if response.status_code == 200:
                    self.ollama_url = url
                    models = response.json().get('models', [])
                    model_names = [m.get('name', '') for m in models]
                    
                    print(f"[AI] ✅ Connected to Ollama at {url}")
                    print(f"[AI] Available models: {', '.join(model_names[:3])}...")
                    
                    # Check if our preferred model is available
                    if self.deepseek_model in model_names:
                        print(f"[AI] ✅ Model '{self.deepseek_model}' ready")
                        return True
                    else:
                        print(f"[AI] ⚠️  Model '{self.deepseek_model}' not found. Available: {model_names}")
                        # Use first available model as fallback
                        if model_names:
                            self.deepseek_model = model_names[0]
                            print(f"[AI] Using fallback model: {self.deepseek_model}")
                            return True
                
            except Exception as e:
                print(f"[AI] Connection failed for {url}: {e}")
                continue
        
        print("[AI] ❌ No Ollama connection available. AI enhancement disabled.")
        self.use_ai_enhancement = False
        return False
    
    def enhance_text(self, text: str, context: str = 'general') -> str:
        """
        Enhance transcribed text with AI formatting and correction.
        Consolidated enhancement logic with input validation.
        """
        # Validate input text
        if VALIDATION_AVAILABLE:
            try:
                text = InputValidator.validate_text(text, max_length=5000, allow_empty=True)
                context = InputValidator.validate_text(context, max_length=100, allow_empty=True)
            except ValidationError as e:
                print(f"[AI] Input validation failed: {e.message}")
                return self.basic_format(text)
        
        if not self.use_ai_enhancement or not text.strip():
            return self.basic_format(text)
        
        if not self.ollama_url:
            print("[AI] No connection available, using basic formatting")
            return self.basic_format(text)
        
        try:
            # Context-aware prompt generation
            prompt = self._generate_prompt(text, context)
            
            # Secure HTTPS request with certificate verification
            session = requests.Session()
            session.verify = True
            session.headers.update({
                'User-Agent': 'VoiceFlow/1.0',
                'Content-Type': 'application/json'
            })
            
            start_time = time.time()
            response = session.post(self.ollama_url, json={
                "model": self.deepseek_model,
                "prompt": prompt,
                "stream": False,
                "temperature": self.config.get('temperature', 0.3),
                "top_p": self.config.get('top_p', 0.9),
                "max_tokens": len(text) * 2
            }, timeout=self.config.get('timeout', 10))
            
            processing_time = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                enhanced = response.json().get('response', text).strip()
                
                # Clean up response formatting
                enhanced = self._clean_ai_response(enhanced)
                
                print(f"[AI] ✅ Enhanced: '{text}' -> '{enhanced}' ({processing_time:.0f}ms)")
                return enhanced
            else:
                print(f"[AI] ❌ Error {response.status_code}: {response.text}")
                return self.basic_format(text)
                
        except Exception as e:
            print(f"[AI] Enhancement failed: {e}")
            return self.basic_format(text)
    
    def _generate_prompt(self, text: str, context: str) -> str:
        """Generate context-aware prompt for AI enhancement."""
        base_prompt = """You are a transcription formatter. Format the following spoken text with proper punctuation, capitalization, and paragraph breaks. Fix any obvious transcription errors. Keep the meaning exactly the same."""
        
        context_prompts = {
            'email': 'This is email content, format appropriately for professional communication.',
            'code': 'This may contain technical terms or code. Preserve technical accuracy.',
            'document': 'This is document content, use formal writing style.',
            'chat': 'This is casual conversation, use natural informal style.',
            'general': 'Format naturally for general text input.'
        }
        
        context_instruction = context_prompts.get(context, context_prompts['general'])
        
        return f"""{base_prompt}

{context_instruction}

Raw transcription: {text}

Formatted text:"""
    
    def _clean_ai_response(self, text: str) -> str:
        """Clean up AI response formatting."""
        # Remove quotes if AI wrapped the response
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        
        # Remove common AI explanation prefixes
        prefixes_to_remove = [
            "Formatted text:",
            "Here is the formatted text:",
            "The formatted text is:",
            "Formatted:"
        ]
        
        for prefix in prefixes_to_remove:
            if text.startswith(prefix):
                text = text[len(prefix):].strip()
        
        return text.strip()
    
    def basic_format(self, text: str) -> str:
        """
        Basic text formatting fallback when AI enhancement is unavailable.
        Consolidated from multiple implementations.
        """
        if not text:
            return ""
        
        # Basic formatting improvements
        text = text.strip()
        
        # Capitalize first letter
        if text:
            text = text[0].upper() + text[1:]
        
        # Add period if missing
        if text and text[-1] not in '.!?':
            text += '.'
        
        # Basic replacements for common speech patterns
        replacements = {
            ' new line': '\n',
            ' new paragraph': '\n\n',
            ' period': '.',
            ' comma': ',',
            ' question mark': '?',
            ' exclamation mark': '!',
            'scratch that': '',  # Remove this phrase
        }
        
        for pattern, replacement in replacements.items():
            text = text.replace(pattern, replacement)
        
        return text.strip()
    
    def get_status(self) -> Dict[str, Any]:
        """Get AI enhancer status information."""
        return {
            "enabled": self.use_ai_enhancement,
            "connected": self.ollama_url is not None,
            "model": self.deepseek_model,
            "ollama_url": self.ollama_url or "Not connected"
        }


def create_enhancer(config: Optional[Dict[str, Any]] = None) -> AIEnhancer:
    """Factory function to create a configured AI enhancer."""
    default_config = {
        'enabled': os.getenv('ENABLE_AI_ENHANCEMENT', 'true').lower() == 'true',
        'model': os.getenv('AI_MODEL', 'llama3.3:latest'),
        'temperature': float(os.getenv('AI_TEMPERATURE', '0.3')),
        'timeout': int(os.getenv('AI_TIMEOUT', '10'))
    }
    
    if config:
        default_config.update(config)
    
    return AIEnhancer(default_config)