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

# Import code context analysis for programming language support
try:
    from .code_context_analyzer import LanguageDetector, LanguageType, CodeContextType
    CODE_CONTEXT_AVAILABLE = True
except ImportError:
    CODE_CONTEXT_AVAILABLE = False
    print("[AI] Warning: Code context analysis not available")


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
        
        # Programming language support
        self.language_detector = None
        self.programming_context_enabled = self.config.get('programming_context', True)
        
        if CODE_CONTEXT_AVAILABLE and self.programming_context_enabled:
            self.language_detector = LanguageDetector()
            print("[AI] ✅ Programming language context support enabled")
        
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
    
    def enhance_text(self, text: str, context: str = 'general', 
                     file_path: Optional[Path] = None, ide_context: Optional[Dict[str, Any]] = None) -> str:
        """
        Enhance transcribed text with AI formatting and correction.
        Now supports programming language-specific enhancement.
        
        Args:
            text: Text to enhance
            context: Context hint ('general', 'code', 'comment', language name)
            file_path: Optional file path for language detection
            ide_context: Optional IDE context information
            
        Returns:
            Enhanced text with programming language awareness
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
            return self.basic_format(text, context)
        
        if not self.ollama_url:
            print("[AI] No connection available, using basic formatting")
            return self.basic_format(text, context)
        
        try:
            # Detect programming language if in code context
            detected_language = None
            programming_context = None
            
            if self.language_detector and CODE_CONTEXT_AVAILABLE:
                # Try to detect language from various sources
                if file_path:
                    detected_language = self.language_detector.detect_language(file_path, text)
                elif ide_context and 'language' in ide_context:
                    # Map IDE language to our enum
                    lang_map = {
                        'python': LanguageType.PYTHON,
                        'javascript': LanguageType.JAVASCRIPT,
                        'typescript': LanguageType.TYPESCRIPT,
                        'java': LanguageType.JAVA,
                        'cpp': LanguageType.CPP,
                        'c': LanguageType.C,
                        'html': LanguageType.HTML,
                        'css': LanguageType.CSS,
                    }
                    detected_language = lang_map.get(ide_context['language'].lower(), LanguageType.UNKNOWN)
                elif context in ['code', 'comment', 'function', 'variable']:
                    detected_language = self.language_detector.detect_language(content=text)
                elif context.lower() in ['python', 'javascript', 'java', 'cpp', 'c', 'html', 'css']:
                    lang_map = {
                        'python': LanguageType.PYTHON,
                        'javascript': LanguageType.JAVASCRIPT,
                        'java': LanguageType.JAVA,
                        'cpp': LanguageType.CPP,
                        'c': LanguageType.C,
                        'html': LanguageType.HTML,
                        'css': LanguageType.CSS,
                    }
                    detected_language = lang_map.get(context.lower(), LanguageType.UNKNOWN)
                
                if detected_language and detected_language != LanguageType.UNKNOWN:
                    programming_context = {
                        'language': detected_language,
                        'context_type': context,
                        'ide_info': ide_context
                    }
                    print(f"[AI] Detected programming language: {detected_language.value}")
            
            # Context-aware prompt generation with programming support
            prompt = self._generate_prompt(text, context, programming_context)
            
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
                return self.basic_format(text, context)
                
        except Exception as e:
            print(f"[AI] Enhancement failed: {e}")
            return self.basic_format(text, context)
    
    def _generate_prompt(self, text: str, context: str, programming_context: Optional[Dict[str, Any]] = None) -> str:
        """Generate context-aware prompt for AI enhancement with programming language support."""
        
        # Programming language specific prompts
        if programming_context and programming_context.get('language'):
            language = programming_context['language']
            context_type = programming_context.get('context_type', 'code')
            
            return self._generate_programming_prompt(text, language, context_type, programming_context)
        
        # General context prompts
        base_prompt = """You are a transcription formatter. Format the following spoken text with proper punctuation, capitalization, and paragraph breaks. Fix any obvious transcription errors. Keep the meaning exactly the same."""
        
        context_prompts = {
            'email': 'This is email content, format appropriately for professional communication.',
            'code': 'This may contain technical terms or code. Preserve technical accuracy and use proper code formatting.',
            'comment': 'This is a code comment. Format appropriately with proper comment syntax.',
            'function': 'This is a function definition. Use proper function naming and syntax.',
            'variable': 'This is a variable declaration. Use proper variable naming conventions.',
            'document': 'This is document content, use formal writing style.',
            'chat': 'This is casual conversation, use natural informal style.',
            'general': 'Format naturally for general text input.'
        }
        
        context_instruction = context_prompts.get(context, context_prompts['general'])
        
        return f"""{base_prompt}

{context_instruction}

Raw transcription: {text}

Formatted text:"""
    
    def _generate_programming_prompt(self, text: str, language: 'LanguageType', 
                                   context_type: str, programming_context: Dict[str, Any]) -> str:
        """Generate programming language-specific enhancement prompts."""
        
        language_instructions = {
            LanguageType.PYTHON: {
                'base': 'You are a Python code formatter. Format transcribed Python code with proper syntax, indentation (4 spaces), and naming conventions (snake_case for variables/functions, PascalCase for classes).',
                'comment': 'Format as a Python comment using # syntax. Keep technical accuracy.',
                'function': 'Format as a Python function definition using "def" keyword with proper snake_case naming.',
                'variable': 'Format as a Python variable assignment using snake_case naming.',
                'code': 'Format as Python code with proper indentation, syntax, and error correction.'
            },
            LanguageType.JAVASCRIPT: {
                'base': 'You are a JavaScript code formatter. Format transcribed JavaScript code with proper syntax, indentation (2 spaces), and naming conventions (camelCase for variables/functions, PascalCase for classes).',
                'comment': 'Format as a JavaScript comment using // or /* */ syntax.',
                'function': 'Format as a JavaScript function using camelCase naming and proper syntax.',
                'variable': 'Format as a JavaScript variable declaration using let/const with camelCase naming.',
                'code': 'Format as JavaScript code with proper syntax and modern ES6+ features where appropriate.'
            },
            LanguageType.JAVA: {
                'base': 'You are a Java code formatter. Format transcribed Java code with proper syntax, indentation (4 spaces), and naming conventions (camelCase for variables/methods, PascalCase for classes).',
                'comment': 'Format as a Java comment using // or /** */ syntax for documentation.',
                'function': 'Format as a Java method with proper access modifiers and camelCase naming.',
                'variable': 'Format as a Java variable declaration with proper type and camelCase naming.',
                'code': 'Format as Java code with proper syntax, access modifiers, and error handling.'
            },
            LanguageType.CPP: {
                'base': 'You are a C++ code formatter. Format transcribed C++ code with proper syntax, indentation (4 spaces), and naming conventions (snake_case or camelCase).',
                'comment': 'Format as a C++ comment using // or /* */ syntax.',
                'function': 'Format as a C++ function with proper return types and parameter syntax.',
                'variable': 'Format as a C++ variable declaration with proper type specification.',
                'code': 'Format as C++ code with proper syntax, headers, and namespace usage.'
            },
            LanguageType.HTML: {
                'base': 'You are an HTML formatter. Format transcribed HTML with proper tag structure and indentation.',
                'comment': 'Format as an HTML comment using <!-- --> syntax.',
                'code': 'Format as HTML with proper tag structure, attributes, and semantic markup.'
            },
            LanguageType.CSS: {
                'base': 'You are a CSS formatter. Format transcribed CSS with proper syntax and indentation.',
                'comment': 'Format as a CSS comment using /* */ syntax.',
                'code': 'Format as CSS with proper selectors, properties, and values.'
            }
        }
        
        # Get language-specific instructions
        lang_instructions = language_instructions.get(language, language_instructions[LanguageType.PYTHON])
        base_instruction = lang_instructions['base']
        context_instruction = lang_instructions.get(context_type, lang_instructions.get('code', ''))
        
        # Additional context from IDE if available
        ide_info = programming_context.get('ide_info', {})
        additional_context = ""
        
        if ide_info:
            if ide_info.get('file_path'):
                additional_context += f"File context: {ide_info['file_path']}\n"
            if ide_info.get('working_directory'):
                additional_context += f"Project context: Working in {ide_info['working_directory']}\n"
        
        return f"""{base_instruction}

{context_instruction}

{additional_context}Important: Preserve all technical accuracy. Fix only obvious transcription errors. Maintain the original intent and meaning.

Raw transcription: {text}

Formatted {language.value} code:"""
    
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
    
    def basic_format(self, text: str, context: str = 'general') -> str:
        """
        Basic text formatting fallback when AI enhancement is unavailable.
        Now supports context-aware formatting including programming contexts.
        """
        if not text:
            return ""
        
        # Basic formatting improvements
        text = text.strip()
        
        # Context-specific formatting
        if context in ['comment', 'python comment']:
            return self._format_basic_comment(text, context)
        elif context in ['function', 'python function', 'javascript function']:
            return self._format_basic_function(text, context)
        elif context in ['variable', 'python variable', 'javascript variable']:
            return self._format_basic_variable(text, context)
        elif context == 'code':
            return self._format_basic_code(text)
        else:
            return self._format_basic_general(text)
    
    def _format_basic_comment(self, text: str, context: str) -> str:
        """Format text as a basic comment."""
        text = text.strip()
        
        # Determine comment style
        if 'python' in context or 'python' in text.lower():
            if not text.startswith('#'):
                text = f"# {text}"
        elif 'javascript' in context or 'java' in context:
            if not text.startswith('//'):
                text = f"// {text}"
        elif 'html' in context:
            if not text.startswith('<!--'):
                text = f"<!-- {text} -->"
        else:
            # Default to hash comment
            if not text.startswith('#'):
                text = f"# {text}"
        
        return text
    
    def _format_basic_function(self, text: str, context: str) -> str:
        """Format text as a basic function definition."""
        text = text.strip()
        
        # Convert to snake_case for Python, camelCase for JavaScript
        if 'python' in context:
            func_name = self._to_snake_case(text)
            return f"def {func_name}():"
        elif 'javascript' in context:
            func_name = self._to_camel_case(text)
            return f"function {func_name}() {{"
        elif 'java' in context:
            func_name = self._to_camel_case(text)
            return f"public void {func_name}() {{"
        else:
            func_name = self._to_snake_case(text)
            return f"def {func_name}():"
    
    def _format_basic_variable(self, text: str, context: str) -> str:
        """Format text as a basic variable declaration."""
        text = text.strip()
        
        if 'python' in context:
            var_name = self._to_snake_case(text)
            return f"{var_name} = "
        elif 'javascript' in context:
            var_name = self._to_camel_case(text)
            return f"const {var_name} = "
        elif 'java' in context:
            var_name = self._to_camel_case(text)
            return f"String {var_name} = "
        else:
            var_name = self._to_snake_case(text)
            return f"{var_name} = "
    
    def _format_basic_code(self, text: str) -> str:
        """Format text as basic code."""
        text = text.strip()
        
        # Basic code patterns
        replacements = {
            ' equals ': ' = ',
            ' plus equals ': ' += ',
            ' minus equals ': ' -= ',
            ' new line': '\n',
            ' indent': '    ',  # 4 spaces
            ' open paren': '(',
            ' close paren': ')',
            ' open bracket': '[',
            ' close bracket': ']',
            ' open brace': '{',
            ' close brace': '}',
        }
        
        for pattern, replacement in replacements.items():
            text = text.replace(pattern, replacement)
        
        return text.strip()
    
    def _format_basic_general(self, text: str) -> str:
        """Format text for general contexts."""
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
    
    def _to_snake_case(self, text: str) -> str:
        """Convert text to snake_case."""
        import re
        # Remove non-alphanumeric characters and split into words
        words = re.findall(r'\w+', text.lower())
        return '_'.join(words) if words else text.lower()
    
    def _to_camel_case(self, text: str) -> str:
        """Convert text to camelCase."""
        import re
        words = re.findall(r'\w+', text.lower())
        if not words:
            return text.lower()
        return words[0] + ''.join(word.capitalize() for word in words[1:])
    
    def get_status(self) -> Dict[str, Any]:
        """Get AI enhancer status information."""
        status = {
            "enabled": self.use_ai_enhancement,
            "connected": self.ollama_url is not None,
            "model": self.deepseek_model,
            "ollama_url": self.ollama_url or "Not connected",
            "programming_context": {
                "enabled": self.programming_context_enabled,
                "available": CODE_CONTEXT_AVAILABLE,
                "language_detector": self.language_detector is not None
            }
        }
        
        if CODE_CONTEXT_AVAILABLE and self.language_detector:
            status["programming_context"]["supported_languages"] = [
                lang.value for lang in LanguageType if lang != LanguageType.UNKNOWN
            ]
        
        return status


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