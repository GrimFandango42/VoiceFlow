"""
VoiceFlow MCP Server - Integration with Claude MCP Ecosystem
Provides voice transcription capabilities as MCP tools for enhanced AI workflows
"""

import asyncio
import json
import sqlite3
import os
import sys
import tempfile
import wave
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# MCP Framework imports following proven success patterns
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    print("MCP framework not available. Install: pip install mcp")
    MCP_AVAILABLE = False

# VoiceFlow components
try:
    from RealtimeSTT import AudioToTextRecorder
    import pyaudio
    import keyboard
    import pyautogui
    import win32api
    import win32gui
    import win32clipboard
    VOICEFLOW_AVAILABLE = True
except ImportError:
    print("VoiceFlow components not available. Run INSTALL_ENHANCED_DEPS.bat")
    VOICEFLOW_AVAILABLE = False

class VoiceFlowMCPServer:
    """
    VoiceFlow MCP Server following established success patterns
    Integrates voice transcription with Claude MCP ecosystem
    """
    
    def __init__(self):
        if not MCP_AVAILABLE:
            raise ImportError("MCP framework required")
        
        # Initialize MCP server following proven patterns
        self.server = Server("voiceflow-transcription")
        
        # VoiceFlow configuration
        self.data_dir = Path.home() / ".voiceflow"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "mcp_transcriptions.db"
        
        # Speech processor state
        self.recorder = None
        self.is_recording = False
        self.current_session = None
        
        # AI enhancement configuration
        self.ollama_urls = [
            "http://localhost:11434/api/generate",
            "http://172.30.248.191:11434/api/generate",
            "http://127.0.0.1:11434/api/generate"
        ]
        self.ollama_url = None
        self.deepseek_model = "llama3.3:latest"
        self.use_ai_enhancement = True
        
        # Initialize components
        self.init_database()
        self.test_ollama_connection()
        if VOICEFLOW_AVAILABLE:
            self.init_speech_processor()
        
        # Register MCP tools following success patterns
        self._register_tools()
        
        print("[VoiceFlow MCP] Server initialized successfully")
    
    def init_database(self):
        """Initialize MCP transcription database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mcp_transcriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    raw_text TEXT NOT NULL,
                    enhanced_text TEXT,
                    context_info TEXT,
                    processing_time_ms INTEGER,
                    word_count INTEGER,
                    ai_enhanced BOOLEAN,
                    source_method TEXT,
                    metadata TEXT
                )
            ''')
            conn.commit()
            conn.close()
            print("[VoiceFlow MCP] Database initialized")
        except Exception as e:
            print(f"[VoiceFlow MCP] Database error: {e}")
    
    def test_ollama_connection(self):
        """Test AI enhancement connectivity"""
        for url in self.ollama_urls:
            try:
                test_url = url.replace('/generate', '/tags')
                response = requests.get(test_url, timeout=2)
                if response.status_code == 200:
                    self.ollama_url = url
                    models = response.json().get('models', [])
                    model_names = [m.get('name', '') for m in models]
                    
                    if self.deepseek_model in model_names:
                        print(f"[VoiceFlow MCP] AI enhancement ready: {self.deepseek_model}")
                        return
                    elif model_names:
                        self.deepseek_model = model_names[0]
                        print(f"[VoiceFlow MCP] Using AI model: {self.deepseek_model}")
                        return
            except:
                continue
        
        print("[VoiceFlow MCP] AI enhancement unavailable")
        self.use_ai_enhancement = False
    
    def init_speech_processor(self):
        """Initialize speech recognition following VoiceFlow patterns"""
        try:
            # Use the most compatible configuration
            self.recorder = AudioToTextRecorder(
                model="base",
                language="en",
                device="cuda" if self._check_gpu() else "cpu",
                compute_type="int8",
                use_microphone=False,  # We'll handle audio manually
                spinner=False,
                level=0,
                enable_realtime_transcription=False
            )
            print("[VoiceFlow MCP] Speech processor ready")
        except Exception as e:
            print(f"[VoiceFlow MCP] Speech processor error: {e}")
            self.recorder = None
    
    def _check_gpu(self):
        """Check GPU availability"""
        try:
            import torch
            return torch.cuda.is_available()
        except:
            return False
    
    def _register_tools(self):
        """Register MCP tools following proven success patterns"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available VoiceFlow tools"""
            return [
                Tool(
                    name="voice_transcribe_text",
                    description="Transcribe speech to text using VoiceFlow engine with AI enhancement",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "audio_file_path": {
                                "type": "string",
                                "description": "Path to audio file (WAV format) to transcribe"
                            },
                            "context": {
                                "type": "string",
                                "description": "Context for AI enhancement (email, chat, code, document, general)",
                                "default": "general"
                            },
                            "enhance_with_ai": {
                                "type": "boolean",
                                "description": "Whether to enhance text with AI formatting",
                                "default": True
                            }
                        },
                        "required": ["audio_file_path"]
                    }
                ),
                Tool(
                    name="voice_record_and_transcribe",
                    description="Record audio from microphone and transcribe to text (Windows only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "duration_seconds": {
                                "type": "number",
                                "description": "Recording duration in seconds (max 30)",
                                "default": 5
                            },
                            "context": {
                                "type": "string",
                                "description": "Context for AI enhancement",
                                "default": "general"
                            },
                            "auto_inject": {
                                "type": "boolean",
                                "description": "Whether to inject text at cursor position",
                                "default": False
                            }
                        }
                    }
                ),
                Tool(
                    name="voice_enhance_text",
                    description="Enhance existing text using VoiceFlow AI formatting",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Text to enhance with AI formatting"
                            },
                            "context": {
                                "type": "string",
                                "description": "Context for enhancement (email, chat, code, document, general)",
                                "default": "general"
                            }
                        },
                        "required": ["text"]
                    }
                ),
                Tool(
                    name="voice_inject_text",
                    description="Inject text at current cursor position (Windows only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Text to inject at cursor position"
                            },
                            "method": {
                                "type": "string",
                                "description": "Injection method (auto, sendkeys, clipboard, winapi)",
                                "default": "auto"
                            }
                        },
                        "required": ["text"]
                    }
                ),
                Tool(
                    name="voice_get_transcription_history",
                    description="Get recent transcription history from VoiceFlow",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "number",
                                "description": "Number of recent transcriptions to retrieve",
                                "default": 10
                            },
                            "session_id": {
                                "type": "string",
                                "description": "Filter by specific session ID (optional)"
                            }
                        }
                    }
                ),
                Tool(
                    name="voice_get_statistics",
                    description="Get VoiceFlow usage statistics and system status",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="voice_detect_application_context",
                    description="Detect current active application context for smart formatting",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Handle tool calls following proven async patterns"""
            try:
                if name == "voice_transcribe_text":
                    result = await self._transcribe_audio_file(
                        arguments.get("audio_file_path"),
                        arguments.get("context", "general"),
                        arguments.get("enhance_with_ai", True)
                    )
                
                elif name == "voice_record_and_transcribe":
                    result = await self._record_and_transcribe(
                        arguments.get("duration_seconds", 5),
                        arguments.get("context", "general"),
                        arguments.get("auto_inject", False)
                    )
                
                elif name == "voice_enhance_text":
                    result = await self._enhance_text(
                        arguments.get("text"),
                        arguments.get("context", "general")
                    )
                
                elif name == "voice_inject_text":
                    result = await self._inject_text(
                        arguments.get("text"),
                        arguments.get("method", "auto")
                    )
                
                elif name == "voice_get_transcription_history":
                    result = await self._get_transcription_history(
                        arguments.get("limit", 10),
                        arguments.get("session_id")
                    )
                
                elif name == "voice_get_statistics":
                    result = await self._get_statistics()
                
                elif name == "voice_detect_application_context":
                    result = await self._detect_application_context()
                
                else:
                    result = {"error": f"Unknown tool: {name}"}
                
                return [TextContent(type="text", text=json.dumps(result, indent=2))]
                
            except Exception as e:
                error_result = {"error": str(e), "tool": name}
                return [TextContent(type="text", text=json.dumps(error_result, indent=2))]
    
    async def _transcribe_audio_file(self, audio_file_path: str, context: str, enhance_with_ai: bool) -> Dict[str, Any]:
        """Transcribe audio file to text"""
        if not self.recorder:
            return {"error": "Speech processor not available"}
        
        if not os.path.exists(audio_file_path):
            return {"error": f"Audio file not found: {audio_file_path}"}
        
        try:
            start_time = time.time()
            
            # Transcribe using VoiceFlow engine
            raw_text = self.recorder.transcribe(audio_file_path)
            
            if not raw_text or not raw_text.strip():
                return {"error": "No speech detected in audio"}
            
            raw_text = raw_text.strip()
            
            # Enhance with AI if requested
            enhanced_text = raw_text
            if enhance_with_ai and self.use_ai_enhancement:
                enhanced_text = await self._enhance_text_with_ai(raw_text, context)
            
            # Calculate metrics
            processing_time = int((time.time() - start_time) * 1000)
            word_count = len(enhanced_text.split())
            
            # Save to database
            session_id = f"mcp_{int(time.time())}"
            await self._save_transcription(
                session_id=session_id,
                raw_text=raw_text,
                enhanced_text=enhanced_text,
                context_info=context,
                processing_time_ms=processing_time,
                word_count=word_count,
                ai_enhanced=enhance_with_ai and self.use_ai_enhancement,
                source_method="file_transcription",
                metadata={"audio_file": audio_file_path}
            )
            
            return {
                "success": True,
                "raw_text": raw_text,
                "enhanced_text": enhanced_text,
                "context": context,
                "word_count": word_count,
                "processing_time_ms": processing_time,
                "ai_enhanced": enhance_with_ai and self.use_ai_enhancement,
                "session_id": session_id
            }
            
        except Exception as e:
            return {"error": f"Transcription failed: {str(e)}"}
    
    async def _record_and_transcribe(self, duration: float, context: str, auto_inject: bool) -> Dict[str, Any]:
        """Record audio and transcribe (Windows only)"""
        if not VOICEFLOW_AVAILABLE:
            return {"error": "VoiceFlow components not available on this system"}
        
        # Limit duration for safety
        duration = min(duration, 30)
        
        try:
            # Record audio
            audio_file = await self._record_audio(duration)
            if not audio_file:
                return {"error": "Failed to record audio"}
            
            # Transcribe
            result = await self._transcribe_audio_file(audio_file, context, True)
            
            # Inject text if requested and successful
            if auto_inject and result.get("success") and VOICEFLOW_AVAILABLE:
                injection_result = await self._inject_text(result["enhanced_text"], "auto")
                result["injection_result"] = injection_result
            
            # Cleanup audio file
            try:
                os.unlink(audio_file)
            except:
                pass
            
            return result
            
        except Exception as e:
            return {"error": f"Recording failed: {str(e)}"}
    
    async def _record_audio(self, duration: float) -> Optional[str]:
        """Record audio from microphone"""
        try:
            audio = pyaudio.PyAudio()
            
            # Audio configuration
            format = pyaudio.paInt16
            channels = 1
            sample_rate = 16000
            chunk_size = 1024
            
            stream = audio.open(
                format=format,
                channels=channels,
                rate=sample_rate,
                input=True,
                frames_per_buffer=chunk_size
            )
            
            print(f"[VoiceFlow MCP] Recording for {duration} seconds...")
            frames = []
            
            for _ in range(int(sample_rate * duration / chunk_size)):
                data = stream.read(chunk_size, exception_on_overflow=False)
                frames.append(data)
            
            stream.stop_stream()
            stream.close()
            audio.terminate()
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
                temp_path = temp_file.name
            
            wf = wave.open(temp_path, 'wb')
            wf.setnchannels(channels)
            wf.setsampwidth(audio.get_sample_size(format))
            wf.setframerate(sample_rate)
            wf.writeframes(b''.join(frames))
            wf.close()
            
            return temp_path
            
        except Exception as e:
            print(f"[VoiceFlow MCP] Recording error: {e}")
            return None
    
    async def _enhance_text(self, text: str, context: str) -> Dict[str, Any]:
        """Enhance text with AI formatting"""
        if not text:
            return {"error": "No text provided"}
        
        enhanced_text = await self._enhance_text_with_ai(text, context)
        
        return {
            "success": True,
            "original_text": text,
            "enhanced_text": enhanced_text,
            "context": context,
            "ai_enhanced": self.use_ai_enhancement
        }
    
    async def _enhance_text_with_ai(self, text: str, context: str) -> str:
        """Enhance text using AI following VoiceFlow patterns"""
        if not self.use_ai_enhancement or not text:
            return self._basic_format(text, context)
        
        try:
            context_prompts = {
                'email': "Format this email text professionally with proper punctuation and grammar:",
                'chat': "Format this casual message naturally with minimal punctuation:",
                'code': "Format this technical text preserving exact terminology:",
                'document': "Format this formal document text with proper punctuation:",
                'social': "Format this social media text casually:",
                'general': "Format this text with proper punctuation and capitalization:"
            }
            
            prompt = f"{context_prompts.get(context, context_prompts['general'])} {text}"
            
            response = requests.post(self.ollama_url, json={
                "model": self.deepseek_model,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.3,
                "top_p": 0.9,
                "max_tokens": len(text) * 2
            }, timeout=5)
            
            if response.status_code == 200:
                enhanced = response.json().get('response', text).strip()
                if enhanced.startswith('"') and enhanced.endswith('"'):
                    enhanced = enhanced[1:-1]
                return enhanced
            
        except Exception as e:
            print(f"[VoiceFlow MCP] AI enhancement error: {e}")
        
        return self._basic_format(text, context)
    
    def _basic_format(self, text: str, context: str) -> str:
        """Basic text formatting fallback"""
        if not text:
            return text
        
        formatted = text.strip()
        if formatted:
            formatted = formatted[0].upper() + formatted[1:]
        
        if context in ['email', 'document'] and not formatted.endswith(('.', '!', '?')):
            formatted += '.'
        
        return formatted
    
    async def _inject_text(self, text: str, method: str) -> Dict[str, Any]:
        """Inject text at cursor position (Windows only)"""
        if not VOICEFLOW_AVAILABLE:
            return {"error": "Text injection not available on this system"}
        
        if not text:
            return {"error": "No text provided"}
        
        try:
            success = False
            method_used = method
            
            if method == "auto" or method == "sendkeys":
                keyboard.write(text)
                success = True
                method_used = "sendkeys"
            
            elif method == "clipboard":
                # Save current clipboard
                original = self._get_clipboard()
                
                # Set our text
                self._set_clipboard(text)
                
                # Send Ctrl+V
                keyboard.send('ctrl+v')
                
                # Restore clipboard
                if original:
                    def restore():
                        time.sleep(0.5)
                        self._set_clipboard(original)
                    asyncio.create_task(asyncio.to_thread(restore))
                
                success = True
                method_used = "clipboard"
            
            elif method == "winapi":
                # Get active window and send WM_CHAR messages
                hwnd = win32gui.GetForegroundWindow()
                if hwnd:
                    for char in text:
                        win32api.SendMessage(hwnd, 0x0102, ord(char), 0)  # WM_CHAR
                    success = True
                    method_used = "winapi"
            
            return {
                "success": success,
                "text": text,
                "method_used": method_used,
                "length": len(text)
            }
            
        except Exception as e:
            return {"error": f"Text injection failed: {str(e)}"}
    
    def _get_clipboard(self) -> Optional[str]:
        """Get current clipboard text"""
        try:
            win32clipboard.OpenClipboard()
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                win32clipboard.CloseClipboard()
                return data.decode('utf-8') if isinstance(data, bytes) else data
        except:
            pass
        finally:
            try:
                win32clipboard.CloseClipboard()
            except:
                pass
        return None
    
    def _set_clipboard(self, text: str) -> bool:
        """Set clipboard text"""
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardData(win32clipboard.CF_TEXT, text.encode('utf-8'))
            win32clipboard.CloseClipboard()
            return True
        except:
            return False
        finally:
            try:
                win32clipboard.CloseClipboard()
            except:
                pass
    
    async def _get_transcription_history(self, limit: int, session_id: Optional[str]) -> Dict[str, Any]:
        """Get transcription history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if session_id:
                cursor.execute('''
                    SELECT * FROM mcp_transcriptions 
                    WHERE session_id = ?
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (session_id, limit))
            else:
                cursor.execute('''
                    SELECT * FROM mcp_transcriptions 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
            
            columns = [desc[0] for desc in cursor.description]
            results = []
            
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            conn.close()
            
            return {
                "success": True,
                "transcriptions": results,
                "count": len(results),
                "session_filter": session_id
            }
            
        except Exception as e:
            return {"error": f"Failed to get history: {str(e)}"}
    
    async def _get_statistics(self) -> Dict[str, Any]:
        """Get VoiceFlow statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total stats
            cursor.execute('SELECT COUNT(*), SUM(word_count), AVG(processing_time_ms) FROM mcp_transcriptions')
            total_count, total_words, avg_processing = cursor.fetchone()
            
            # Today's stats
            cursor.execute('''
                SELECT COUNT(*), SUM(word_count), AVG(processing_time_ms) 
                FROM mcp_transcriptions
                WHERE DATE(timestamp) = DATE('now')
            ''')
            today_count, today_words, today_avg_processing = cursor.fetchone()
            
            # AI enhancement stats
            cursor.execute('SELECT COUNT(*) FROM mcp_transcriptions WHERE ai_enhanced = 1')
            ai_enhanced_count = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "success": True,
                "statistics": {
                    "total": {
                        "transcriptions": total_count or 0,
                        "words": total_words or 0,
                        "avg_processing_ms": round(avg_processing or 0, 2)
                    },
                    "today": {
                        "transcriptions": today_count or 0,
                        "words": today_words or 0,
                        "avg_processing_ms": round(today_avg_processing or 0, 2)
                    },
                    "ai_enhancement": {
                        "enhanced_count": ai_enhanced_count or 0,
                        "enhancement_rate": round((ai_enhanced_count or 0) / max(1, total_count or 1) * 100, 1)
                    }
                },
                "system_status": {
                    "speech_processor_available": self.recorder is not None,
                    "ai_enhancement_available": self.use_ai_enhancement,
                    "windows_integration_available": VOICEFLOW_AVAILABLE,
                    "gpu_available": self._check_gpu()
                }
            }
            
        except Exception as e:
            return {"error": f"Failed to get statistics: {str(e)}"}
    
    async def _detect_application_context(self) -> Dict[str, Any]:
        """Detect current application context"""
        if not VOICEFLOW_AVAILABLE:
            return {"error": "Application detection not available on this system"}
        
        try:
            hwnd = win32gui.GetForegroundWindow()
            if not hwnd:
                return {"error": "No active window found"}
            
            window_title = win32gui.GetWindowText(hwnd)
            _, process_id = win32process.GetWindowThreadProcessId(hwnd)
            
            try:
                process_handle = win32api.OpenProcess(0x0400 | 0x0010, False, process_id)
                executable_path = win32process.GetModuleFileNameEx(process_handle, 0)
                app_name = os.path.basename(executable_path).lower()
                win32api.CloseHandle(process_handle)
            except:
                app_name = "unknown"
                executable_path = ""
            
            # Detect context type
            context = self._classify_application_context(app_name, window_title)
            
            return {
                "success": True,
                "application": {
                    "name": app_name,
                    "title": window_title,
                    "executable": executable_path,
                    "process_id": process_id,
                    "context_type": context
                },
                "suggested_formatting": self._get_context_suggestions(context)
            }
            
        except Exception as e:
            return {"error": f"Context detection failed: {str(e)}"}
    
    def _classify_application_context(self, app_name: str, window_title: str) -> str:
        """Classify application context"""
        app_name = app_name.lower()
        window_title = window_title.lower()
        
        if any(email in app_name for email in ['outlook', 'thunderbird', 'mailbird']):
            return 'email'
        elif any(browser in app_name for browser in ['chrome', 'firefox', 'edge', 'msedge']):
            if any(site in window_title for site in ['gmail', 'outlook', 'yahoo mail']):
                return 'email'
            elif any(site in window_title for site in ['slack', 'discord', 'teams']):
                return 'chat'
            return 'web'
        elif any(dev in app_name for dev in ['code', 'notepad++', 'sublime', 'pycharm']):
            return 'code'
        elif any(office in app_name for office in ['winword', 'excel', 'powerpoint']):
            return 'document'
        elif any(chat in app_name for chat in ['slack', 'discord', 'teams']):
            return 'chat'
        else:
            return 'general'
    
    def _get_context_suggestions(self, context: str) -> Dict[str, str]:
        """Get formatting suggestions for context"""
        suggestions = {
            'email': "Professional tone, proper punctuation, formal language",
            'chat': "Casual tone, minimal punctuation, conversational",
            'code': "Preserve technical terms, exact formatting",
            'document': "Formal tone, proper grammar and punctuation",
            'web': "Context-dependent, generally casual to formal",
            'general': "Balanced tone, proper capitalization and punctuation"
        }
        
        return {
            "formatting_style": suggestions.get(context, suggestions['general']),
            "recommended_ai_enhancement": context in ['email', 'document', 'general']
        }
    
    async def _save_transcription(self, **kwargs):
        """Save transcription to MCP database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO mcp_transcriptions
                (session_id, raw_text, enhanced_text, context_info, processing_time_ms,
                 word_count, ai_enhanced, source_method, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                kwargs.get('session_id'),
                kwargs.get('raw_text'),
                kwargs.get('enhanced_text'),
                kwargs.get('context_info'),
                kwargs.get('processing_time_ms'),
                kwargs.get('word_count'),
                kwargs.get('ai_enhanced'),
                kwargs.get('source_method'),
                json.dumps(kwargs.get('metadata', {}))
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[VoiceFlow MCP] Database save error: {e}")

async def main():
    """Main entry point following MCP server patterns"""
    if not MCP_AVAILABLE:
        print("MCP framework not available. Install: pip install mcp")
        return
    
    server_instance = VoiceFlowMCPServer()
    
    # Run MCP server using proven stdio pattern
    async with stdio_server() as (read_stream, write_stream):
        await server_instance.server.run(
            read_stream, 
            write_stream,
            server_instance.server.create_initialization_options()
        )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[VoiceFlow MCP] Server stopped by user")
    except Exception as e:
        print(f"[VoiceFlow MCP] Fatal error: {e}")
        sys.exit(1)