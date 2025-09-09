"""
Debug Session Transcription and Variable Naming Features

Advanced debugging support for voice-driven development with:
- Debug session transcription and logging
- Voice-controlled breakpoint management
- Variable inspection and naming assistance
- Debug command interpretation and execution
- Real-time debugging narration
"""

import re
import json
import time
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import queue

try:
    import psutil
    PROCESS_DETECTION = True
except ImportError:
    PROCESS_DETECTION = False

try:
    from .code_context_analyzer import LanguageType, CodeContextType
    CODE_CONTEXT_AVAILABLE = True
except ImportError:
    CODE_CONTEXT_AVAILABLE = False


class DebuggerType(Enum):
    """Supported debugger types."""
    GDB = "gdb"
    LLDB = "lldb"
    PDB = "pdb"          # Python debugger
    NODE_INSPECTOR = "node"  # Node.js inspector
    CHROME_DEVTOOLS = "chrome"
    VS_CODE = "vscode"
    INTELLIJ = "intellij"
    JAVA_DEBUGGER = "jdb"
    UNKNOWN = "unknown"


class DebugState(Enum):
    """Debug session states."""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    PAUSED = "paused"
    STEPPING = "stepping"
    BREAKPOINT = "breakpoint"
    ERROR = "error"
    FINISHED = "finished"


class BreakpointType(Enum):
    """Types of breakpoints."""
    LINE = "line"
    FUNCTION = "function"
    CONDITIONAL = "conditional"
    WATCHPOINT = "watchpoint"
    EXCEPTION = "exception"


@dataclass
class Variable:
    """Debug variable information."""
    name: str
    value: str
    type: str
    scope: str  # local, global, closure
    is_mutable: bool = True
    memory_address: Optional[str] = None
    children: List['Variable'] = field(default_factory=list)


@dataclass
class Breakpoint:
    """Breakpoint information."""
    id: str
    file_path: Path
    line_number: int
    breakpoint_type: BreakpointType
    condition: Optional[str] = None
    hit_count: int = 0
    enabled: bool = True
    temporary: bool = False


@dataclass
class StackFrame:
    """Stack frame information."""
    id: str
    function_name: str
    file_path: Path
    line_number: int
    variables: List[Variable]
    is_current: bool = False


@dataclass
class DebugEvent:
    """Debug session event."""
    timestamp: datetime
    event_type: str  # breakpoint_hit, step_complete, variable_changed, etc.
    description: str
    location: Optional[Tuple[Path, int]] = None
    variables: List[Variable] = field(default_factory=list)
    stack_frames: List[StackFrame] = field(default_factory=list)


class VoiceDebugCommand:
    """Voice command for debugging."""
    
    # Command patterns and their mappings
    COMMAND_PATTERNS = {
        # Navigation commands
        'continue': [
            r'continue(?:\s+execution)?',
            r'(?:resume|run)(?:\s+program)?',
            r'keep\s+(?:going|running)',
            r'(?:go|move)\s+(?:ahead|forward)'
        ],
        'step_over': [
            r'step\s+over',
            r'next(?:\s+line)?',
            r'execute\s+(?:this\s+)?line',
            r'skip\s+(?:this\s+)?(?:function|call)'
        ],
        'step_into': [
            r'step\s+into',
            r'enter\s+(?:function|method)',
            r'go\s+(?:into|inside)(?:\s+(?:function|method))?',
            r'dive\s+(?:into|in)'
        ],
        'step_out': [
            r'step\s+out',
            r'(?:finish|complete)(?:\s+function)?',
            r'(?:exit|leave)(?:\s+(?:function|method))?',
            r'go\s+(?:back|up)(?:\s+(?:one\s+)?level)?'
        ],
        
        # Breakpoint commands
        'set_breakpoint': [
            r'(?:set|add|create)\s+breakpoint(?:\s+(?:at|on))?(?:\s+line)?\s+(\d+)',
            r'break(?:\s+(?:at|on))?\s+line\s+(\d+)',
            r'stop\s+(?:at|on)\s+line\s+(\d+)',
            r'pause\s+(?:at|on)\s+line\s+(\d+)'
        ],
        'remove_breakpoint': [
            r'(?:remove|delete|clear)\s+breakpoint(?:\s+(?:at|on))?(?:\s+line)?\s+(\d+)',
            r'unbreak\s+line\s+(\d+)',
            r'disable\s+breakpoint\s+(\d+)'
        ],
        'list_breakpoints': [
            r'(?:list|show)\s+breakpoints?',
            r'what\s+breakpoints?',
            r'where\s+(?:are\s+)?(?:the\s+)?breakpoints?'
        ],
        
        # Variable inspection
        'inspect_variable': [
            r'(?:inspect|examine|show|print)\s+(?:variable\s+)?([a-zA-Z_]\w*)',
            r'what\s+(?:is|\'s)\s+(?:the\s+value\s+of\s+)?([a-zA-Z_]\w*)',
            r'(?:check|look\s+at)\s+([a-zA-Z_]\w*)',
            r'value\s+of\s+([a-zA-Z_]\w*)'
        ],
        'set_variable': [
            r'(?:set|change)\s+([a-zA-Z_]\w*)\s+to\s+(.+)',
            r'assign\s+(.+)\s+to\s+([a-zA-Z_]\w*)',
            r'([a-zA-Z_]\w*)\s+(?:equals|=)\s+(.+)'
        ],
        'watch_variable': [
            r'(?:watch|monitor)\s+(?:variable\s+)?([a-zA-Z_]\w*)',
            r'track\s+(?:changes\s+(?:to|in)\s+)?([a-zA-Z_]\w*)',
            r'notify\s+(?:when|if)\s+([a-zA-Z_]\w*)\s+changes'
        ],
        
        # Stack inspection
        'show_stack': [
            r'(?:show|display)\s+(?:call\s+)?stack',
            r'(?:where\s+)?(?:am\s+)?(?:i|we)',
            r'call\s+(?:stack|trace)',
            r'backtrace'
        ],
        'move_up_stack': [
            r'(?:go|move)\s+up(?:\s+(?:stack|frame))?',
            r'(?:previous|parent)\s+(?:frame|function)',
            r'caller(?:\s+function)?'
        ],
        'move_down_stack': [
            r'(?:go|move)\s+down(?:\s+(?:stack|frame))?',
            r'(?:next|child)\s+(?:frame|function)',
            r'callee(?:\s+function)?'
        ]
    }
    
    @classmethod
    def parse_voice_command(cls, voice_input: str) -> Optional[Tuple[str, List[str]]]:
        """Parse voice input into debug command and arguments."""
        voice_lower = voice_input.lower().strip()
        
        for command, patterns in cls.COMMAND_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, voice_lower)
                if match:
                    args = list(match.groups()) if match.groups() else []
                    return command, args
        
        return None


class DebugSessionTranscriber:
    """Transcribes and logs debug sessions."""
    
    def __init__(self, session_id: str, output_dir: Optional[Path] = None):
        """Initialize debug session transcriber."""
        self.session_id = session_id
        self.output_dir = output_dir or Path.cwd() / "debug_sessions"
        self.output_dir.mkdir(exist_ok=True)
        
        self.transcript_file = self.output_dir / f"debug_session_{session_id}_{int(time.time())}.md"
        self.events_file = self.output_dir / f"debug_events_{session_id}_{int(time.time())}.json"
        
        self.events: List[DebugEvent] = []
        self.voice_commands: List[Tuple[datetime, str, Optional[str]]] = []
        self.is_recording = False
        
        # Start transcript
        self._init_transcript()
    
    def _init_transcript(self):
        """Initialize transcript file."""
        with open(self.transcript_file, 'w') as f:
            f.write(f"# Debug Session Transcript\n\n")
            f.write(f"**Session ID:** {self.session_id}\n")
            f.write(f"**Started:** {datetime.now().isoformat()}\n\n")
            f.write(f"## Debug Events\n\n")
    
    def start_recording(self):
        """Start recording debug session."""
        self.is_recording = True
        self._log_event("session_started", "Debug session recording started")
    
    def stop_recording(self):
        """Stop recording debug session."""
        self.is_recording = False
        self._log_event("session_ended", "Debug session recording ended")
        self._finalize_transcript()
    
    def log_voice_command(self, voice_input: str, parsed_command: Optional[str] = None):
        """Log a voice command."""
        if not self.is_recording:
            return
        
        timestamp = datetime.now()
        self.voice_commands.append((timestamp, voice_input, parsed_command))
        
        # Add to transcript
        with open(self.transcript_file, 'a') as f:
            f.write(f"### {timestamp.strftime('%H:%M:%S')} - Voice Command\n")
            f.write(f"**Input:** \"{voice_input}\"\n")
            if parsed_command:
                f.write(f"**Parsed:** {parsed_command}\n")
            f.write("\n")
    
    def log_debug_event(self, event: DebugEvent):
        """Log a debug event."""
        if not self.is_recording:
            return
        
        self.events.append(event)
        
        # Add to transcript
        with open(self.transcript_file, 'a') as f:
            f.write(f"### {event.timestamp.strftime('%H:%M:%S')} - {event.event_type}\n")
            f.write(f"{event.description}\n")
            
            if event.location:
                file_path, line = event.location
                f.write(f"**Location:** {file_path.name}:{line}\n")
            
            if event.variables:
                f.write("**Variables:**\n")
                for var in event.variables:
                    f.write(f"- `{var.name}` = `{var.value}` ({var.type})\n")
            
            if event.stack_frames:
                f.write("**Stack Trace:**\n")
                for i, frame in enumerate(event.stack_frames):
                    current = "→ " if frame.is_current else "  "
                    f.write(f"{current}{i}: {frame.function_name} ({frame.file_path.name}:{frame.line_number})\n")
            
            f.write("\n")
    
    def _log_event(self, event_type: str, description: str, **kwargs):
        """Log a simple event."""
        event = DebugEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            description=description,
            **kwargs
        )
        self.log_debug_event(event)
    
    def _finalize_transcript(self):
        """Finalize transcript with summary."""
        with open(self.transcript_file, 'a') as f:
            f.write("## Session Summary\n\n")
            f.write(f"- **Total Events:** {len(self.events)}\n")
            f.write(f"- **Voice Commands:** {len(self.voice_commands)}\n")
            f.write(f"- **Duration:** {self._calculate_duration()}\n")
            f.write("\n")
        
        # Save events as JSON
        events_data = [
            {
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'description': event.description,
                'location': [str(event.location[0]), event.location[1]] if event.location else None,
                'variables': [
                    {
                        'name': var.name,
                        'value': var.value,
                        'type': var.type,
                        'scope': var.scope
                    }
                    for var in event.variables
                ],
                'stack_frames': [
                    {
                        'function_name': frame.function_name,
                        'file_path': str(frame.file_path),
                        'line_number': frame.line_number,
                        'is_current': frame.is_current
                    }
                    for frame in event.stack_frames
                ]
            }
            for event in self.events
        ]
        
        with open(self.events_file, 'w') as f:
            json.dump({
                'session_id': self.session_id,
                'events': events_data,
                'voice_commands': [
                    {
                        'timestamp': ts.isoformat(),
                        'input': inp,
                        'parsed': parsed
                    }
                    for ts, inp, parsed in self.voice_commands
                ]
            }, f, indent=2)
    
    def _calculate_duration(self) -> str:
        """Calculate session duration."""
        if self.events:
            start_time = self.events[0].timestamp
            end_time = self.events[-1].timestamp
            duration = end_time - start_time
            return str(duration)
        return "0:00:00"


class VariableNamingAssistant:
    """Assists with variable naming using voice input."""
    
    def __init__(self):
        """Initialize variable naming assistant."""
        self.naming_history: Dict[str, List[str]] = {}
        self.context_patterns = self._load_context_patterns()
    
    def _load_context_patterns(self) -> Dict[str, List[str]]:
        """Load context-based naming patterns."""
        return {
            'counter': ['count', 'counter', 'index', 'i', 'idx', 'num'],
            'temporary': ['temp', 'tmp', 'buffer', 'intermediate'],
            'result': ['result', 'output', 'answer', 'value', 'data'],
            'input': ['input', 'params', 'args', 'data', 'value'],
            'collection': ['list', 'array', 'items', 'elements', 'collection'],
            'flag': ['flag', 'is_enabled', 'has_value', 'can_execute', 'should_continue'],
            'string': ['text', 'message', 'content', 'data', 'string'],
            'file': ['file', 'path', 'filename', 'document'],
            'config': ['config', 'settings', 'options', 'preferences'],
            'error': ['error', 'exception', 'err', 'failure']
        }
    
    def suggest_variable_name(self, voice_description: str, variable_type: Optional[str] = None,
                            language: Optional[LanguageType] = None) -> List[str]:
        """Suggest variable names based on voice description."""
        voice_lower = voice_description.lower()
        suggestions = []
        
        # Extract key words from description
        words = re.findall(r'\b\w+\b', voice_lower)
        filtered_words = [w for w in words if w not in ['the', 'a', 'an', 'is', 'are', 'for', 'to', 'of']]
        
        # Generate suggestions based on context patterns
        for context, patterns in self.context_patterns.items():
            if any(pattern in voice_lower for pattern in patterns):
                suggestions.extend(self._generate_names_for_context(filtered_words, context, language))
        
        # Generate generic suggestions
        if not suggestions:
            suggestions = self._generate_generic_names(filtered_words, language)
        
        # Apply language-specific naming conventions
        if language:
            suggestions = [self._apply_naming_convention(name, language) for name in suggestions]
        
        # Remove duplicates and return top suggestions
        unique_suggestions = list(dict.fromkeys(suggestions))
        return unique_suggestions[:5]
    
    def _generate_names_for_context(self, words: List[str], context: str, 
                                  language: Optional[LanguageType]) -> List[str]:
        """Generate names for specific context."""
        suggestions = []
        
        if context == 'counter':
            if len(words) == 1:
                suggestions.extend([f"{words[0]}_count", f"{words[0]}_index", f"num_{words[0]}"])
            suggestions.extend(['count', 'counter', 'index', 'i', 'idx'])
        
        elif context == 'flag':
            if words:
                suggestions.extend([f"is_{words[0]}", f"has_{words[0]}", f"can_{words[0]}"])
            suggestions.extend(['flag', 'enabled', 'active'])
        
        elif context == 'collection':
            if words:
                singular = words[0].rstrip('s')  # Simple pluralization
                suggestions.extend([f"{singular}_list", f"{words[0]}", f"{singular}_array"])
            suggestions.extend(['items', 'elements', 'collection'])
        
        elif context == 'result':
            if words:
                suggestions.extend([f"{words[0]}_result", f"{words[0]}_output"])
            suggestions.extend(['result', 'output', 'value'])
        
        return suggestions
    
    def _generate_generic_names(self, words: List[str], language: Optional[LanguageType]) -> List[str]:
        """Generate generic variable names."""
        if not words:
            return ['value', 'data', 'item', 'temp']
        
        suggestions = []
        
        # Single word
        if len(words) == 1:
            suggestions.append(words[0])
        
        # Multiple words - combine them
        if len(words) > 1:
            # Join with underscore
            suggestions.append('_'.join(words))
            
            # Camel case
            camel_case = words[0] + ''.join(w.capitalize() for w in words[1:])
            suggestions.append(camel_case)
            
            # Abbreviated
            if len(words) <= 3:
                abbreviated = ''.join(w[0] for w in words)
                suggestions.append(abbreviated)
        
        # Add prefixes/suffixes
        base_name = '_'.join(words[:2]) if len(words) > 1 else words[0]
        suggestions.extend([
            f"{base_name}_value",
            f"{base_name}_data",
            f"current_{base_name}",
            f"temp_{base_name}"
        ])
        
        return suggestions
    
    def _apply_naming_convention(self, name: str, language: LanguageType) -> str:
        """Apply language-specific naming convention."""
        words = name.split('_')
        
        if language == LanguageType.PYTHON:
            # Python uses snake_case
            return '_'.join(w.lower() for w in words)
        
        elif language in [LanguageType.JAVASCRIPT, LanguageType.JAVA]:
            # JavaScript and Java use camelCase
            if not words:
                return name.lower()
            return words[0].lower() + ''.join(w.capitalize() for w in words[1:])
        
        elif language == LanguageType.CPP:
            # C++ commonly uses snake_case or camelCase
            return '_'.join(w.lower() for w in words)
        
        else:
            # Default to snake_case
            return '_'.join(w.lower() for w in words)
    
    def record_naming_choice(self, description: str, chosen_name: str):
        """Record user's naming choice for learning."""
        key = description.lower()
        if key not in self.naming_history:
            self.naming_history[key] = []
        
        if chosen_name not in self.naming_history[key]:
            self.naming_history[key].append(chosen_name)
    
    def get_naming_history(self, description: str) -> List[str]:
        """Get naming history for similar descriptions."""
        key = description.lower()
        return self.naming_history.get(key, [])


class DebuggerIntegration:
    """Integration with various debuggers."""
    
    def __init__(self):
        """Initialize debugger integration."""
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.transcriber: Optional[DebugSessionTranscriber] = None
        self.naming_assistant = VariableNamingAssistant()
        self.command_queue = queue.Queue()
        self.event_callbacks: List[Callable] = []
    
    def start_debug_session(self, session_id: str, debugger_type: DebuggerType,
                          target_file: Optional[Path] = None) -> bool:
        """Start a new debug session."""
        try:
            # Initialize transcriber
            self.transcriber = DebugSessionTranscriber(session_id)
            self.transcriber.start_recording()
            
            # Create session info
            self.active_sessions[session_id] = {
                'debugger_type': debugger_type,
                'target_file': target_file,
                'state': DebugState.NOT_STARTED,
                'breakpoints': {},
                'variables': {},
                'stack_frames': [],
                'start_time': datetime.now()
            }
            
            print(f"[DEBUG] Started debug session {session_id} with {debugger_type.value}")
            return True
            
        except Exception as e:
            print(f"[DEBUG] Failed to start session: {e}")
            return False
    
    def stop_debug_session(self, session_id: str) -> bool:
        """Stop a debug session."""
        if session_id not in self.active_sessions:
            return False
        
        try:
            if self.transcriber:
                self.transcriber.stop_recording()
            
            del self.active_sessions[session_id]
            print(f"[DEBUG] Stopped debug session {session_id}")
            return True
            
        except Exception as e:
            print(f"[DEBUG] Failed to stop session: {e}")
            return False
    
    def process_voice_debug_command(self, voice_input: str, session_id: str) -> bool:
        """Process voice command for debugging."""
        if session_id not in self.active_sessions:
            print(f"[DEBUG] No active session: {session_id}")
            return False
        
        # Parse voice command
        parsed = VoiceDebugCommand.parse_voice_command(voice_input)
        if not parsed:
            print(f"[DEBUG] Could not parse command: {voice_input}")
            return False
        
        command, args = parsed
        
        # Log voice command
        if self.transcriber:
            self.transcriber.log_voice_command(voice_input, command)
        
        # Execute command
        return self._execute_debug_command(session_id, command, args)
    
    def _execute_debug_command(self, session_id: str, command: str, args: List[str]) -> bool:
        """Execute a debug command."""
        session = self.active_sessions[session_id]
        
        try:
            if command == 'continue':
                return self._continue_execution(session_id)
            elif command == 'step_over':
                return self._step_over(session_id)
            elif command == 'step_into':
                return self._step_into(session_id)
            elif command == 'step_out':
                return self._step_out(session_id)
            elif command == 'set_breakpoint':
                line_number = int(args[0]) if args else None
                return self._set_breakpoint(session_id, line_number)
            elif command == 'remove_breakpoint':
                line_number = int(args[0]) if args else None
                return self._remove_breakpoint(session_id, line_number)
            elif command == 'inspect_variable':
                var_name = args[0] if args else None
                return self._inspect_variable(session_id, var_name)
            elif command == 'show_stack':
                return self._show_stack(session_id)
            else:
                print(f"[DEBUG] Unknown command: {command}")
                return False
                
        except Exception as e:
            print(f"[DEBUG] Command execution failed: {e}")
            return False
    
    def _continue_execution(self, session_id: str) -> bool:
        """Continue program execution."""
        session = self.active_sessions[session_id]
        session['state'] = DebugState.RUNNING
        
        if self.transcriber:
            self.transcriber._log_event("continue", "Continuing program execution")
        
        print(f"[DEBUG] Continuing execution for session {session_id}")
        return True
    
    def _step_over(self, session_id: str) -> bool:
        """Step over current line."""
        session = self.active_sessions[session_id]
        session['state'] = DebugState.STEPPING
        
        if self.transcriber:
            self.transcriber._log_event("step_over", "Stepping over current line")
        
        print(f"[DEBUG] Stepping over for session {session_id}")
        return True
    
    def _step_into(self, session_id: str) -> bool:
        """Step into function call."""
        session = self.active_sessions[session_id]
        session['state'] = DebugState.STEPPING
        
        if self.transcriber:
            self.transcriber._log_event("step_into", "Stepping into function call")
        
        print(f"[DEBUG] Stepping into for session {session_id}")
        return True
    
    def _step_out(self, session_id: str) -> bool:
        """Step out of current function."""
        session = self.active_sessions[session_id]
        session['state'] = DebugState.STEPPING
        
        if self.transcriber:
            self.transcriber._log_event("step_out", "Stepping out of current function")
        
        print(f"[DEBUG] Stepping out for session {session_id}")
        return True
    
    def _set_breakpoint(self, session_id: str, line_number: Optional[int]) -> bool:
        """Set a breakpoint."""
        if not line_number:
            return False
        
        session = self.active_sessions[session_id]
        breakpoint_id = f"{session_id}_{line_number}"
        
        breakpoint = Breakpoint(
            id=breakpoint_id,
            file_path=session.get('target_file', Path('unknown')),
            line_number=line_number,
            breakpoint_type=BreakpointType.LINE
        )
        
        session['breakpoints'][breakpoint_id] = breakpoint
        
        if self.transcriber:
            self.transcriber._log_event(
                "breakpoint_set",
                f"Set breakpoint at line {line_number}",
                location=(breakpoint.file_path, line_number)
            )
        
        print(f"[DEBUG] Set breakpoint at line {line_number}")
        return True
    
    def _remove_breakpoint(self, session_id: str, line_number: Optional[int]) -> bool:
        """Remove a breakpoint."""
        if not line_number:
            return False
        
        session = self.active_sessions[session_id]
        breakpoint_id = f"{session_id}_{line_number}"
        
        if breakpoint_id in session['breakpoints']:
            del session['breakpoints'][breakpoint_id]
            
            if self.transcriber:
                self.transcriber._log_event(
                    "breakpoint_removed",
                    f"Removed breakpoint at line {line_number}"
                )
            
            print(f"[DEBUG] Removed breakpoint at line {line_number}")
            return True
        
        return False
    
    def _inspect_variable(self, session_id: str, var_name: Optional[str]) -> bool:
        """Inspect a variable."""
        if not var_name:
            return False
        
        session = self.active_sessions[session_id]
        
        # In a real implementation, this would query the actual debugger
        # For now, create mock variable data
        variable = Variable(
            name=var_name,
            value="<value>",
            type="<type>",
            scope="local"
        )
        
        session['variables'][var_name] = variable
        
        if self.transcriber:
            self.transcriber._log_event(
                "variable_inspected",
                f"Inspected variable {var_name}",
                variables=[variable]
            )
        
        print(f"[DEBUG] Inspected variable: {var_name}")
        return True
    
    def _show_stack(self, session_id: str) -> bool:
        """Show call stack."""
        session = self.active_sessions[session_id]
        
        # Mock stack frames
        stack_frames = [
            StackFrame(
                id="frame_0",
                function_name="main",
                file_path=session.get('target_file', Path('main.py')),
                line_number=10,
                variables=[],
                is_current=True
            )
        ]
        
        session['stack_frames'] = stack_frames
        
        if self.transcriber:
            self.transcriber._log_event(
                "stack_displayed",
                "Displayed call stack",
                stack_frames=stack_frames
            )
        
        print(f"[DEBUG] Showed call stack for session {session_id}")
        return True
    
    def suggest_variable_names(self, description: str, language: Optional[LanguageType] = None) -> List[str]:
        """Get variable name suggestions."""
        return self.naming_assistant.suggest_variable_name(description, language=language)
    
    def get_debug_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get debug session status."""
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        return {
            'session_id': session_id,
            'debugger_type': session['debugger_type'].value,
            'state': session['state'].value,
            'target_file': str(session.get('target_file', '')),
            'breakpoints': len(session['breakpoints']),
            'variables': len(session['variables']),
            'start_time': session['start_time'].isoformat(),
            'transcript_file': str(self.transcriber.transcript_file) if self.transcriber else None
        }
    
    def get_all_sessions_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all active sessions."""
        return {
            session_id: self.get_debug_status(session_id)
            for session_id in self.active_sessions
        }


def create_debug_integration() -> DebuggerIntegration:
    """Factory function to create debug integration."""
    return DebuggerIntegration()