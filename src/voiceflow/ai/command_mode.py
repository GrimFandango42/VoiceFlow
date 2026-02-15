"""
Command Mode for VoiceFlow

Detects and executes voice commands for text manipulation:
- "make this more formal" → Rewrites selected text formally
- "summarize this" → Creates a summary
- "fix the grammar" → Corrects grammar
- "turn into bullet points" → Converts to list
"""

import re
import logging
from typing import Optional, Tuple, Callable, Dict, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CommandType(Enum):
    """Types of voice commands"""
    FORMALIZE = "formalize"
    CASUALIZE = "casualize"
    SUMMARIZE = "summarize"
    EXPAND = "expand"
    GRAMMAR = "grammar"
    BULLETIZE = "bulletize"
    SIMPLIFY = "simplify"
    UNDO = "undo"
    NONE = "none"


@dataclass
class CommandResult:
    """Result of command execution"""
    text: str
    command: CommandType
    success: bool
    original: Optional[str] = None
    error: Optional[str] = None


class CommandMode:
    """
    Detects and executes voice commands on text.

    Usage:
        mode = CommandMode()

        # Check if transcription is a command
        is_cmd, cmd_type = mode.detect_command("make this more formal")
        if is_cmd:
            result = mode.execute(cmd_type, selected_text)
    """

    # Command patterns with their types
    COMMAND_PATTERNS: Dict[CommandType, list] = {
        CommandType.FORMALIZE: [
            r"make (this|it) (more )?(formal|professional)",
            r"(formalize|professionalize) (this|it)",
            r"(more )?formal (tone|style|version)",
        ],
        CommandType.CASUALIZE: [
            r"make (this|it) (more )?(casual|friendly|informal)",
            r"(casualize) (this|it)",
            r"(more )?casual (tone|style|version)",
        ],
        CommandType.SUMMARIZE: [
            r"summarize (this|it)",
            r"(give me |create )?(a )?summary",
            r"make (this|it) shorter",
            r"(shorten|condense) (this|it)",
        ],
        CommandType.EXPAND: [
            r"expand (this|it|on this)",
            r"make (this|it) longer",
            r"(elaborate|add more detail)",
        ],
        CommandType.GRAMMAR: [
            r"fix (the )?grammar",
            r"correct (the )?(grammar|spelling|errors)",
            r"proofread (this|it)",
        ],
        CommandType.BULLETIZE: [
            r"(turn|convert) (this |it )?(into|to) (bullet|bulleted)( points| list)?",
            r"make (this |it )?(a |into )?(bullet|bulleted)( points| list)",
            r"(bullet|bulleted) (points|list)( please)?",
        ],
        CommandType.SIMPLIFY: [
            r"simplify (this|it)",
            r"make (this|it) (more )?(simple|simpler|easier)",
            r"(use )?simpler words",
        ],
        CommandType.UNDO: [
            r"undo( that)?",
            r"(go |revert )back",
            r"never ?mind",
            r"cancel( that)?",
        ],
    }

    # LLM prompts for each command type
    COMMAND_PROMPTS: Dict[CommandType, str] = {
        CommandType.FORMALIZE: "Rewrite this text in a more formal, professional tone. Keep the same meaning:\n\n{text}",
        CommandType.CASUALIZE: "Rewrite this text in a more casual, friendly tone. Keep the same meaning:\n\n{text}",
        CommandType.SUMMARIZE: "Summarize this text concisely while keeping the key points:\n\n{text}",
        CommandType.EXPAND: "Expand on this text with more detail and explanation:\n\n{text}",
        CommandType.GRAMMAR: "Fix any grammar, spelling, or punctuation errors in this text. Only fix errors, don't change the style:\n\n{text}",
        CommandType.BULLETIZE: "Convert this text into a bulleted list format:\n\n{text}",
        CommandType.SIMPLIFY: "Rewrite this text using simpler words and shorter sentences. Make it easier to understand:\n\n{text}",
    }

    def __init__(
        self,
        use_llm: bool = True,
        requires_prefix: bool = True,
        prefix: str = "command",
    ):
        """
        Initialize command mode.

        Args:
            use_llm: Whether to use LLM for command execution
        """
        self.use_llm = use_llm
        self.requires_prefix = bool(requires_prefix)
        self.prefix = (prefix or "command").strip().lower()
        self._llm_client = None
        self._last_original: Optional[str] = None
        self._last_result: Optional[str] = None

        # Compile patterns for speed
        self._compiled_patterns: Dict[CommandType, list] = {}
        for cmd_type, patterns in self.COMMAND_PATTERNS.items():
            self._compiled_patterns[cmd_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def _get_llm_client(self):
        """Lazy load LLM client"""
        if self._llm_client is None and self.use_llm:
            try:
                from voiceflow.ai.llm_client import get_llm_client
                self._llm_client = get_llm_client()
            except Exception as e:
                logger.warning(f"Failed to initialize LLM client: {e}")

        return self._llm_client

    def detect_command(self, text: str) -> Tuple[bool, CommandType]:
        """
        Detect if text is a voice command.

        Args:
            text: Transcribed text to check

        Returns:
            Tuple of (is_command, command_type)
        """
        if not text:
            return False, CommandType.NONE

        text_lower = text.lower().strip()
        if not text_lower:
            return False, CommandType.NONE

        if self.requires_prefix:
            if not text_lower.startswith(self.prefix):
                return False, CommandType.NONE
            text_lower = text_lower[len(self.prefix):].lstrip(" ,:.-")
            if not text_lower:
                return False, CommandType.NONE

        # Check each command type
        for cmd_type, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.fullmatch(text_lower):
                    logger.debug(f"Detected command: {cmd_type.value}")
                    return True, cmd_type

        return False, CommandType.NONE

    def execute(
        self,
        command: CommandType,
        text: str,
        context: Optional[str] = None,
    ) -> CommandResult:
        """
        Execute a command on the given text.

        Args:
            command: The command type to execute
            text: The text to transform
            context: Optional additional context

        Returns:
            CommandResult with transformed text
        """
        if command == CommandType.NONE:
            return CommandResult(
                text=text,
                command=command,
                success=False,
                error="No command specified",
            )

        if command == CommandType.UNDO:
            return self._handle_undo()

        if not text:
            return CommandResult(
                text="",
                command=command,
                success=False,
                error="No text provided",
            )

        # Save for potential undo
        self._last_original = text

        # Try LLM execution
        if self.use_llm:
            result = self._llm_execute(command, text)
            if result.success:
                self._last_result = result.text
                return result

        # Fall back to rule-based execution
        result = self._rule_execute(command, text)
        if result.success:
            self._last_result = result.text

        return result

    def _handle_undo(self) -> CommandResult:
        """Handle undo command"""
        if self._last_original:
            text = self._last_original
            self._last_original = None
            return CommandResult(
                text=text,
                command=CommandType.UNDO,
                success=True,
            )
        else:
            return CommandResult(
                text="",
                command=CommandType.UNDO,
                success=False,
                error="Nothing to undo",
            )

    def _llm_execute(self, command: CommandType, text: str) -> CommandResult:
        """Execute command using LLM"""
        client = self._get_llm_client()
        if not client:
            return CommandResult(
                text=text,
                command=command,
                success=False,
                error="LLM not available",
            )

        try:
            prompt_template = self.COMMAND_PROMPTS.get(command)
            if not prompt_template:
                return CommandResult(
                    text=text,
                    command=command,
                    success=False,
                    error=f"No prompt for command: {command}",
                )

            prompt = prompt_template.format(text=text)

            system_prompt = """You are a text transformation assistant.
Output ONLY the transformed text, nothing else.
Do not add explanations, quotes, or prefixes like "Here is..."."""

            response = client.generate(
                prompt=prompt,
                system=system_prompt,
                temperature=0.3,
                max_tokens=len(text) * 2 + 100,
            )

            if response.success and response.text:
                result_text = response.text.strip()

                # Remove quotes if added
                if result_text.startswith('"') and result_text.endswith('"'):
                    result_text = result_text[1:-1]

                return CommandResult(
                    text=result_text,
                    command=command,
                    success=True,
                    original=text,
                )

        except Exception as e:
            logger.warning(f"LLM command execution failed: {e}")

        return CommandResult(
            text=text,
            command=command,
            success=False,
            error="LLM execution failed",
        )

    def _rule_execute(self, command: CommandType, text: str) -> CommandResult:
        """Execute command using rules (fallback)"""
        result_text = text

        if command == CommandType.GRAMMAR:
            # Basic grammar fixes
            result_text = self._basic_grammar_fix(text)

        elif command == CommandType.BULLETIZE:
            # Convert to bullet points
            result_text = self._to_bullets(text)

        elif command == CommandType.SIMPLIFY:
            # Basic simplification (just ensure proper formatting)
            result_text = text.strip()
            if result_text:
                result_text = result_text[0].upper() + result_text[1:]

        else:
            # For other commands, return original if no LLM
            return CommandResult(
                text=text,
                command=command,
                success=False,
                error="Rule-based execution not available for this command",
            )

        return CommandResult(
            text=result_text,
            command=command,
            success=True,
            original=text,
        )

    def _basic_grammar_fix(self, text: str) -> str:
        """Basic grammar corrections"""
        result = text

        # Fix double spaces
        result = re.sub(r'\s+', ' ', result)

        # Capitalize first letter
        if result:
            result = result[0].upper() + result[1:]

        # Add period at end if missing
        if result and result[-1] not in '.!?':
            result += '.'

        # Fix spacing around punctuation
        result = re.sub(r'\s+([.,!?])', r'\1', result)
        result = re.sub(r'([.,!?])([A-Za-z])', r'\1 \2', result)

        return result

    def _to_bullets(self, text: str) -> str:
        """Convert text to bullet points"""
        # Split by sentences
        sentences = re.split(r'[.!?]+', text)
        bullets = []

        for s in sentences:
            s = s.strip()
            if s:
                bullets.append(f"• {s}")

        return '\n'.join(bullets) if bullets else text


# Global instance
_command_mode: Optional[CommandMode] = None


def get_command_mode(use_llm: bool = True) -> CommandMode:
    """Get or create global command mode instance"""
    global _command_mode

    if _command_mode is None:
        _command_mode = CommandMode(use_llm=use_llm)

    return _command_mode
