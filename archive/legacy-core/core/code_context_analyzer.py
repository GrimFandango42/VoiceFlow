"""
Code Context Analyzer

Syntax-aware text processing for programming languages with context detection,
formatting rules, and integration with language servers and syntax highlighting.
"""

import re
import os
import ast
import json
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Set, Union
from dataclasses import dataclass
from enum import Enum
import subprocess

# Try to import language-specific parsers
try:
    import pygments
    from pygments.lexers import get_lexer_by_name, guess_lexer
    from pygments.token import Token
    from pygments.formatters import get_formatter_by_name
    SYNTAX_HIGHLIGHTING = True
except ImportError:
    SYNTAX_HIGHLIGHTING = False
    print("[CONTEXT] Warning: pygments not available - syntax highlighting disabled")

try:
    # Tree-sitter for advanced parsing (if available)
    import tree_sitter
    TREE_SITTER = True
except ImportError:
    TREE_SITTER = False


class LanguageType(Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CPP = "cpp"
    C = "c"
    CSHARP = "csharp"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    HTML = "html"
    CSS = "css"
    SQL = "sql"
    BASH = "bash"
    POWERSHELL = "powershell"
    JSON = "json"
    XML = "xml"
    YAML = "yaml"
    MARKDOWN = "markdown"
    UNKNOWN = "unknown"


class CodeContextType(Enum):
    """Types of code contexts where text might be injected."""
    CODE = "code"              # Regular code
    COMMENT = "comment"        # Comments
    STRING = "string"          # String literals
    DOCSTRING = "docstring"    # Documentation strings
    IMPORT = "import"          # Import statements
    FUNCTION_DEF = "function"  # Function definitions
    CLASS_DEF = "class"        # Class definitions
    VARIABLE = "variable"      # Variable declarations
    UNKNOWN = "unknown"


@dataclass
class CodePosition:
    """Represents a position in code with context."""
    line: int
    column: int
    context_type: CodeContextType
    language: LanguageType
    indentation_level: int
    scope: Optional[str]  # Function/class scope
    preceding_code: str
    following_code: str


@dataclass
class LanguageRules:
    """Language-specific formatting and syntax rules."""
    comment_syntax: Dict[str, str]  # single, multi_start, multi_end
    string_delimiters: List[str]
    statement_terminators: List[str]
    indentation_style: str  # "spaces" or "tabs"
    indentation_size: int
    line_continuation: Optional[str]
    keywords: Set[str]
    built_ins: Set[str]
    naming_conventions: Dict[str, str]  # variables, functions, classes, constants


class LanguageDetector:
    """Detects programming language from file extensions and content."""
    
    EXTENSION_MAP = {
        '.py': LanguageType.PYTHON,
        '.js': LanguageType.JAVASCRIPT,
        '.jsx': LanguageType.JAVASCRIPT,
        '.ts': LanguageType.TYPESCRIPT,
        '.tsx': LanguageType.TYPESCRIPT,
        '.java': LanguageType.JAVA,
        '.cpp': LanguageType.CPP,
        '.cc': LanguageType.CPP,
        '.cxx': LanguageType.CPP,
        '.c': LanguageType.C,
        '.h': LanguageType.C,
        '.cs': LanguageType.CSHARP,
        '.go': LanguageType.GO,
        '.rs': LanguageType.RUST,
        '.php': LanguageType.PHP,
        '.rb': LanguageType.RUBY,
        '.html': LanguageType.HTML,
        '.htm': LanguageType.HTML,
        '.css': LanguageType.CSS,
        '.sql': LanguageType.SQL,
        '.sh': LanguageType.BASH,
        '.bash': LanguageType.BASH,
        '.ps1': LanguageType.POWERSHELL,
        '.json': LanguageType.JSON,
        '.xml': LanguageType.XML,
        '.yaml': LanguageType.YAML,
        '.yml': LanguageType.YAML,
        '.md': LanguageType.MARKDOWN,
    }
    
    CONTENT_PATTERNS = {
        LanguageType.PYTHON: [r'^\s*def\s+', r'^\s*class\s+', r'^\s*import\s+', r'if\s+__name__\s*==\s*["\']__main__["\']'],
        LanguageType.JAVASCRIPT: [r'function\s+\w+', r'var\s+\w+', r'let\s+\w+', r'const\s+\w+', r'=>\s*{'],
        LanguageType.JAVA: [r'public\s+class\s+', r'public\s+static\s+void\s+main', r'package\s+[\w.]+'],
        LanguageType.CPP: [r'#include\s*<', r'using\s+namespace\s+', r'int\s+main\s*\('],
        LanguageType.HTML: [r'<!DOCTYPE\s+html>', r'<html[^>]*>', r'<head[^>]*>', r'<body[^>]*>'],
        LanguageType.CSS: [r'[\w-]+\s*:\s*[^;]+;', r'@media\s+', r'\.[\w-]+\s*{'],
    }
    
    def detect_language(self, file_path: Optional[Path] = None, content: Optional[str] = None) -> LanguageType:
        """Detect programming language from file path or content."""
        # Try file extension first
        if file_path:
            extension = file_path.suffix.lower()
            if extension in self.EXTENSION_MAP:
                return self.EXTENSION_MAP[extension]
        
        # Try content analysis
        if content and SYNTAX_HIGHLIGHTING:
            try:
                lexer = guess_lexer(content)
                lexer_name = lexer.name.lower()
                
                for lang_type in LanguageType:
                    if lang_type.value in lexer_name:
                        return lang_type
            except Exception:
                pass
        
        # Pattern-based detection
        if content:
            return self._detect_by_patterns(content)
        
        return LanguageType.UNKNOWN
    
    def _detect_by_patterns(self, content: str) -> LanguageType:
        """Detect language using regex patterns."""
        for language, patterns in self.CONTENT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                    return language
        
        return LanguageType.UNKNOWN


class LanguageRulesProvider:
    """Provides language-specific formatting and syntax rules."""
    
    def __init__(self):
        """Initialize language rules provider."""
        self.rules_cache: Dict[LanguageType, LanguageRules] = {}
        self._load_all_rules()
    
    def _load_all_rules(self):
        """Load rules for all supported languages."""
        self.rules_cache.update({
            LanguageType.PYTHON: self._get_python_rules(),
            LanguageType.JAVASCRIPT: self._get_javascript_rules(),
            LanguageType.TYPESCRIPT: self._get_typescript_rules(),
            LanguageType.JAVA: self._get_java_rules(),
            LanguageType.CPP: self._get_cpp_rules(),
            LanguageType.C: self._get_c_rules(),
            LanguageType.CSHARP: self._get_csharp_rules(),
            LanguageType.GO: self._get_go_rules(),
            LanguageType.RUST: self._get_rust_rules(),
            LanguageType.HTML: self._get_html_rules(),
            LanguageType.CSS: self._get_css_rules(),
            LanguageType.JSON: self._get_json_rules(),
        })
    
    def get_rules(self, language: LanguageType) -> LanguageRules:
        """Get formatting rules for a specific language."""
        return self.rules_cache.get(language, self._get_default_rules())
    
    def _get_python_rules(self) -> LanguageRules:
        """Python language rules."""
        return LanguageRules(
            comment_syntax={"single": "#", "multi_start": '"""', "multi_end": '"""'},
            string_delimiters=["'", '"', '"""', "'''"],
            statement_terminators=[],  # Python doesn't require semicolons
            indentation_style="spaces",
            indentation_size=4,
            line_continuation="\\",
            keywords={
                "and", "as", "assert", "break", "class", "continue", "def", "del", "elif", "else",
                "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",
                "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield"
            },
            built_ins={
                "abs", "all", "any", "bin", "bool", "bytearray", "bytes", "callable", "chr", "classmethod",
                "compile", "complex", "delattr", "dict", "dir", "divmod", "enumerate", "eval", "exec",
                "filter", "float", "format", "frozenset", "getattr", "globals", "hasattr", "hash", "help",
                "hex", "id", "input", "int", "isinstance", "issubclass", "iter", "len", "list", "locals",
                "map", "max", "memoryview", "min", "next", "object", "oct", "open", "ord", "pow", "print",
                "property", "range", "repr", "reversed", "round", "set", "setattr", "slice", "sorted",
                "staticmethod", "str", "sum", "super", "tuple", "type", "vars", "zip"
            },
            naming_conventions={
                "variables": "snake_case",
                "functions": "snake_case", 
                "classes": "PascalCase",
                "constants": "UPPER_SNAKE_CASE"
            }
        )
    
    def _get_javascript_rules(self) -> LanguageRules:
        """JavaScript language rules."""
        return LanguageRules(
            comment_syntax={"single": "//", "multi_start": "/*", "multi_end": "*/"},
            string_delimiters=['"', "'", "`"],
            statement_terminators=[";"],
            indentation_style="spaces",
            indentation_size=2,
            line_continuation=None,
            keywords={
                "abstract", "arguments", "await", "boolean", "break", "byte", "case", "catch", "char",
                "class", "const", "continue", "debugger", "default", "delete", "do", "double", "else",
                "enum", "eval", "export", "extends", "false", "final", "finally", "float", "for",
                "function", "goto", "if", "implements", "import", "in", "instanceof", "int", "interface",
                "let", "long", "native", "new", "null", "package", "private", "protected", "public",
                "return", "short", "static", "super", "switch", "synchronized", "this", "throw",
                "throws", "transient", "true", "try", "typeof", "var", "void", "volatile", "while", "with", "yield"
            },
            built_ins={
                "Array", "Boolean", "Date", "Error", "Function", "JSON", "Math", "Number", "Object",
                "RegExp", "String", "console", "document", "window", "setTimeout", "setInterval",
                "clearTimeout", "clearInterval", "parseInt", "parseFloat", "isNaN", "isFinite"
            },
            naming_conventions={
                "variables": "camelCase",
                "functions": "camelCase",
                "classes": "PascalCase", 
                "constants": "UPPER_SNAKE_CASE"
            }
        )
    
    def _get_typescript_rules(self) -> LanguageRules:
        """TypeScript language rules (extends JavaScript)."""
        js_rules = self._get_javascript_rules()
        ts_keywords = js_rules.keywords | {
            "type", "interface", "enum", "namespace", "module", "declare", "abstract", "readonly",
            "keyof", "typeof", "as", "is", "infer", "never", "unknown", "any"
        }
        
        return LanguageRules(
            comment_syntax=js_rules.comment_syntax,
            string_delimiters=js_rules.string_delimiters,
            statement_terminators=js_rules.statement_terminators,
            indentation_style=js_rules.indentation_style,
            indentation_size=js_rules.indentation_size,
            line_continuation=js_rules.line_continuation,
            keywords=ts_keywords,
            built_ins=js_rules.built_ins,
            naming_conventions=js_rules.naming_conventions
        )
    
    def _get_java_rules(self) -> LanguageRules:
        """Java language rules."""
        return LanguageRules(
            comment_syntax={"single": "//", "multi_start": "/*", "multi_end": "*/"},
            string_delimiters=['"'],
            statement_terminators=[";"],
            indentation_style="spaces",
            indentation_size=4,
            line_continuation=None,
            keywords={
                "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
                "const", "continue", "default", "do", "double", "else", "enum", "extends", "final",
                "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int",
                "interface", "long", "native", "new", "package", "private", "protected", "public",
                "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
                "throw", "throws", "transient", "try", "void", "volatile", "while"
            },
            built_ins={
                "String", "Integer", "Double", "Boolean", "Character", "Long", "Short", "Byte", "Float",
                "Object", "Class", "System", "Math", "ArrayList", "HashMap", "HashSet", "Scanner"
            },
            naming_conventions={
                "variables": "camelCase",
                "functions": "camelCase",
                "classes": "PascalCase",
                "constants": "UPPER_SNAKE_CASE"
            }
        )
    
    def _get_cpp_rules(self) -> LanguageRules:
        """C++ language rules."""
        return LanguageRules(
            comment_syntax={"single": "//", "multi_start": "/*", "multi_end": "*/"},
            string_delimiters=['"', "'"],
            statement_terminators=[";"],
            indentation_style="spaces",
            indentation_size=4,
            line_continuation="\\",
            keywords={
                "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break",
                "case", "catch", "char", "char16_t", "char32_t", "class", "compl", "const", "constexpr",
                "const_cast", "continue", "decltype", "default", "delete", "do", "double", "dynamic_cast",
                "else", "enum", "explicit", "export", "extern", "false", "float", "for", "friend", "goto",
                "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept", "not", "not_eq",
                "nullptr", "operator", "or", "or_eq", "private", "protected", "public", "register",
                "reinterpret_cast", "return", "short", "signed", "sizeof", "static", "static_assert",
                "static_cast", "struct", "switch", "template", "this", "thread_local", "throw", "true",
                "try", "typedef", "typeid", "typename", "union", "unsigned", "using", "virtual", "void",
                "volatile", "wchar_t", "while", "xor", "xor_eq"
            },
            built_ins={
                "std", "cout", "cin", "endl", "string", "vector", "map", "set", "iostream", "algorithm",
                "memory", "utility", "functional", "iterator", "exception", "stdexcept"
            },
            naming_conventions={
                "variables": "snake_case",
                "functions": "snake_case",
                "classes": "PascalCase",
                "constants": "UPPER_SNAKE_CASE"
            }
        )
    
    def _get_c_rules(self) -> LanguageRules:
        """C language rules."""
        return LanguageRules(
            comment_syntax={"single": "//", "multi_start": "/*", "multi_end": "*/"},
            string_delimiters=['"', "'"],
            statement_terminators=[";"],
            indentation_style="spaces",
            indentation_size=4,
            line_continuation="\\",
            keywords={
                "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
                "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
                "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch",
                "typedef", "union", "unsigned", "void", "volatile", "while", "_Alignas", "_Alignof",
                "_Atomic", "_Static_assert", "_Noreturn", "_Thread_local", "_Generic"
            },
            built_ins={
                "printf", "scanf", "malloc", "free", "strlen", "strcpy", "strcmp", "strcat", "memcpy",
                "memset", "FILE", "NULL", "size_t", "ptrdiff_t", "wchar_t"
            },
            naming_conventions={
                "variables": "snake_case", 
                "functions": "snake_case",
                "constants": "UPPER_SNAKE_CASE"
            }
        )
    
    def _get_csharp_rules(self) -> LanguageRules:
        """C# language rules."""
        return LanguageRules(
            comment_syntax={"single": "//", "multi_start": "/*", "multi_end": "*/"},
            string_delimiters=['"', "'"],
            statement_terminators=[";"],
            indentation_style="spaces",
            indentation_size=4,
            line_continuation=None,
            keywords={
                "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
                "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else",
                "enum", "event", "explicit", "extern", "false", "finally", "fixed", "float", "for",
                "foreach", "goto", "if", "implicit", "in", "int", "interface", "internal", "is", "lock",
                "long", "namespace", "new", "null", "object", "operator", "out", "override", "params",
                "private", "protected", "public", "readonly", "ref", "return", "sbyte", "sealed",
                "short", "sizeof", "stackalloc", "static", "string", "struct", "switch", "this",
                "throw", "true", "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort",
                "using", "virtual", "void", "volatile", "while"
            },
            built_ins={
                "Console", "String", "Int32", "Double", "Boolean", "Object", "Array", "List", "Dictionary",
                "StringBuilder", "DateTime", "Exception", "Math", "Convert", "System"
            },
            naming_conventions={
                "variables": "camelCase",
                "functions": "PascalCase",
                "classes": "PascalCase",
                "constants": "PascalCase"
            }
        )
    
    def _get_go_rules(self) -> LanguageRules:
        """Go language rules."""
        return LanguageRules(
            comment_syntax={"single": "//", "multi_start": "/*", "multi_end": "*/"},
            string_delimiters=['"', "'", "`"],
            statement_terminators=[],  # Go doesn't require semicolons in most cases
            indentation_style="tabs",
            indentation_size=1,
            line_continuation=None,
            keywords={
                "break", "case", "chan", "const", "continue", "default", "defer", "else", "fallthrough",
                "for", "func", "go", "goto", "if", "import", "interface", "map", "package", "range",
                "return", "select", "struct", "switch", "type", "var"
            },
            built_ins={
                "bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8",
                "int16", "int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32",
                "uint64", "uintptr", "append", "cap", "close", "complex", "copy", "delete", "imag",
                "len", "make", "new", "panic", "print", "println", "real", "recover"
            },
            naming_conventions={
                "variables": "camelCase",
                "functions": "camelCase",
                "constants": "PascalCase"
            }
        )
    
    def _get_rust_rules(self) -> LanguageRules:
        """Rust language rules."""
        return LanguageRules(
            comment_syntax={"single": "//", "multi_start": "/*", "multi_end": "*/"},
            string_delimiters=['"', "'"],
            statement_terminators=[";"],
            indentation_style="spaces",
            indentation_size=4,
            line_continuation=None,
            keywords={
                "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
                "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
                "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
                "use", "where", "while", "async", "await", "dyn"
            },
            built_ins={
                "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
                "f32", "f64", "bool", "char", "str", "String", "Vec", "Option", "Result", "Box", "Rc",
                "Arc", "RefCell", "Mutex", "println", "panic", "assert", "debug_assert"
            },
            naming_conventions={
                "variables": "snake_case",
                "functions": "snake_case",
                "constants": "UPPER_SNAKE_CASE",
                "types": "PascalCase"
            }
        )
    
    def _get_html_rules(self) -> LanguageRules:
        """HTML language rules."""
        return LanguageRules(
            comment_syntax={"multi_start": "<!--", "multi_end": "-->"},
            string_delimiters=['"', "'"],
            statement_terminators=[],
            indentation_style="spaces",
            indentation_size=2,
            line_continuation=None,
            keywords=set(),  # HTML doesn't have keywords per se
            built_ins={
                "html", "head", "body", "title", "meta", "link", "script", "style", "div", "span",
                "p", "h1", "h2", "h3", "h4", "h5", "h6", "a", "img", "ul", "ol", "li", "table",
                "tr", "td", "th", "form", "input", "button", "select", "option", "textarea"
            },
            naming_conventions={
                "attributes": "kebab-case",
                "ids": "kebab-case",
                "classes": "kebab-case"
            }
        )
    
    def _get_css_rules(self) -> LanguageRules:
        """CSS language rules."""
        return LanguageRules(
            comment_syntax={"multi_start": "/*", "multi_end": "*/"},
            string_delimiters=['"', "'"],
            statement_terminators=[";"],
            indentation_style="spaces",
            indentation_size=2,
            line_continuation=None,
            keywords=set(),
            built_ins={
                "color", "background", "margin", "padding", "border", "width", "height", "display",
                "position", "top", "left", "right", "bottom", "float", "clear", "font", "text",
                "line-height", "text-align", "vertical-align", "list-style", "overflow", "z-index"
            },
            naming_conventions={
                "selectors": "kebab-case",
                "properties": "kebab-case"
            }
        )
    
    def _get_json_rules(self) -> LanguageRules:
        """JSON language rules."""
        return LanguageRules(
            comment_syntax={},  # JSON doesn't support comments
            string_delimiters=['"'],
            statement_terminators=[],
            indentation_style="spaces",
            indentation_size=2,
            line_continuation=None,
            keywords={"true", "false", "null"},
            built_ins=set(),
            naming_conventions={
                "keys": "camelCase"
            }
        )
    
    def _get_default_rules(self) -> LanguageRules:
        """Default rules for unknown languages."""
        return LanguageRules(
            comment_syntax={"single": "#"},
            string_delimiters=['"', "'"],
            statement_terminators=[],
            indentation_style="spaces",
            indentation_size=4,
            line_continuation=None,
            keywords=set(),
            built_ins=set(),
            naming_conventions={}
        )


class SyntaxAnalyzer:
    """Analyzes code syntax and determines context for text injection."""
    
    def __init__(self):
        """Initialize syntax analyzer."""
        self.language_detector = LanguageDetector()
        self.rules_provider = LanguageRulesProvider()
        self.syntax_cache: Dict[str, Any] = {}
    
    def analyze_context(self, code: str, cursor_line: int, cursor_column: int,
                       file_path: Optional[Path] = None) -> CodePosition:
        """
        Analyze code context at cursor position.
        
        Args:
            code: Full code content
            cursor_line: Current cursor line (0-based)
            cursor_column: Current cursor column (0-based)
            file_path: Optional file path for language detection
            
        Returns:
            CodePosition with detailed context information
        """
        # Detect language
        language = self.language_detector.detect_language(file_path, code)
        
        # Split code into lines
        lines = code.splitlines()
        
        # Ensure cursor position is valid
        if cursor_line >= len(lines):
            cursor_line = len(lines) - 1
        if cursor_line < 0:
            cursor_line = 0
        
        current_line = lines[cursor_line] if lines else ""
        if cursor_column > len(current_line):
            cursor_column = len(current_line)
        
        # Determine context type
        context_type = self._determine_context_type(
            lines, cursor_line, cursor_column, language
        )
        
        # Calculate indentation
        indentation_level = self._calculate_indentation(current_line, language)
        
        # Determine scope
        scope = self._determine_scope(lines, cursor_line, language)
        
        # Get surrounding code
        preceding_code = self._get_preceding_code(lines, cursor_line, cursor_column)
        following_code = self._get_following_code(lines, cursor_line, cursor_column)
        
        return CodePosition(
            line=cursor_line,
            column=cursor_column,
            context_type=context_type,
            language=language,
            indentation_level=indentation_level,
            scope=scope,
            preceding_code=preceding_code,
            following_code=following_code
        )
    
    def _determine_context_type(self, lines: List[str], line: int, column: int,
                               language: LanguageType) -> CodeContextType:
        """Determine the type of code context at the cursor position."""
        if not lines or line >= len(lines):
            return CodeContextType.UNKNOWN
        
        current_line = lines[line]
        rules = self.rules_provider.get_rules(language)
        
        # Check if we're in a comment
        if self._is_in_comment(lines, line, column, rules):
            return CodeContextType.COMMENT
        
        # Check if we're in a string
        if self._is_in_string(current_line, column, rules):
            return CodeContextType.STRING
        
        # Language-specific context detection
        if language == LanguageType.PYTHON:
            return self._determine_python_context(lines, line, column)
        elif language in [LanguageType.JAVASCRIPT, LanguageType.TYPESCRIPT]:
            return self._determine_js_context(lines, line, column)
        elif language == LanguageType.JAVA:
            return self._determine_java_context(lines, line, column)
        
        return CodeContextType.CODE
    
    def _is_in_comment(self, lines: List[str], line: int, column: int,
                      rules: LanguageRules) -> bool:
        """Check if cursor is within a comment."""
        current_line = lines[line]
        
        # Single line comment
        single_comment = rules.comment_syntax.get("single")
        if single_comment:
            comment_pos = current_line.find(single_comment)
            if comment_pos != -1 and column >= comment_pos:
                return True
        
        # Multi-line comment (simplified check)
        multi_start = rules.comment_syntax.get("multi_start")
        multi_end = rules.comment_syntax.get("multi_end")
        
        if multi_start and multi_end:
            # Check if we're in a multi-line comment
            # This is a simplified implementation
            text_before_cursor = '\n'.join(lines[:line+1])[:column]
            start_count = text_before_cursor.count(multi_start)
            end_count = text_before_cursor.count(multi_end)
            return start_count > end_count
        
        return False
    
    def _is_in_string(self, line: str, column: int, rules: LanguageRules) -> bool:
        """Check if cursor is within a string literal."""
        # Simplified string detection
        text_before_cursor = line[:column]
        
        for delimiter in rules.string_delimiters:
            if delimiter in text_before_cursor:
                count = text_before_cursor.count(delimiter)
                if count % 2 == 1:  # Odd number means we're inside a string
                    return True
        
        return False
    
    def _determine_python_context(self, lines: List[str], line: int, column: int) -> CodeContextType:
        """Determine context for Python code."""
        current_line = lines[line].strip()
        
        # Check for docstrings
        if '"""' in current_line or "'''" in current_line:
            return CodeContextType.DOCSTRING
        
        # Check for function/class definitions
        if re.match(r'^\s*def\s+', current_line):
            return CodeContextType.FUNCTION_DEF
        if re.match(r'^\s*class\s+', current_line):
            return CodeContextType.CLASS_DEF
        
        # Check for import statements
        if re.match(r'^\s*(import|from)\s+', current_line):
            return CodeContextType.IMPORT
        
        # Check for variable assignment
        if '=' in current_line and not any(op in current_line for op in ['==', '!=', '<=', '>=']):
            return CodeContextType.VARIABLE
        
        return CodeContextType.CODE
    
    def _determine_js_context(self, lines: List[str], line: int, column: int) -> CodeContextType:
        """Determine context for JavaScript/TypeScript code."""
        current_line = lines[line].strip()
        
        # Check for function definitions
        if re.match(r'^\s*(function\s+\w+|const\s+\w+\s*=\s*\(.*\)\s*=>|\w+\s*\(.*\)\s*{)', current_line):
            return CodeContextType.FUNCTION_DEF
        
        # Check for class definitions
        if re.match(r'^\s*class\s+', current_line):
            return CodeContextType.CLASS_DEF
        
        # Check for import/export statements
        if re.match(r'^\s*(import|export)\s+', current_line):
            return CodeContextType.IMPORT
        
        # Check for variable declarations
        if re.match(r'^\s*(let|const|var)\s+', current_line):
            return CodeContextType.VARIABLE
        
        return CodeContextType.CODE
    
    def _determine_java_context(self, lines: List[str], line: int, column: int) -> CodeContextType:
        """Determine context for Java code."""
        current_line = lines[line].strip()
        
        # Check for method definitions
        if re.match(r'^\s*(public|private|protected)?\s*(static\s+)?\w+\s+\w+\s*\(', current_line):
            return CodeContextType.FUNCTION_DEF
        
        # Check for class definitions
        if re.match(r'^\s*(public\s+)?(abstract\s+)?class\s+', current_line):
            return CodeContextType.CLASS_DEF
        
        # Check for import statements
        if re.match(r'^\s*import\s+', current_line):
            return CodeContextType.IMPORT
        
        # Check for variable declarations
        if re.match(r'^\s*\w+\s+\w+\s*[=;]', current_line):
            return CodeContextType.VARIABLE
        
        return CodeContextType.CODE
    
    def _calculate_indentation(self, line: str, language: LanguageType) -> int:
        """Calculate indentation level for the current line."""
        rules = self.rules_provider.get_rules(language)
        
        if rules.indentation_style == "tabs":
            return len(line) - len(line.lstrip('\t'))
        else:
            spaces = len(line) - len(line.lstrip(' '))
            return spaces // rules.indentation_size
    
    def _determine_scope(self, lines: List[str], line: int, language: LanguageType) -> Optional[str]:
        """Determine the current scope (function/class name)."""
        scope_stack = []
        
        for i in range(min(line + 1, len(lines))):
            current_line = lines[i].strip()
            
            if language == LanguageType.PYTHON:
                # Function definition
                func_match = re.match(r'def\s+(\w+)', current_line)
                if func_match:
                    scope_stack.append(f"function:{func_match.group(1)}")
                
                # Class definition
                class_match = re.match(r'class\s+(\w+)', current_line)
                if class_match:
                    scope_stack.append(f"class:{class_match.group(1)}")
        
        return scope_stack[-1] if scope_stack else None
    
    def _get_preceding_code(self, lines: List[str], line: int, column: int) -> str:
        """Get code preceding the cursor position."""
        if not lines or line >= len(lines):
            return ""
        
        preceding_lines = lines[:line]
        current_line_part = lines[line][:column]
        
        # Return last few lines plus current line part
        context_lines = preceding_lines[-3:] + [current_line_part]
        return '\n'.join(context_lines)
    
    def _get_following_code(self, lines: List[str], line: int, column: int) -> str:
        """Get code following the cursor position."""
        if not lines or line >= len(lines):
            return ""
        
        current_line_part = lines[line][column:]
        following_lines = lines[line + 1:line + 4]  # Next 3 lines
        
        context_lines = [current_line_part] + following_lines
        return '\n'.join(context_lines)


class CodeFormatter:
    """Formats text according to language-specific rules and context."""
    
    def __init__(self):
        """Initialize code formatter."""
        self.rules_provider = LanguageRulesProvider()
    
    def format_for_context(self, text: str, position: CodePosition) -> str:
        """
        Format text according to the code context and language rules.
        
        Args:
            text: Text to format
            position: Code position context
            
        Returns:
            Formatted text appropriate for the context
        """
        if not text.strip():
            return text
        
        rules = self.rules_provider.get_rules(position.language)
        
        # Apply context-specific formatting
        if position.context_type == CodeContextType.COMMENT:
            return self._format_comment(text, rules, position)
        elif position.context_type == CodeContextType.STRING:
            return self._format_string(text, rules)
        elif position.context_type == CodeContextType.FUNCTION_DEF:
            return self._format_function_definition(text, rules, position)
        elif position.context_type == CodeContextType.VARIABLE:
            return self._format_variable_assignment(text, rules, position)
        else:
            return self._format_general_code(text, rules, position)
    
    def _format_comment(self, text: str, rules: LanguageRules, position: CodePosition) -> str:
        """Format text as a comment."""
        single_comment = rules.comment_syntax.get("single", "#")
        
        # Add comment prefix if not present
        if not text.strip().startswith(single_comment):
            text = f"{single_comment} {text.strip()}"
        
        # Add proper indentation
        indent = self._get_indentation_string(position.indentation_level, rules)
        return f"{indent}{text}"
    
    def _format_string(self, text: str, rules: LanguageRules) -> str:
        """Format text as a string literal."""
        # Escape quotes in the text
        preferred_delimiter = rules.string_delimiters[0] if rules.string_delimiters else '"'
        
        # Escape the preferred delimiter in the text
        escaped_text = text.replace(preferred_delimiter, f"\\{preferred_delimiter}")
        
        return f"{preferred_delimiter}{escaped_text}{preferred_delimiter}"
    
    def _format_function_definition(self, text: str, rules: LanguageRules, position: CodePosition) -> str:
        """Format text as a function definition."""
        # Apply naming conventions
        naming_style = rules.naming_conventions.get("functions", "snake_case")
        function_name = self._apply_naming_convention(text.strip(), naming_style)
        
        # Language-specific function definition format
        if position.language == LanguageType.PYTHON:
            return f"def {function_name}():"
        elif position.language in [LanguageType.JAVASCRIPT, LanguageType.TYPESCRIPT]:
            return f"function {function_name}() {{"
        elif position.language == LanguageType.JAVA:
            return f"public void {function_name}() {{"
        else:
            return function_name
    
    def _format_variable_assignment(self, text: str, rules: LanguageRules, position: CodePosition) -> str:
        """Format text as a variable assignment."""
        # Apply naming conventions
        naming_style = rules.naming_conventions.get("variables", "snake_case")
        variable_name = self._apply_naming_convention(text.strip(), naming_style)
        
        # Language-specific variable declaration
        if position.language == LanguageType.PYTHON:
            return f"{variable_name} = "
        elif position.language in [LanguageType.JAVASCRIPT, LanguageType.TYPESCRIPT]:
            return f"const {variable_name} = "
        elif position.language == LanguageType.JAVA:
            return f"String {variable_name} = "
        else:
            return f"{variable_name} = "
    
    def _format_general_code(self, text: str, rules: LanguageRules, position: CodePosition) -> str:
        """Format text as general code."""
        # Add proper indentation
        indent = self._get_indentation_string(position.indentation_level, rules)
        
        # Add statement terminator if needed
        if rules.statement_terminators and not any(text.strip().endswith(term) for term in rules.statement_terminators):
            text = text.strip() + rules.statement_terminators[0]
        
        return f"{indent}{text.strip()}"
    
    def _get_indentation_string(self, level: int, rules: LanguageRules) -> str:
        """Get indentation string for the given level."""
        if rules.indentation_style == "tabs":
            return "\t" * level
        else:
            return " " * (level * rules.indentation_size)
    
    def _apply_naming_convention(self, text: str, convention: str) -> str:
        """Apply naming convention to text."""
        # Remove non-alphanumeric characters and split into words
        words = re.findall(r'\w+', text.lower())
        
        if not words:
            return text
        
        if convention == "snake_case":
            return "_".join(words)
        elif convention == "camelCase":
            return words[0] + "".join(word.capitalize() for word in words[1:])
        elif convention == "PascalCase":
            return "".join(word.capitalize() for word in words)
        elif convention == "UPPER_SNAKE_CASE":
            return "_".join(word.upper() for word in words)
        elif convention == "kebab-case":
            return "-".join(words)
        else:
            return "_".join(words)  # Default to snake_case


def create_code_context_analyzer() -> SyntaxAnalyzer:
    """Factory function to create a code context analyzer."""
    return SyntaxAnalyzer()


def create_code_formatter() -> CodeFormatter:
    """Factory function to create a code formatter."""
    return CodeFormatter()