"""
Code Template and Snippet Generation System

Intelligent code template and snippet generation for voice-driven development.
Supports multiple programming languages with context-aware template selection,
variable extraction, and smart placeholder filling.
"""

import re
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

try:
    from .code_context_analyzer import LanguageType, CodeContextType, LanguageRulesProvider
    CODE_CONTEXT_AVAILABLE = True
except ImportError:
    CODE_CONTEXT_AVAILABLE = False


class TemplateType(Enum):
    """Types of code templates."""
    FUNCTION = "function"
    CLASS = "class"
    METHOD = "method"
    VARIABLE = "variable"
    LOOP = "loop"
    CONDITIONAL = "conditional"
    EXCEPTION_HANDLING = "exception"
    IMPORT = "import"
    COMMENT = "comment"
    DOCSTRING = "docstring"
    TEST = "test"
    MAIN = "main"
    INTERFACE = "interface"
    ENUM = "enum"
    STRUCT = "struct"
    DECORATOR = "decorator"
    ASYNC_FUNCTION = "async_function"
    PROPERTY = "property"


@dataclass
class TemplateVariable:
    """Template variable placeholder."""
    name: str
    default_value: str = ""
    description: str = ""
    type_hint: Optional[str] = None
    choices: List[str] = field(default_factory=list)
    required: bool = True


@dataclass
class CodeTemplate:
    """Code template definition."""
    name: str
    template_type: TemplateType
    language: LanguageType
    template: str
    description: str = ""
    variables: List[TemplateVariable] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)  # Voice triggers
    context_requirements: List[CodeContextType] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)


@dataclass
class GeneratedCode:
    """Generated code result."""
    code: str
    template_name: str
    variables_used: Dict[str, str]
    cursor_position: Optional[Tuple[int, int]] = None  # Line, column
    selections: List[Tuple[int, int, int, int]] = field(default_factory=list)  # Start/end line/col


class TemplateVariableExtractor:
    """Extracts variables from voice input for template filling."""
    
    # Common variable patterns in speech
    VARIABLE_PATTERNS = {
        'variable_name': [
            r'(?:variable|var)\s+(?:called|named)?\s*([a-zA-Z_]\w*)',
            r'([a-zA-Z_]\w+)\s+(?:variable|var)',
            r'(?:set|create)\s+([a-zA-Z_]\w+)'
        ],
        'function_name': [
            r'(?:function|method|def)\s+(?:called|named)?\s*([a-zA-Z_]\w*)',
            r'([a-zA-Z_]\w+)\s+(?:function|method)',
            r'(?:create|define)\s+([a-zA-Z_]\w+)'
        ],
        'class_name': [
            r'(?:class)\s+(?:called|named)?\s*([a-zA-Z_]\w*)',
            r'([a-zA-Z_]\w+)\s+(?:class)',
            r'(?:create|define)\s+class\s+([a-zA-Z_]\w+)'
        ],
        'parameter': [
            r'(?:parameter|param|argument|arg)\s+([a-zA-Z_]\w*)',
            r'with\s+([a-zA-Z_]\w+)\s+(?:parameter|param)',
            r'takes\s+([a-zA-Z_]\w+)'
        ],
        'return_type': [
            r'returns?\s+([a-zA-Z_]\w*)',
            r'return\s+type\s+([a-zA-Z_]\w*)',
            r'gives?\s+(?:back\s+)?([a-zA-Z_]\w*)'
        ]
    }
    
    def extract_variables(self, voice_input: str, template: CodeTemplate) -> Dict[str, str]:
        """Extract template variables from voice input."""
        variables = {}
        voice_lower = voice_input.lower()
        
        for template_var in template.variables:
            value = self._extract_single_variable(voice_lower, template_var)
            if value:
                variables[template_var.name] = value
            elif template_var.default_value:
                variables[template_var.name] = template_var.default_value
        
        return variables
    
    def _extract_single_variable(self, voice_input: str, template_var: TemplateVariable) -> Optional[str]:
        """Extract a single variable from voice input."""
        # Try to find variable based on its name/type
        var_name = template_var.name.lower()
        
        # Look for specific patterns based on variable name
        if 'name' in var_name:
            if 'function' in var_name or 'method' in var_name:
                return self._extract_by_patterns(voice_input, self.VARIABLE_PATTERNS['function_name'])
            elif 'class' in var_name:
                return self._extract_by_patterns(voice_input, self.VARIABLE_PATTERNS['class_name'])
            elif 'variable' in var_name:
                return self._extract_by_patterns(voice_input, self.VARIABLE_PATTERNS['variable_name'])
        
        if 'parameter' in var_name or 'param' in var_name or 'arg' in var_name:
            return self._extract_by_patterns(voice_input, self.VARIABLE_PATTERNS['parameter'])
        
        if 'return' in var_name or 'type' in var_name:
            return self._extract_by_patterns(voice_input, self.VARIABLE_PATTERNS['return_type'])
        
        # Generic extraction - look for quoted strings or identifiers
        generic_patterns = [
            rf'{re.escape(var_name)}\s+([a-zA-Z_]\w*)',
            rf'([a-zA-Z_]\w+)\s+{re.escape(var_name)}',
            r'"([^"]+)"',
            r"'([^']+)'"
        ]
        
        return self._extract_by_patterns(voice_input, generic_patterns)
    
    def _extract_by_patterns(self, text: str, patterns: List[str]) -> Optional[str]:
        """Extract text using regex patterns."""
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None


class TemplateRepository:
    """Repository for storing and managing code templates."""
    
    def __init__(self):
        """Initialize template repository."""
        self.templates: Dict[str, Dict[str, List[CodeTemplate]]] = {}
        self._load_builtin_templates()
    
    def _load_builtin_templates(self):
        """Load built-in templates for common programming patterns."""
        # Python templates
        self._add_python_templates()
        
        # JavaScript templates
        self._add_javascript_templates()
        
        # Java templates
        self._add_java_templates()
        
        # C++ templates
        self._add_cpp_templates()
    
    def _add_python_templates(self):
        """Add Python-specific templates."""
        python_templates = [
            # Function template
            CodeTemplate(
                name="python_function",
                template_type=TemplateType.FUNCTION,
                language=LanguageType.PYTHON,
                template="""def ${function_name}(${parameters}):
    \"\"\"${description}\"\"\"
    ${body}
    return ${return_value}""",
                description="Python function with docstring",
                variables=[
                    TemplateVariable("function_name", "my_function", "Function name"),
                    TemplateVariable("parameters", "", "Function parameters"),
                    TemplateVariable("description", "Function description", "Function description"),
                    TemplateVariable("body", "pass", "Function body"),
                    TemplateVariable("return_value", "None", "Return value")
                ],
                triggers=["python function", "def function", "create function"],
                context_requirements=[CodeContextType.FUNCTION_DEF, CodeContextType.CODE]
            ),
            
            # Class template
            CodeTemplate(
                name="python_class",
                template_type=TemplateType.CLASS,
                language=LanguageType.PYTHON,
                template="""class ${class_name}:
    \"\"\"${description}\"\"\"
    
    def __init__(self${init_params}):
        \"\"\"Initialize ${class_name}.\"\"\"
        ${init_body}
    
    def ${method_name}(self):
        \"\"\"${method_description}\"\"\"
        ${method_body}""",
                description="Python class with constructor and method",
                variables=[
                    TemplateVariable("class_name", "MyClass", "Class name"),
                    TemplateVariable("description", "Class description", "Class description"),
                    TemplateVariable("init_params", "", "Constructor parameters"),
                    TemplateVariable("init_body", "pass", "Constructor body"),
                    TemplateVariable("method_name", "my_method", "Method name"),
                    TemplateVariable("method_description", "Method description", "Method description"),
                    TemplateVariable("method_body", "pass", "Method body")
                ],
                triggers=["python class", "create class", "class definition"],
                context_requirements=[CodeContextType.CLASS_DEF, CodeContextType.CODE]
            ),
            
            # For loop template
            CodeTemplate(
                name="python_for_loop",
                template_type=TemplateType.LOOP,
                language=LanguageType.PYTHON,
                template="""for ${item} in ${iterable}:
    ${body}""",
                description="Python for loop",
                variables=[
                    TemplateVariable("item", "item", "Loop variable"),
                    TemplateVariable("iterable", "items", "Iterable object"),
                    TemplateVariable("body", "pass", "Loop body")
                ],
                triggers=["for loop", "iterate over", "loop through"],
                context_requirements=[CodeContextType.CODE]
            ),
            
            # Try-except template
            CodeTemplate(
                name="python_try_except",
                template_type=TemplateType.EXCEPTION_HANDLING,
                language=LanguageType.PYTHON,
                template="""try:
    ${try_body}
except ${exception_type} as ${exception_var}:
    ${except_body}
finally:
    ${finally_body}""",
                description="Python try-except-finally block",
                variables=[
                    TemplateVariable("try_body", "pass", "Try block body"),
                    TemplateVariable("exception_type", "Exception", "Exception type"),
                    TemplateVariable("exception_var", "e", "Exception variable"),
                    TemplateVariable("except_body", "pass", "Exception handling body"),
                    TemplateVariable("finally_body", "pass", "Finally block body")
                ],
                triggers=["try except", "exception handling", "error handling"],
                context_requirements=[CodeContextType.CODE]
            ),
            
            # Main template
            CodeTemplate(
                name="python_main",
                template_type=TemplateType.MAIN,
                language=LanguageType.PYTHON,
                template="""def main():
    \"\"\"Main function.\"\"\"
    ${main_body}


if __name__ == "__main__":
    main()""",
                description="Python main function",
                variables=[
                    TemplateVariable("main_body", "pass", "Main function body")
                ],
                triggers=["main function", "if name main", "entry point"],
                context_requirements=[CodeContextType.CODE]
            )
        ]
        
        for template in python_templates:
            self.add_template(template)
    
    def _add_javascript_templates(self):
        """Add JavaScript-specific templates."""
        js_templates = [
            # Function template
            CodeTemplate(
                name="js_function",
                template_type=TemplateType.FUNCTION,
                language=LanguageType.JAVASCRIPT,
                template="""function ${function_name}(${parameters}) {
    ${body}
    return ${return_value};
}""",
                description="JavaScript function",
                variables=[
                    TemplateVariable("function_name", "myFunction", "Function name"),
                    TemplateVariable("parameters", "", "Function parameters"),
                    TemplateVariable("body", "// TODO: implement", "Function body"),
                    TemplateVariable("return_value", "undefined", "Return value")
                ],
                triggers=["javascript function", "js function", "function"],
                context_requirements=[CodeContextType.FUNCTION_DEF, CodeContextType.CODE]
            ),
            
            # Arrow function template
            CodeTemplate(
                name="js_arrow_function",
                template_type=TemplateType.FUNCTION,
                language=LanguageType.JAVASCRIPT,
                template="""const ${function_name} = (${parameters}) => {
    ${body}
    return ${return_value};
};""",
                description="JavaScript arrow function",
                variables=[
                    TemplateVariable("function_name", "myFunction", "Function name"),
                    TemplateVariable("parameters", "", "Function parameters"),
                    TemplateVariable("body", "// TODO: implement", "Function body"),
                    TemplateVariable("return_value", "undefined", "Return value")
                ],
                triggers=["arrow function", "lambda function", "fat arrow"],
                context_requirements=[CodeContextType.FUNCTION_DEF, CodeContextType.CODE]
            ),
            
            # Class template
            CodeTemplate(
                name="js_class",
                template_type=TemplateType.CLASS,
                language=LanguageType.JAVASCRIPT,
                template="""class ${class_name} {
    constructor(${constructor_params}) {
        ${constructor_body}
    }
    
    ${method_name}(${method_params}) {
        ${method_body}
        return ${method_return};
    }
}""",
                description="JavaScript class",
                variables=[
                    TemplateVariable("class_name", "MyClass", "Class name"),
                    TemplateVariable("constructor_params", "", "Constructor parameters"),
                    TemplateVariable("constructor_body", "// Initialize", "Constructor body"),
                    TemplateVariable("method_name", "myMethod", "Method name"),
                    TemplateVariable("method_params", "", "Method parameters"),
                    TemplateVariable("method_body", "// TODO: implement", "Method body"),
                    TemplateVariable("method_return", "undefined", "Method return value")
                ],
                triggers=["javascript class", "js class", "create class"],
                context_requirements=[CodeContextType.CLASS_DEF, CodeContextType.CODE]
            )
        ]
        
        for template in js_templates:
            self.add_template(template)
    
    def _add_java_templates(self):
        """Add Java-specific templates."""
        java_templates = [
            # Method template
            CodeTemplate(
                name="java_method",
                template_type=TemplateType.METHOD,
                language=LanguageType.JAVA,
                template="""public ${return_type} ${method_name}(${parameters}) {
    ${body}
    return ${return_value};
}""",
                description="Java method",
                variables=[
                    TemplateVariable("return_type", "void", "Return type"),
                    TemplateVariable("method_name", "myMethod", "Method name"),
                    TemplateVariable("parameters", "", "Method parameters"),
                    TemplateVariable("body", "// TODO: implement", "Method body"),
                    TemplateVariable("return_value", "null", "Return value")
                ],
                triggers=["java method", "public method", "method"],
                context_requirements=[CodeContextType.FUNCTION_DEF, CodeContextType.CODE]
            ),
            
            # Class template
            CodeTemplate(
                name="java_class",
                template_type=TemplateType.CLASS,
                language=LanguageType.JAVA,
                template="""public class ${class_name} {
    private ${field_type} ${field_name};
    
    public ${class_name}(${constructor_params}) {
        ${constructor_body}
    }
    
    public ${getter_return_type} get${getter_field_name}() {
        return ${field_name};
    }
    
    public void set${setter_field_name}(${setter_param_type} ${setter_param_name}) {
        this.${field_name} = ${setter_param_name};
    }
}""",
                description="Java class with constructor and getter/setter",
                variables=[
                    TemplateVariable("class_name", "MyClass", "Class name"),
                    TemplateVariable("field_type", "String", "Field type"),
                    TemplateVariable("field_name", "value", "Field name"),
                    TemplateVariable("constructor_params", "", "Constructor parameters"),
                    TemplateVariable("constructor_body", "// Initialize", "Constructor body"),
                    TemplateVariable("getter_return_type", "String", "Getter return type"),
                    TemplateVariable("getter_field_name", "Value", "Getter field name"),
                    TemplateVariable("setter_field_name", "Value", "Setter field name"),
                    TemplateVariable("setter_param_type", "String", "Setter parameter type"),
                    TemplateVariable("setter_param_name", "value", "Setter parameter name")
                ],
                triggers=["java class", "create class", "class with getters"],
                context_requirements=[CodeContextType.CLASS_DEF, CodeContextType.CODE]
            )
        ]
        
        for template in java_templates:
            self.add_template(template)
    
    def _add_cpp_templates(self):
        """Add C++ specific templates."""
        cpp_templates = [
            # Function template
            CodeTemplate(
                name="cpp_function",
                template_type=TemplateType.FUNCTION,
                language=LanguageType.CPP,
                template="""${return_type} ${function_name}(${parameters}) {
    ${body}
    return ${return_value};
}""",
                description="C++ function",
                variables=[
                    TemplateVariable("return_type", "void", "Return type"),
                    TemplateVariable("function_name", "myFunction", "Function name"),
                    TemplateVariable("parameters", "", "Function parameters"),
                    TemplateVariable("body", "// TODO: implement", "Function body"),
                    TemplateVariable("return_value", "0", "Return value")
                ],
                triggers=["cpp function", "c++ function", "function"],
                context_requirements=[CodeContextType.FUNCTION_DEF, CodeContextType.CODE]
            ),
            
            # Class template
            CodeTemplate(
                name="cpp_class",
                template_type=TemplateType.CLASS,
                language=LanguageType.CPP,
                template="""class ${class_name} {
private:
    ${private_members}

public:
    ${class_name}(${constructor_params});
    ~${class_name}();
    
    ${method_return_type} ${method_name}(${method_params});
    
private:
    ${private_methods}
};""",
                description="C++ class declaration",
                variables=[
                    TemplateVariable("class_name", "MyClass", "Class name"),
                    TemplateVariable("private_members", "// Private members", "Private member variables"),
                    TemplateVariable("constructor_params", "", "Constructor parameters"),
                    TemplateVariable("method_return_type", "void", "Method return type"),
                    TemplateVariable("method_name", "myMethod", "Method name"),
                    TemplateVariable("method_params", "", "Method parameters"),
                    TemplateVariable("private_methods", "// Private methods", "Private methods")
                ],
                triggers=["cpp class", "c++ class", "create class"],
                context_requirements=[CodeContextType.CLASS_DEF, CodeContextType.CODE]
            )
        ]
        
        for template in cpp_templates:
            self.add_template(template)
    
    def add_template(self, template: CodeTemplate):
        """Add a template to the repository."""
        language = template.language.value
        template_type = template.template_type.value
        
        if language not in self.templates:
            self.templates[language] = {}
        
        if template_type not in self.templates[language]:
            self.templates[language][template_type] = []
        
        self.templates[language][template_type].append(template)
    
    def find_templates(self, language: LanguageType, 
                      template_type: Optional[TemplateType] = None,
                      voice_trigger: Optional[str] = None) -> List[CodeTemplate]:
        """Find templates matching criteria."""
        language_templates = self.templates.get(language.value, {})
        
        if template_type:
            templates = language_templates.get(template_type.value, [])
        else:
            # Get all templates for the language
            templates = []
            for template_list in language_templates.values():
                templates.extend(template_list)
        
        # Filter by voice trigger if provided
        if voice_trigger:
            voice_lower = voice_trigger.lower()
            filtered_templates = []
            for template in templates:
                for trigger in template.triggers:
                    if trigger.lower() in voice_lower or voice_lower in trigger.lower():
                        filtered_templates.append(template)
                        break
            return filtered_templates
        
        return templates
    
    def get_template_by_name(self, name: str) -> Optional[CodeTemplate]:
        """Get template by name."""
        for language_templates in self.templates.values():
            for template_list in language_templates.values():
                for template in template_list:
                    if template.name == name:
                        return template
        return None
    
    def get_all_templates(self) -> List[CodeTemplate]:
        """Get all templates."""
        all_templates = []
        for language_templates in self.templates.values():
            for template_list in language_templates.values():
                all_templates.extend(template_list)
        return all_templates


class TemplateEngine:
    """Template processing and code generation engine."""
    
    def __init__(self):
        """Initialize template engine."""
        self.repository = TemplateRepository()
        self.variable_extractor = TemplateVariableExtractor()
        self.rules_provider = LanguageRulesProvider() if CODE_CONTEXT_AVAILABLE else None
    
    def generate_code(self, voice_input: str, language: LanguageType, 
                     context: Optional[CodeContextType] = None,
                     template_name: Optional[str] = None) -> Optional[GeneratedCode]:
        """Generate code from voice input."""
        
        # Find suitable template
        if template_name:
            template = self.repository.get_template_by_name(template_name)
            if not template:
                print(f"[TEMPLATES] Template '{template_name}' not found")
                return None
        else:
            templates = self._find_matching_templates(voice_input, language, context)
            if not templates:
                print(f"[TEMPLATES] No matching templates found for: {voice_input}")
                return None
            template = templates[0]  # Use best match
        
        # Extract variables from voice input
        variables = self.variable_extractor.extract_variables(voice_input, template)
        
        # Apply naming conventions
        variables = self._apply_naming_conventions(variables, language)
        
        # Generate code
        code = self._fill_template(template.template, variables)
        
        # Determine cursor position and selections
        cursor_pos, selections = self._find_cursor_and_selections(code)
        
        return GeneratedCode(
            code=code,
            template_name=template.name,
            variables_used=variables,
            cursor_position=cursor_pos,
            selections=selections
        )
    
    def _find_matching_templates(self, voice_input: str, language: LanguageType,
                               context: Optional[CodeContextType]) -> List[CodeTemplate]:
        """Find templates matching voice input and context."""
        # First try to find by voice trigger
        templates = self.repository.find_templates(language, voice_trigger=voice_input)
        
        if not templates and context:
            # Try to find by template type based on context
            template_type_map = {
                CodeContextType.FUNCTION_DEF: TemplateType.FUNCTION,
                CodeContextType.CLASS_DEF: TemplateType.CLASS,
                CodeContextType.VARIABLE: TemplateType.VARIABLE,
                CodeContextType.COMMENT: TemplateType.COMMENT
            }
            
            template_type = template_type_map.get(context)
            if template_type:
                templates = self.repository.find_templates(language, template_type)
        
        if not templates:
            # Fallback: get all templates for the language
            templates = self.repository.find_templates(language)
        
        # Score and sort templates
        scored_templates = []
        for template in templates:
            score = self._score_template_match(voice_input, template, context)
            scored_templates.append((score, template))
        
        scored_templates.sort(key=lambda x: x[0], reverse=True)
        return [template for score, template in scored_templates if score > 0]
    
    def _score_template_match(self, voice_input: str, template: CodeTemplate,
                            context: Optional[CodeContextType]) -> float:
        """Score how well a template matches the voice input and context."""
        score = 0.0
        voice_lower = voice_input.lower()
        
        # Check trigger matches
        for trigger in template.triggers:
            if trigger.lower() in voice_lower:
                score += 10.0
            elif any(word in voice_lower for word in trigger.lower().split()):
                score += 5.0
        
        # Check context requirements
        if context and context in template.context_requirements:
            score += 8.0
        
        # Check for template type keywords in voice input
        type_keywords = {
            TemplateType.FUNCTION: ['function', 'method', 'def'],
            TemplateType.CLASS: ['class'],
            TemplateType.LOOP: ['loop', 'for', 'while', 'iterate'],
            TemplateType.CONDITIONAL: ['if', 'condition', 'check'],
            TemplateType.EXCEPTION_HANDLING: ['try', 'catch', 'exception', 'error'],
            TemplateType.IMPORT: ['import', 'include', 'require'],
            TemplateType.COMMENT: ['comment', 'note', 'explain'],
            TemplateType.TEST: ['test', 'unit test', 'assert']
        }
        
        keywords = type_keywords.get(template.template_type, [])
        for keyword in keywords:
            if keyword in voice_lower:
                score += 3.0
        
        return score
    
    def _apply_naming_conventions(self, variables: Dict[str, str], 
                                language: LanguageType) -> Dict[str, str]:
        """Apply language-specific naming conventions to variables."""
        if not self.rules_provider:
            return variables
        
        rules = self.rules_provider.get_rules(language)
        conventions = rules.naming_conventions
        
        for var_name, value in variables.items():
            if not value:
                continue
            
            # Apply naming convention based on variable type
            if 'function' in var_name or 'method' in var_name:
                convention = conventions.get('functions', 'snake_case')
                variables[var_name] = self._apply_naming_convention(value, convention)
            elif 'class' in var_name:
                convention = conventions.get('classes', 'PascalCase')
                variables[var_name] = self._apply_naming_convention(value, convention)
            elif 'variable' in var_name or 'field' in var_name:
                convention = conventions.get('variables', 'snake_case')
                variables[var_name] = self._apply_naming_convention(value, convention)
            elif 'constant' in var_name:
                convention = conventions.get('constants', 'UPPER_SNAKE_CASE')
                variables[var_name] = self._apply_naming_convention(value, convention)
        
        return variables
    
    def _apply_naming_convention(self, text: str, convention: str) -> str:
        """Apply specific naming convention to text."""
        # Clean and split text
        words = re.findall(r'\w+', text.lower())
        
        if not words:
            return text
        
        if convention == 'snake_case':
            return '_'.join(words)
        elif convention == 'camelCase':
            return words[0] + ''.join(word.capitalize() for word in words[1:])
        elif convention == 'PascalCase':
            return ''.join(word.capitalize() for word in words)
        elif convention == 'UPPER_SNAKE_CASE':
            return '_'.join(word.upper() for word in words)
        elif convention == 'kebab-case':
            return '-'.join(words)
        else:
            return '_'.join(words)  # Default to snake_case
    
    def _fill_template(self, template: str, variables: Dict[str, str]) -> str:
        """Fill template with variables."""
        result = template
        
        # Replace variable placeholders
        for var_name, value in variables.items():
            placeholder = f"${{{var_name}}}"
            result = result.replace(placeholder, value)
        
        # Handle any remaining placeholders with default values
        remaining_placeholders = re.findall(r'\$\{([^}]+)\}', result)
        for placeholder in remaining_placeholders:
            if ':' in placeholder:
                # Handle default values: ${var:default}
                var_name, default_value = placeholder.split(':', 1)
                result = result.replace(f"${{{placeholder}}}", default_value)
            else:
                # Remove empty placeholders
                result = result.replace(f"${{{placeholder}}}", f"TODO_{placeholder}")
        
        return result
    
    def _find_cursor_and_selections(self, code: str) -> Tuple[Optional[Tuple[int, int]], List[Tuple[int, int, int, int]]]:
        """Find cursor position and text selections in generated code."""
        lines = code.split('\n')
        cursor_pos = None
        selections = []
        
        # Look for cursor markers (|) and selection markers ([text])
        for line_idx, line in enumerate(lines):
            if '|' in line:
                col_idx = line.index('|')
                cursor_pos = (line_idx, col_idx)
                lines[line_idx] = line.replace('|', '')
            
            # Look for selection markers
            selection_matches = re.finditer(r'\[([^\]]+)\]', line)
            for match in selection_matches:
                start_col = match.start()
                end_col = match.end() - 2  # Adjust for brackets
                selections.append((line_idx, start_col, line_idx, end_col))
                lines[line_idx] = line.replace(match.group(0), match.group(1))
        
        # If no cursor position found, place at end of code
        if cursor_pos is None and lines:
            cursor_pos = (len(lines) - 1, len(lines[-1]))
        
        return cursor_pos, selections
    
    def get_available_templates(self, language: LanguageType) -> List[Dict[str, Any]]:
        """Get available templates for a language."""
        templates = self.repository.find_templates(language)
        
        return [
            {
                'name': template.name,
                'type': template.template_type.value,
                'description': template.description,
                'triggers': template.triggers,
                'variables': [
                    {
                        'name': var.name,
                        'description': var.description,
                        'default': var.default_value,
                        'required': var.required
                    }
                    for var in template.variables
                ]
            }
            for template in templates
        ]


class VoiceFlowTemplateIntegration:
    """Integration between VoiceFlow and template system."""
    
    def __init__(self):
        """Initialize template integration."""
        self.template_engine = TemplateEngine()
        self.enabled = True
        self.auto_apply = True
    
    def process_voice_input_for_templates(self, voice_input: str, language: LanguageType,
                                        context: Optional[CodeContextType] = None) -> Optional[GeneratedCode]:
        """Process voice input to generate code templates."""
        if not self.enabled:
            return None
        
        # Check if voice input seems like a template request
        template_indicators = [
            'create', 'generate', 'make', 'add', 'new', 'function', 'class', 
            'method', 'loop', 'if', 'try', 'catch', 'import', 'main'
        ]
        
        voice_lower = voice_input.lower()
        if not any(indicator in voice_lower for indicator in template_indicators):
            return None
        
        return self.template_engine.generate_code(voice_input, language, context)
    
    def get_template_suggestions(self, partial_input: str, language: LanguageType) -> List[Dict[str, Any]]:
        """Get template suggestions based on partial voice input."""
        templates = self.template_engine.repository.find_templates(language, voice_trigger=partial_input)
        
        return [
            {
                'name': template.name,
                'description': template.description,
                'triggers': template.triggers,
                'score': self.template_engine._score_template_match(partial_input, template, None)
            }
            for template in templates[:5]  # Top 5 suggestions
        ]
    
    def add_custom_template(self, template_data: Dict[str, Any]) -> bool:
        """Add a custom template from user input."""
        try:
            # Parse template data
            template = CodeTemplate(
                name=template_data['name'],
                template_type=TemplateType(template_data['type']),
                language=LanguageType(template_data['language']),
                template=template_data['template'],
                description=template_data.get('description', ''),
                variables=[
                    TemplateVariable(
                        name=var['name'],
                        default_value=var.get('default', ''),
                        description=var.get('description', ''),
                        required=var.get('required', True)
                    )
                    for var in template_data.get('variables', [])
                ],
                triggers=template_data.get('triggers', []),
                tags=template_data.get('tags', [])
            )
            
            self.template_engine.repository.add_template(template)
            return True
            
        except Exception as e:
            print(f"[TEMPLATES] Error adding custom template: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get template system status."""
        all_templates = self.template_engine.repository.get_all_templates()
        
        # Group by language
        language_counts = {}
        for template in all_templates:
            lang = template.language.value
            language_counts[lang] = language_counts.get(lang, 0) + 1
        
        return {
            'enabled': self.enabled,
            'auto_apply': self.auto_apply,
            'total_templates': len(all_templates),
            'templates_by_language': language_counts,
            'supported_languages': list(language_counts.keys())
        }


def create_template_integration() -> VoiceFlowTemplateIntegration:
    """Factory function to create template integration."""
    return VoiceFlowTemplateIntegration()