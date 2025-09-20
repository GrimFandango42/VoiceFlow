#!/usr/bin/env python3
"""
Static Analysis Testing Expert
Uses static analysis to catch issues without running code.
"""

import pytest
import ast
import inspect
from pathlib import Path
from typing import List, Dict, Any


class FunctionCallAnalyzer(ast.NodeVisitor):
    """AST visitor to analyze function calls."""
    
    def __init__(self):
        self.function_calls = []
        self.imports = {}
    
    def visit_Import(self, node):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        for alias in node.names:
            full_name = f"{node.module}.{alias.name}" if node.module else alias.name
            self.imports[alias.asname or alias.name] = full_name
        self.generic_visit(node)
    
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            args = []
            
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    args.append(arg.id)
                elif isinstance(arg, ast.Attribute):
                    args.append(f"{arg.value.id}.{arg.attr}" if isinstance(arg.value, ast.Name) else "unknown")
                else:
                    args.append("unknown")
            
            self.function_calls.append({
                'function': func_name,
                'args': args,
                'line': node.lineno
            })
        
        self.generic_visit(node)


class TestStaticAnalysis:
    """Static analysis tests to catch issues before runtime."""
    
    def test_function_call_patterns(self):
        """Test function call patterns in source files."""
        source_files = [
            Path(__file__).parent.parent.parent / "voiceflow_simple.py",
            Path(__file__).parent.parent.parent / "voiceflow_tray_integrated.py",
        ]
        
        issues = []
        
        for source_file in source_files:
            if not source_file.exists():
                continue
                
            try:
                with open(source_file, 'r', encoding='utf-8') as f:
                    source = f.read()
                
                tree = ast.parse(source)
                analyzer = FunctionCallAnalyzer()
                analyzer.visit(tree)
                
                # Check for create_audio_recorder calls
                for call in analyzer.function_calls:
                    if call['function'] == 'create_audio_recorder':
                        args = call['args']
                        
                        # First arg should be config-like, second should be string-like
                        if len(args) >= 2:
                            first_arg = args[0]
                            second_arg = args[1]
                            
                            # Pattern: create_audio_recorder(config, config.audio_recorder_type)
                            # First arg should be 'config' or similar
                            # Second arg should be 'config.audio_recorder_type' or similar
                            
                            if not (first_arg == 'config' or first_arg == 'voiceflow_config'):
                                issues.append(f"{source_file.name}:{call['line']} - "
                                            f"create_audio_recorder first arg should be config, got {first_arg}")
                            
                            if not ('audio_recorder_type' in second_arg):
                                issues.append(f"{source_file.name}:{call['line']} - "
                                            f"create_audio_recorder second arg should be recorder type, got {second_arg}")
                
                # Check for create_transcription_engine calls
                for call in analyzer.function_calls:
                    if call['function'] == 'create_transcription_engine':
                        args = call['args']
                        
                        if len(args) >= 2:
                            first_arg = args[0]
                            second_arg = args[1]
                            
                            if not (first_arg == 'config' or first_arg == 'voiceflow_config'):
                                issues.append(f"{source_file.name}:{call['line']} - "
                                            f"create_transcription_engine first arg should be config, got {first_arg}")
                            
                            if not ('transcription_engine_type' in second_arg):
                                issues.append(f"{source_file.name}:{call['line']} - "
                                            f"create_transcription_engine second arg should be engine type, got {second_arg}")
                
            except Exception as e:
                issues.append(f"Failed to analyze {source_file.name}: {e}")
        
        if issues:
            pytest.fail(f"Static analysis found issues:\n" + "\n".join(issues))
    
    def test_import_patterns(self):
        """Test import patterns for consistency."""
        source_files = [
            Path(__file__).parent.parent.parent / "voiceflow_simple.py",
            Path(__file__).parent.parent.parent / "voiceflow_tray_integrated.py",
        ]
        
        issues = []
        
        for source_file in source_files:
            if not source_file.exists():
                continue
                
            try:
                with open(source_file, 'r', encoding='utf-8') as f:
                    source = f.read()
                
                tree = ast.parse(source)
                analyzer = FunctionCallAnalyzer()
                analyzer.visit(tree)
                
                # Check that required functions are imported
                required_imports = [
                    'create_audio_recorder',
                    'create_transcription_engine',
                    'VoiceFlowConfig'
                ]
                
                available_names = set(analyzer.imports.keys())
                
                for required in required_imports:
                    if required not in available_names:
                        # Check if it's imported with a different name or from a module
                        found = False
                        for name, full_name in analyzer.imports.items():
                            if required in full_name or required == name:
                                found = True
                                break
                        
                        if not found:
                            issues.append(f"{source_file.name} - Missing import: {required}")
                
            except Exception as e:
                issues.append(f"Failed to analyze imports in {source_file.name}: {e}")
        
        if issues:
            pytest.fail(f"Import analysis found issues:\n" + "\n".join(issues))


class TestTypeHintAnalysis:
    """Analyze type hints for consistency."""
    
    def test_function_signature_consistency(self):
        """Test that function signatures are consistent with their usage."""
        try:
            from voiceflow.core.audio import create_audio_recorder
            from voiceflow.core.transcription import create_transcription_engine
            
            # Get function signatures
            audio_sig = inspect.signature(create_audio_recorder)
            transcription_sig = inspect.signature(create_transcription_engine)
            
            issues = []
            
            # Check create_audio_recorder signature
            audio_params = list(audio_sig.parameters.keys())
            if len(audio_params) < 2:
                issues.append("create_audio_recorder should have at least 2 parameters")
            elif audio_params[0] != 'config':
                issues.append(f"create_audio_recorder first parameter should be 'config', got '{audio_params[0]}'")
            
            # Check create_transcription_engine signature
            transcription_params = list(transcription_sig.parameters.keys())
            if len(transcription_params) < 2:
                issues.append("create_transcription_engine should have at least 2 parameters")
            elif transcription_params[0] != 'config':
                issues.append(f"create_transcription_engine first parameter should be 'config', got '{transcription_params[0]}'")
            
            if issues:
                pytest.fail(f"Function signature issues:\n" + "\n".join(issues))
                
        except ImportError as e:
            pytest.skip(f"Could not import functions for analysis: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])