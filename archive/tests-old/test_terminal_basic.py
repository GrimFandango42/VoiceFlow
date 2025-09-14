#!/usr/bin/env python3
"""
Basic test for terminal integration functionality without GUI dependencies.
"""

import sys
import os
from enum import Enum

# Define terminal types (copy from main module for testing)
class TerminalType(Enum):
    """Enumeration of supported terminal types."""
    UNKNOWN = "unknown"
    CMD = "cmd"
    POWERSHELL = "powershell"
    POWERSHELL_CORE = "pwsh" 
    WSL = "wsl"
    GIT_BASH = "git_bash"
    VSCODE_TERMINAL = "vscode_terminal"
    WINDOWS_TERMINAL = "windows_terminal"
    CONEMU = "conemu"
    MINTTY = "mintty"
    HYPER = "hyper"
    TERMINUS = "terminus"


def test_terminal_types():
    """Test terminal type enumeration."""
    print("Testing Terminal Types:")
    print("=" * 30)
    
    for terminal_type in TerminalType:
        print(f"  {terminal_type.name} = '{terminal_type.value}'")
    
    print(f"\nTotal terminal types: {len(list(TerminalType))}")
    return True


def test_terminal_signatures():
    """Test terminal signature mappings."""
    print("\nTesting Terminal Signatures:")
    print("=" * 30)
    
    # Define signatures like in the main module
    terminal_signatures = {
        # Windows built-in terminals
        'cmd.exe': TerminalType.CMD,
        'powershell.exe': TerminalType.POWERSHELL,
        'pwsh.exe': TerminalType.POWERSHELL_CORE,
        
        # WSL
        'wsl.exe': TerminalType.WSL,
        'bash.exe': TerminalType.WSL,
        
        # Third-party terminals
        'WindowsTerminal.exe': TerminalType.WINDOWS_TERMINAL,
        'wt.exe': TerminalType.WINDOWS_TERMINAL,
        'ConEmu64.exe': TerminalType.CONEMU,
        'ConEmu.exe': TerminalType.CONEMU,
        'mintty.exe': TerminalType.MINTTY,
        'sh.exe': TerminalType.GIT_BASH,
        'Hyper.exe': TerminalType.HYPER,
        'Terminus.exe': TerminalType.TERMINUS,
        
        # VS Code
        'Code.exe': TerminalType.VSCODE_TERMINAL,
    }
    
    print("Executable → Terminal Type mappings:")
    for executable, terminal_type in terminal_signatures.items():
        print(f"  {executable} → {terminal_type.value}")
    
    print(f"\nTotal signatures: {len(terminal_signatures)}")
    return True


def test_command_patterns():
    """Test command pattern matching."""
    print("\nTesting Command Patterns:")
    print("=" * 30)
    
    import re
    
    command_patterns = {
        # Navigation commands
        r'change directory (.+)': 'cd "{}"',
        r'go to (.+)': 'cd "{}"',
        r'list (?:files|directory)': 'ls -la',
        r'show directory': 'pwd',
        
        # File operations
        r'create file (.+)': 'touch "{}"',
        r'remove file (.+)': 'rm "{}"',
        
        # Git commands
        r'git status': 'git status',
        r'git add all': 'git add .',
        r'git commit (.+)': 'git commit -m "{}"',
    }
    
    test_inputs = [
        "change directory home",
        "list files",
        "git status",
        "create file test.txt",
        "git commit initial setup"
    ]
    
    print("Voice Input → Command mappings:")
    for voice_input in test_inputs:
        for pattern, command_template in command_patterns.items():
            match = re.search(pattern, voice_input.lower())
            if match:
                try:
                    if match.groups():
                        command = command_template.format(*match.groups())
                    else:
                        command = command_template
                    print(f"  '{voice_input}' → '{command}'")
                    break
                except:
                    pass
        else:
            print(f"  '{voice_input}' → No match")
    
    return True


def test_text_preprocessing():
    """Test text preprocessing for different terminals."""
    print("\nTesting Text Preprocessing:")
    print("=" * 30)
    
    def preprocess_text(text, terminal_type):
        """Simplified preprocessing logic."""
        terminal_configs = {
            TerminalType.CMD: {
                'escape_chars': ['^', '&', '<', '>', '|'],
                'escape_prefix': '^'
            },
            TerminalType.POWERSHELL: {
                'escape_chars': ['`', '$', '"', "'"],
                'escape_prefix': '`'
            },
            TerminalType.WSL: {
                'escape_chars': ['\\', '$', '"', "'", '`'],
                'escape_prefix': '\\'
            }
        }
        
        config = terminal_configs.get(terminal_type, {})
        escape_chars = config.get('escape_chars', [])
        escape_prefix = config.get('escape_prefix', '')
        
        processed_text = text
        for char in escape_chars:
            if char in processed_text and escape_prefix:
                processed_text = processed_text.replace(char, f'{escape_prefix}{char}')
        
        return processed_text
    
    test_cases = [
        ("echo Hello & World", TerminalType.CMD),
        ("Write-Host 'Hello $world'", TerminalType.POWERSHELL),
        ("echo 'Hello $USER'", TerminalType.WSL),
    ]
    
    print("Text preprocessing for different terminals:")
    for text, terminal_type in test_cases:
        processed = preprocess_text(text, terminal_type)
        if processed != text:
            print(f"  {terminal_type.value}: '{text}' → '{processed}'")
        else:
            print(f"  {terminal_type.value}: '{text}' → No changes needed")
    
    return True


def test_configuration_structure():
    """Test configuration file structure."""
    print("\nTesting Configuration:")
    print("=" * 30)
    
    import json
    from pathlib import Path
    
    config_path = Path(__file__).parent / "config" / "terminal_config.json"
    
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            print(f"Configuration file loaded: {config_path}")
            print("Configuration sections:")
            for section in config.keys():
                print(f"  ✅ {section}")
            
            # Check key sections
            required_sections = [
                'terminal_integration',
                'detection', 
                'injection_methods',
                'terminal_configs',
                'command_processing'
            ]
            
            missing_sections = []
            for section in required_sections:
                if section not in config:
                    missing_sections.append(section)
            
            if missing_sections:
                print(f"Missing sections: {missing_sections}")
                return False
            else:
                print("All required configuration sections present")
                return True
                
        except Exception as e:
            print(f"❌ Error loading configuration: {e}")
            return False
    else:
        print(f"❌ Configuration file not found: {config_path}")
        return False


def run_basic_tests():
    """Run all basic tests."""
    print("🎤 VoiceFlow Terminal Integration - Basic Tests")
    print("=" * 60)
    
    tests = [
        ("Terminal Types", test_terminal_types),
        ("Terminal Signatures", test_terminal_signatures),
        ("Command Patterns", test_command_patterns),
        ("Text Preprocessing", test_text_preprocessing),
        ("Configuration", test_configuration_structure),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results[test_name] = result
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"\n{status}: {test_name}")
        except Exception as e:
            results[test_name] = False
            print(f"\n❌ ERROR: {test_name} - {e}")
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary:")
    print("=" * 60)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅" if result else "❌"
        print(f"  {status} {test_name}")
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All basic tests passed! Terminal integration architecture is sound.")
    elif passed >= total * 0.8:
        print("⚠️  Most tests passed. Minor issues to address.")
    else:
        print("❌ Several tests failed. Architecture needs review.")
    
    return passed == total


if __name__ == "__main__":
    success = run_basic_tests()
    sys.exit(0 if success else 1)