#!/usr/bin/env python3
"""
VoiceFlow Terminal Integration Demo

Demonstrates the terminal integration capabilities of VoiceFlow including:
- Terminal detection across different types
- Smart text injection with fallback methods
- Voice command processing for terminal environments
- VS Code integration for development workflows

Usage:
    python demo_terminal_integration.py
"""

import sys
import time
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from core.terminal_integration import (
        create_terminal_injector, TerminalDetector, TerminalType,
        test_terminal_detection, test_text_injection
    )
    from core.vscode_terminal_api import create_vscode_terminal_integration
    TERMINAL_INTEGRATION_AVAILABLE = True
except ImportError as e:
    print(f"❌ Terminal integration not available: {e}")
    TERMINAL_INTEGRATION_AVAILABLE = False


def print_banner():
    """Print demo banner."""
    print("=" * 60)
    print("🎤 VoiceFlow Terminal Integration Demo")
    print("=" * 60)
    print()


def demonstrate_terminal_detection():
    """Demonstrate terminal detection capabilities."""
    print("📡 Terminal Detection Demo")
    print("-" * 30)
    
    if not TERMINAL_INTEGRATION_AVAILABLE:
        print("❌ Terminal integration not available")
        return False
    
    detector = TerminalDetector()
    
    # Get current window info
    window_info = detector.get_active_window_info()
    if window_info:
        print(f"Active Window:")
        print(f"  Title: {window_info.get('title', 'Unknown')}")
        print(f"  Executable: {window_info.get('executable', 'Unknown')}")
        print(f"  Class: {window_info.get('class', 'Unknown')}")
        print()
    
    # Detect terminal type
    terminal_type, metadata = detector.detect_terminal_type(window_info)
    
    print(f"Terminal Detection Result:")
    print(f"  Type: {terminal_type.value}")
    print(f"  Detection Method: {metadata.get('detection_method', 'unknown')}")
    print(f"  Confidence: {'High' if metadata.get('detection_method') == 'executable' else 'Medium'}")
    print()
    
    # Show terminal capabilities
    if terminal_type != TerminalType.UNKNOWN:
        print(f"✅ Terminal detected: {terminal_type.value}")
        return True
    else:
        print("⚠️  No terminal detected or unknown terminal type")
        return False


def demonstrate_command_processing():
    """Demonstrate voice command processing."""
    print("🗣️  Voice Command Processing Demo")
    print("-" * 30)
    
    if not TERMINAL_INTEGRATION_AVAILABLE:
        print("❌ Terminal integration not available")
        return
    
    from core.terminal_integration import TerminalCommandProcessor
    
    processor = TerminalCommandProcessor()
    
    # Test various voice commands
    test_commands = [
        "list files",
        "change directory home",
        "git status",
        "create file test.txt",
        "show directory",
        "git add all",
        "git commit initial setup",
        "remove file temp.log"
    ]
    
    print("Testing voice command processing:")
    print()
    
    for voice_input in test_commands:
        # Test for different terminal types
        for terminal_type in [TerminalType.CMD, TerminalType.WSL, TerminalType.POWERSHELL]:
            processed = processor.process_voice_command(voice_input, terminal_type)
            if processed != voice_input:  # Command was processed
                print(f"  '{voice_input}' → '{processed}' ({terminal_type.value})")
                break
        else:
            print(f"  '{voice_input}' → No processing needed")
    
    print()


def demonstrate_text_injection():
    """Demonstrate text injection capabilities."""
    print("💉 Text Injection Demo")
    print("-" * 30)
    
    if not TERMINAL_INTEGRATION_AVAILABLE:
        print("❌ Terminal integration not available")
        return False
    
    injector = create_terminal_injector()
    
    # Test different types of text
    test_texts = [
        "echo 'Hello from VoiceFlow!'",
        "ls -la",
        "pwd",
        "# This is a comment",
        "git status"
    ]
    
    print("Testing text injection methods:")
    print("(Note: This will actually type into your active terminal)")
    print()
    
    proceed = input("Proceed with injection test? (y/N): ").lower().strip()
    if proceed != 'y':
        print("Skipping injection test")
        return False
    
    print("Starting injection test in 3 seconds...")
    time.sleep(3)
    
    for i, test_text in enumerate(test_texts):
        print(f"  Injecting: '{test_text}'")
        success = injector.inject_enhanced_text(test_text, enable_command_processing=True)
        
        if success:
            print(f"    ✅ Success")
        else:
            print(f"    ❌ Failed")
        
        # Small delay between injections
        time.sleep(1)
    
    # Show statistics
    stats = injector.get_statistics()
    print()
    print("Injection Statistics:")
    print(f"  Total attempts: {stats['total_injections']}")
    print(f"  Successful: {stats['successful_injections']}")
    print(f"  Failed: {stats['failed_injections']}")
    print(f"  Success rate: {stats['success_rate_percent']}%")
    print()
    
    return stats['successful_injections'] > 0


def demonstrate_vscode_integration():
    """Demonstrate VS Code terminal integration."""
    print("🔷 VS Code Integration Demo")
    print("-" * 30)
    
    if not TERMINAL_INTEGRATION_AVAILABLE:
        print("❌ Terminal integration not available")
        return False
    
    try:
        vscode_integration = create_vscode_terminal_integration()
    except:
        print("❌ VS Code integration not available")
        return False
    
    # Get integration info
    info = vscode_integration.get_integration_info()
    
    print("VS Code Status:")
    print(f"  VS Code running: {info['vscode_running']}")
    print(f"  VS Code processes: {len(info['vscode_processes'])}")
    print(f"  Active terminals: {info['active_terminals']}")
    print()
    
    if info['vscode_processes']:
        print("VS Code Processes:")
        for proc in info['vscode_processes'][:3]:  # Show first 3
            print(f"  PID {proc['pid']}: {proc['name']}")
        print()
    
    if info['terminal_windows']:
        print("VS Code Terminal Windows:")
        for term in info['terminal_windows'][:3]:  # Show first 3
            print(f"  {term['title']} ({term['terminal_type']})")
        print()
    
    # Show injection methods status
    methods = info['injection_methods']
    print("Available Injection Methods:")
    for method, available in methods.items():
        if method not in ['vscode_processes', 'terminal_windows']:
            status = "✅" if available else "❌"
            print(f"  {status} {method}")
    print()
    
    # Diagnose integration
    diagnosis = vscode_integration.diagnose_integration()
    print(f"Integration Status: {diagnosis['status'].upper()}")
    
    if diagnosis['issues']:
        print("Issues:")
        for issue in diagnosis['issues']:
            print(f"  ⚠️  {issue}")
    
    if diagnosis['recommendations']:
        print("Recommendations:")
        for rec in diagnosis['recommendations']:
            print(f"  💡 {rec}")
    
    print()
    return info['vscode_running']


def demonstrate_configuration():
    """Demonstrate configuration capabilities."""
    print("⚙️  Configuration Demo")
    print("-" * 30)
    
    config_path = Path(__file__).parent / "config" / "terminal_config.json"
    
    if config_path.exists():
        print(f"Configuration file: {config_path}")
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            print("Configuration sections:")
            for section in config.keys():
                print(f"  📋 {section}")
            
            print()
            print("Terminal Integration Settings:")
            terminal_config = config.get('terminal_integration', {})
            print(f"  Enabled: {terminal_config.get('enabled', False)}")
            print(f"  Version: {terminal_config.get('version', 'unknown')}")
            
            priority_order = terminal_config.get('priority_order', [])
            if priority_order:
                print(f"  Injection Priority:")
                for i, method in enumerate(priority_order, 1):
                    print(f"    {i}. {method}")
            
        except Exception as e:
            print(f"❌ Error loading configuration: {e}")
    else:
        print(f"❌ Configuration file not found: {config_path}")
    
    print()


def run_comprehensive_demo():
    """Run comprehensive demo of all features."""
    print_banner()
    
    # Check availability
    if not TERMINAL_INTEGRATION_AVAILABLE:
        print("❌ Terminal integration is not available.")
        print("Please install required dependencies:")
        print("  - pyautogui")
        print("  - keyboard") 
        print("  - win32api (Windows only)")
        print("  - psutil")
        return False
    
    # Run demonstrations
    demo_results = {}
    
    print("🚀 Running comprehensive terminal integration demo...\n")
    
    # 1. Terminal Detection
    demo_results['detection'] = demonstrate_terminal_detection()
    print()
    
    # 2. Command Processing
    demonstrate_command_processing()
    
    # 3. Configuration
    demonstrate_configuration()
    
    # 4. VS Code Integration
    demo_results['vscode'] = demonstrate_vscode_integration()
    
    # 5. Text Injection (optional)
    demo_results['injection'] = demonstrate_text_injection()
    
    # Summary
    print("📊 Demo Summary")
    print("-" * 30)
    print(f"Terminal Detection: {'✅ Working' if demo_results.get('detection') else '❌ Not detected'}")
    print(f"VS Code Integration: {'✅ Available' if demo_results.get('vscode') else '❌ Not available'}")
    print(f"Text Injection: {'✅ Working' if demo_results.get('injection') else '❌ Not tested'}")
    print()
    
    # Success criteria
    working_features = sum(demo_results.values())
    total_features = len(demo_results)
    
    if working_features >= 2:
        print("🎉 Terminal integration is working well!")
        print("VoiceFlow should work effectively in terminal environments.")
    elif working_features >= 1:
        print("⚠️  Terminal integration is partially working.")
        print("Some features available, but optimal experience may require additional setup.")
    else:
        print("❌ Terminal integration needs setup.")
        print("Please check dependencies and environment configuration.")
    
    print()
    print("For more information, see the documentation at:")
    print("https://github.com/voiceflow/terminal-integration")
    print()
    
    return working_features > 0


def main():
    """Main demo entry point."""
    try:
        success = run_comprehensive_demo()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
        return 0
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())