#!/usr/bin/env python3
"""
VoiceFlow Browser Integration CLI Utility

A command-line utility for testing and configuring browser integration features.
Allows users to test browser automation, text injection, and element detection.
"""

import argparse
import sys
import time
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

# VoiceFlow imports
try:
    from core.browser_integration import (
        BrowserIntegrationEngine, BrowserConfig, BrowserType,
        InputElementType, FrameworkType
    )
    from core.voiceflow_core import create_engine
    VOICEFLOW_AVAILABLE = True
except ImportError as e:
    print(f"Error: VoiceFlow core not available: {e}")
    print("Make sure you're running from the VoiceFlow directory")
    sys.exit(1)

try:
    from selenium.common.exceptions import WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("Warning: Selenium not available. Install with: pip install selenium webdriver-manager")


class BrowserIntegrationCLI:
    """Command-line interface for browser integration testing."""
    
    def __init__(self):
        self.engine = None
        self.browser_engine = None
        
    def create_test_html(self, output_path: str = "test_page.html"):
        """Create a test HTML page for browser integration testing."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>VoiceFlow Browser Integration Test Page</title>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .form-group { margin: 15px 0; }
                label { display: block; margin-bottom: 5px; font-weight: bold; }
                input, textarea { padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
                input[type="text"], input[type="email"], input[type="search"] { width: 300px; }
                textarea { width: 300px; height: 100px; }
                .contenteditable { 
                    border: 1px solid #ddd; 
                    padding: 10px; 
                    min-height: 50px; 
                    width: 300px;
                    background: #f9f9f9;
                }
                .status { 
                    margin: 20px 0; 
                    padding: 10px; 
                    background: #e7f3ff; 
                    border-radius: 4px; 
                }
                button { padding: 10px 20px; margin: 10px 5px 0 0; }
            </style>
        </head>
        <body>
            <h1>VoiceFlow Browser Integration Test Page</h1>
            <div class="status" id="status">Ready for testing...</div>
            
            <form id="test-form">
                <div class="form-group">
                    <label for="text-input">Text Input:</label>
                    <input type="text" id="text-input" name="text" placeholder="Enter text here">
                </div>
                
                <div class="form-group">
                    <label for="email-input">Email Input:</label>
                    <input type="email" id="email-input" name="email" placeholder="Enter email address">
                </div>
                
                <div class="form-group">
                    <label for="search-input">Search Input:</label>
                    <input type="search" id="search-input" name="search" placeholder="Search...">
                </div>
                
                <div class="form-group">
                    <label for="password-input">Password Input:</label>
                    <input type="password" id="password-input" name="password" placeholder="Enter password">
                </div>
                
                <div class="form-group">
                    <label for="textarea">Textarea:</label>
                    <textarea id="textarea" name="message" placeholder="Enter your message here..."></textarea>
                </div>
                
                <div class="form-group">
                    <label for="contenteditable">Contenteditable Div:</label>
                    <div id="contenteditable" class="contenteditable" contenteditable="true">
                        Click here to edit this content...
                    </div>
                </div>
                
                <button type="button" onclick="clearAll()">Clear All</button>
                <button type="button" onclick="showValues()">Show Values</button>
                <button type="submit">Submit Form</button>
            </form>
            
            <div id="results" style="margin-top: 20px;"></div>
            
            <script>
                // Track all input events
                window.inputEvents = [];
                window.formData = {};
                
                function trackEvent(event) {
                    window.inputEvents.push({
                        timestamp: Date.now(),
                        type: event.type,
                        element: event.target.id || event.target.tagName,
                        value: event.target.value || event.target.textContent
                    });
                    
                    updateStatus('Event: ' + event.type + ' on ' + (event.target.id || event.target.tagName));
                }
                
                function updateStatus(message) {
                    document.getElementById('status').textContent = message;
                }
                
                function clearAll() {
                    document.querySelectorAll('input, textarea').forEach(el => el.value = '');
                    document.getElementById('contenteditable').textContent = 'Click here to edit this content...';
                    updateStatus('All fields cleared');
                }
                
                function showValues() {
                    const values = {};
                    document.querySelectorAll('input, textarea').forEach(el => {
                        if (el.id) values[el.id] = el.value;
                    });
                    values['contenteditable'] = document.getElementById('contenteditable').textContent;
                    
                    document.getElementById('results').innerHTML = 
                        '<h3>Current Values:</h3><pre>' + JSON.stringify(values, null, 2) + '</pre>';
                    
                    updateStatus('Values displayed');
                }
                
                // Add event listeners
                document.addEventListener('input', trackEvent);
                document.addEventListener('change', trackEvent);
                document.addEventListener('focus', trackEvent);
                document.addEventListener('blur', trackEvent);
                
                // Form submission handler
                document.getElementById('test-form').addEventListener('submit', function(e) {
                    e.preventDefault();
                    updateStatus('Form submitted (prevented default)');
                });
                
                updateStatus('Test page loaded and ready');
            </script>
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Test HTML page created: {Path(output_path).absolute()}")
        return Path(output_path).absolute()
    
    def test_browser_detection(self, browser_type: str = "chrome", headless: bool = True):
        """Test browser detection and initialization."""
        print(f"\n=== Browser Detection Test ({browser_type}) ===")
        
        if not SELENIUM_AVAILABLE:
            print("❌ Selenium not available")
            return False
        
        try:
            browser_config = BrowserConfig(
                browser_type=getattr(BrowserType, browser_type.upper()),
                headless=headless,
                timeout=30
            )
            
            self.browser_engine = BrowserIntegrationEngine()
            success = self.browser_engine.initialize(browser_config)
            
            if success:
                print("✅ Browser initialized successfully")
                
                browser_info = self.browser_engine.get_browser_info()
                print(f"   Browser: {browser_info.get('browser_name', 'unknown')}")
                print(f"   Version: {browser_info.get('browser_version', 'unknown')}")
                print(f"   Session: {browser_info.get('session_id', 'unknown')}")
                
                return True
            else:
                print("❌ Browser initialization failed")
                return False
                
        except Exception as e:
            print(f"❌ Browser detection error: {e}")
            return False
    
    def test_element_detection(self, url: str):
        """Test input element detection on a webpage."""
        print(f"\n=== Element Detection Test ===")
        print(f"URL: {url}")
        
        if not self.browser_engine:
            print("❌ Browser not initialized")
            return []
        
        try:
            # Navigate to URL
            success = self.browser_engine.inject_text_to_browser("", target_url=url)
            if not success:
                print("❌ Failed to navigate to URL")
                return []
            
            print("✅ Page loaded successfully")
            
            # Detect elements
            elements = self.browser_engine.detect_browser_elements()
            
            print(f"✅ Found {len(elements)} input elements:")
            
            for i, elem in enumerate(elements, 1):
                print(f"   {i}. {elem['type']} ({elem['framework']} framework)")
                print(f"      Focused: {elem['is_focused']}, Visible: {elem['is_visible']}")
                if elem['selector']:
                    print(f"      Selector: {elem['selector'][:100]}...")
            
            return elements
            
        except Exception as e:
            print(f"❌ Element detection error: {e}")
            return []
    
    def test_text_injection(self, text: str, target_url: Optional[str] = None):
        """Test text injection into focused elements."""
        print(f"\n=== Text Injection Test ===")
        print(f"Text: '{text[:50]}{'...' if len(text) > 50 else ''}'")
        
        if not self.browser_engine:
            print("❌ Browser not initialized")
            return False
        
        try:
            if target_url:
                success = self.browser_engine.inject_text_to_browser("", target_url=target_url)
                if not success:
                    print("❌ Failed to navigate to URL")
                    return False
                time.sleep(2)  # Wait for page load
            
            # Inject text
            success = self.browser_engine.inject_text_to_browser(text)
            
            if success:
                print("✅ Text injection successful")
                return True
            else:
                print("❌ Text injection failed")
                return False
                
        except Exception as e:
            print(f"❌ Text injection error: {e}")
            return False
    
    def interactive_test_session(self, url: str):
        """Run an interactive testing session."""
        print(f"\n=== Interactive Test Session ===")
        print(f"URL: {url}")
        print("Commands:")
        print("  detect - Detect input elements")
        print("  inject <text> - Inject text into focused element")
        print("  focus <element_number> - Focus on specific element")
        print("  status - Show browser status")
        print("  quit - Exit session")
        
        if not self.browser_engine:
            print("❌ Browser not initialized")
            return
        
        # Navigate to URL
        success = self.browser_engine.inject_text_to_browser("", target_url=url)
        if not success:
            print("❌ Failed to navigate to URL")
            return
        
        elements = []
        
        while True:
            try:
                command = input("\n> ").strip()
                
                if command == "quit":
                    break
                
                elif command == "detect":
                    elements = self.browser_engine.detect_browser_elements()
                    print(f"Found {len(elements)} elements:")
                    for i, elem in enumerate(elements, 1):
                        status = "🎯" if elem['is_focused'] else "👁️" if elem['is_visible'] else "👻"
                        print(f"  {i}. {status} {elem['type']} ({elem['framework']})")
                
                elif command.startswith("inject "):
                    text = command[7:]  # Remove "inject "
                    if text:
                        success = self.browser_engine.inject_text_to_browser(text)
                        print("✅ Injected" if success else "❌ Failed")
                    else:
                        print("❌ No text provided")
                
                elif command == "status":
                    browser_info = self.browser_engine.get_browser_info()
                    print(f"Current URL: {browser_info.get('current_url', 'unknown')}")
                    print(f"Title: {browser_info.get('title', 'unknown')}")
                    print(f"Windows: {browser_info.get('window_handles', 0)}")
                
                elif command.startswith("focus "):
                    try:
                        element_num = int(command[6:]) - 1
                        if 0 <= element_num < len(elements):
                            # This would require additional implementation
                            print("Focus command not yet implemented")
                        else:
                            print("❌ Invalid element number")
                    except ValueError:
                        print("❌ Invalid number")
                
                else:
                    print("❌ Unknown command")
                    
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def run_full_test_suite(self, browser_type: str = "chrome", headless: bool = True):
        """Run a comprehensive test suite."""
        print("🚀 VoiceFlow Browser Integration Test Suite")
        print("=" * 50)
        
        # Create test page
        test_page = self.create_test_html()
        test_url = f"file://{test_page}"
        
        try:
            # Test 1: Browser Detection
            if not self.test_browser_detection(browser_type, headless):
                print("\n❌ Browser detection failed - stopping tests")
                return False
            
            # Test 2: Element Detection
            elements = self.test_element_detection(test_url)
            if not elements:
                print("\n❌ Element detection failed - stopping tests")
                return False
            
            # Test 3: Text Injection Tests
            test_texts = [
                "Hello, World!",
                "test@example.com",
                "This is a multi-line\ntext message with\nspecial characters: !@#$%",
                "Unicode test: 你好 🌍 café résumé"
            ]
            
            injection_successes = 0
            for i, text in enumerate(test_texts, 1):
                print(f"\n--- Text Injection Test {i} ---")
                if self.test_text_injection(text, test_url):
                    injection_successes += 1
                time.sleep(1)  # Brief pause between tests
            
            # Test 4: Security Validation
            print(f"\n=== Security Validation Test ===")
            malicious_texts = [
                "<script>alert('XSS')</script>",
                "'; DROP TABLE users; --",
                "javascript:alert('test')"
            ]
            
            security_blocks = 0
            for text in malicious_texts:
                print(f"Testing: {text[:30]}...")
                if not self.test_text_injection(text, test_url):
                    security_blocks += 1
                    print("✅ Blocked (expected)")
                else:
                    print("⚠️  Not blocked (security concern)")
            
            # Summary
            print(f"\n🎯 Test Suite Summary")
            print(f"=" * 30)
            print(f"Browser initialization: ✅")
            print(f"Element detection: ✅ ({len(elements)} elements)")
            print(f"Text injection: {injection_successes}/{len(test_texts)} successful")
            print(f"Security validation: {security_blocks}/{len(malicious_texts)} blocked")
            
            overall_success = (injection_successes >= len(test_texts) // 2 and 
                             security_blocks >= len(malicious_texts) // 2)
            
            print(f"Overall result: {'✅ PASS' if overall_success else '❌ FAIL'}")
            
            return overall_success
            
        finally:
            # Cleanup
            if self.browser_engine:
                self.browser_engine.cleanup()
            
            # Clean up test file
            try:
                test_page.unlink()
                print(f"\n🧹 Cleaned up test file: {test_page.name}")
            except:
                pass
    
    def cleanup(self):
        """Clean up resources."""
        if self.browser_engine:
            self.browser_engine.cleanup()
        if self.engine:
            self.engine.cleanup()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="VoiceFlow Browser Integration CLI Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s test                                   # Run full test suite
  %(prog)s test --browser firefox --no-headless  # Test with Firefox GUI
  %(prog)s detect --url https://example.com      # Detect elements on website
  %(prog)s inject "Hello World" --url file://test.html  # Inject text
  %(prog)s interactive --url https://google.com  # Interactive session
  %(prog)s create-test-page                       # Create test HTML page
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run comprehensive test suite')
    test_parser.add_argument('--browser', choices=['chrome', 'firefox', 'edge'], 
                           default='chrome', help='Browser type to test')
    test_parser.add_argument('--no-headless', action='store_true', 
                           help='Run browser in GUI mode')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect input elements')
    detect_parser.add_argument('--url', required=True, help='URL to analyze')
    detect_parser.add_argument('--browser', choices=['chrome', 'firefox', 'edge'], 
                             default='chrome', help='Browser type')
    detect_parser.add_argument('--no-headless', action='store_true', 
                             help='Run browser in GUI mode')
    
    # Inject command
    inject_parser = subparsers.add_parser('inject', help='Inject text into webpage')
    inject_parser.add_argument('text', help='Text to inject')
    inject_parser.add_argument('--url', help='URL to navigate to first')
    inject_parser.add_argument('--browser', choices=['chrome', 'firefox', 'edge'], 
                             default='chrome', help='Browser type')
    inject_parser.add_argument('--no-headless', action='store_true', 
                             help='Run browser in GUI mode')
    
    # Interactive command
    interactive_parser = subparsers.add_parser('interactive', help='Interactive test session')
    interactive_parser.add_argument('--url', required=True, help='URL to work with')
    interactive_parser.add_argument('--browser', choices=['chrome', 'firefox', 'edge'], 
                                   default='chrome', help='Browser type')
    interactive_parser.add_argument('--no-headless', action='store_true', 
                                   help='Run browser in GUI mode')
    
    # Create test page command
    create_parser = subparsers.add_parser('create-test-page', help='Create test HTML page')
    create_parser.add_argument('--output', default='test_page.html', 
                             help='Output file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    cli = BrowserIntegrationCLI()
    
    try:
        if args.command == 'test':
            headless = not args.no_headless
            success = cli.run_full_test_suite(args.browser, headless)
            sys.exit(0 if success else 1)
        
        elif args.command == 'detect':
            headless = not args.no_headless
            if cli.test_browser_detection(args.browser, headless):
                cli.test_element_detection(args.url)
        
        elif args.command == 'inject':
            headless = not args.no_headless
            if cli.test_browser_detection(args.browser, headless):
                cli.test_text_injection(args.text, args.url)
        
        elif args.command == 'interactive':
            headless = not args.no_headless
            if cli.test_browser_detection(args.browser, headless):
                cli.interactive_test_session(args.url)
        
        elif args.command == 'create-test-page':
            cli.create_test_html(args.output)
    
    except KeyboardInterrupt:
        print("\n👋 Interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
    finally:
        cli.cleanup()


if __name__ == "__main__":
    main()