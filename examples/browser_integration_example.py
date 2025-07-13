#!/usr/bin/env python3
"""
VoiceFlow Browser Integration Example

This example demonstrates how to use the new browser integration features
to inject speech-to-text results directly into web forms and applications.
"""

import time
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

try:
    from core.voiceflow_core import create_engine
    from core.browser_integration import BrowserConfig, BrowserType
except ImportError as e:
    print(f"Error importing VoiceFlow: {e}")
    print("Make sure you're running from the VoiceFlow directory")
    sys.exit(1)


def example_basic_browser_integration():
    """Basic example of browser integration with VoiceFlow."""
    print("🎤 VoiceFlow Browser Integration Example")
    print("=" * 50)
    
    # Create VoiceFlow engine with browser integration
    config = {
        'model': 'base',
        'browser_type': 'chrome',
        'browser_headless': False,  # Show browser for demo
        'browser_timeout': 30
    }
    
    engine = create_engine(config)
    
    try:
        # Check browser integration status
        browser_status = engine.get_browser_status()
        print(f"Browser integration enabled: {browser_status['integration_enabled']}")
        print(f"Selenium available: {browser_status['selenium_available']}")
        
        if not browser_status['selenium_available']:
            print("❌ Selenium not available. Install with:")
            print("   pip install selenium webdriver-manager")
            return
        
        # Open a browser session
        print("\n🌐 Opening browser session...")
        success = engine.open_browser_session(
            url="https://www.google.com",
            browser_type="chrome"
        )
        
        if success:
            print("✅ Browser session opened")
            
            # Wait a moment for page to load
            time.sleep(3)
            
            # Detect input elements
            print("\n🔍 Detecting input elements...")
            elements = engine.detect_browser_inputs()
            
            print(f"Found {len(elements)} input elements:")
            for i, element in enumerate(elements, 1):
                print(f"  {i}. {element['type']} - Framework: {element['framework']}")
            
            # Simulate speech-to-text result and inject
            simulated_speech = "VoiceFlow browser integration test"
            print(f"\n💬 Simulating speech result: '{simulated_speech}'")
            
            # Use the enhanced inject_text method with auto method selection
            injection_success = engine.inject_text(simulated_speech, injection_method="auto")
            
            if injection_success:
                print("✅ Text injected successfully using intelligent method selection")
            else:
                print("❌ Text injection failed")
            
            # Keep browser open for a moment to see the result
            print("\n⏱️  Keeping browser open for 10 seconds to observe result...")
            time.sleep(10)
            
        else:
            print("❌ Failed to open browser session")
    
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        # Clean up
        print("\n🧹 Cleaning up...")
        engine.close_browser_session()
        engine.cleanup()
        print("✅ Cleanup complete")


def example_form_filling():
    """Example of filling out a web form using VoiceFlow."""
    print("\n📝 Form Filling Example")
    print("=" * 30)
    
    # Create a simple test form HTML
    test_form_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>VoiceFlow Form Test</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; }
            input, textarea { padding: 8px; width: 300px; }
        </style>
    </head>
    <body>
        <h1>Contact Form</h1>
        <form>
            <div class="form-group">
                <label>Name:</label>
                <input type="text" id="name" placeholder="Enter your name">
            </div>
            <div class="form-group">
                <label>Email:</label>
                <input type="email" id="email" placeholder="Enter your email">
            </div>
            <div class="form-group">
                <label>Message:</label>
                <textarea id="message" placeholder="Enter your message"></textarea>
            </div>
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    """
    
    # Save test form
    test_file = Path("temp_form.html")
    test_file.write_text(test_form_html)
    
    try:
        config = {
            'browser_type': 'chrome',
            'browser_headless': False
        }
        
        engine = create_engine(config)
        
        if not engine.get_browser_status()['selenium_available']:
            print("❌ Selenium not available")
            return
        
        # Open form
        form_url = f"file://{test_file.absolute()}"
        print(f"📄 Opening test form: {form_url}")
        
        success = engine.open_browser_session(url=form_url)
        if not success:
            print("❌ Failed to open form")
            return
        
        time.sleep(2)  # Wait for form to load
        
        # Simulate filling form with voice input
        form_data = [
            ("John Doe", "name field"),
            ("john.doe@example.com", "email field"),
            ("Hello, this message was dictated using VoiceFlow!", "message field")
        ]
        
        for text, description in form_data:
            print(f"\n🎤 Simulating speech for {description}: '{text}'")
            
            # In a real scenario, this would be the result of speech processing
            success = engine.inject_text(text, injection_method="browser")
            
            if success:
                print(f"✅ Filled {description}")
            else:
                print(f"❌ Failed to fill {description}")
            
            time.sleep(2)  # Pause between fields
        
        print("\n✅ Form filling complete! Check the browser window.")
        time.sleep(10)  # Keep form open to see results
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        # Cleanup
        engine.cleanup()
        try:
            test_file.unlink()
        except:
            pass


def example_real_world_integration():
    """Example showing real-world integration scenarios."""
    print("\n🌍 Real-World Integration Example")
    print("=" * 40)
    
    config = {
        'browser_type': 'chrome',
        'browser_headless': False,
        'browser_timeout': 30
    }
    
    engine = create_engine(config)
    
    if not engine.get_browser_status()['selenium_available']:
        print("❌ Selenium not available")
        return
    
    try:
        # Demonstrate different injection methods
        print("🔧 Testing different injection methods...")
        
        # Method 1: System injection (traditional pyautogui)
        print("\n1. System injection method:")
        test_text = "System injection test"
        success = engine.inject_text(test_text, injection_method="system")
        print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
        
        # Method 2: Browser injection (advanced Selenium)
        print("\n2. Browser injection method:")
        # First open a browser session
        engine.open_browser_session(url="https://www.google.com")
        time.sleep(3)
        
        test_text = "Browser injection test"
        success = engine.inject_text(test_text, injection_method="browser")
        print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
        
        # Method 3: Auto method selection (intelligent)
        print("\n3. Auto method selection:")
        test_text = "Auto method selection test"
        success = engine.inject_text(test_text, injection_method="auto")
        print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
        
        # Show browser status
        print("\n📊 Browser Status:")
        status = engine.get_browser_status()
        if status['active_session']:
            info = status['browser_info']
            print(f"   Current URL: {info.get('current_url', 'N/A')}")
            print(f"   Page Title: {info.get('title', 'N/A')}")
            print(f"   Browser: {info.get('browser_name', 'N/A')}")
        
        time.sleep(5)
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        engine.cleanup()


def main():
    """Run all examples."""
    print("🚀 VoiceFlow Browser Integration Examples")
    print("=========================================")
    
    try:
        # Run examples
        example_basic_browser_integration()
        
        input("\nPress Enter to continue to form filling example...")
        example_form_filling()
        
        input("\nPress Enter to continue to real-world integration example...")
        example_real_world_integration()
        
        print("\n🎉 All examples completed!")
        
    except KeyboardInterrupt:
        print("\n👋 Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()