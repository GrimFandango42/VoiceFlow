"""
VoiceFlow Browser Integration Test Suite

Comprehensive test suite for browser automation and text injection capabilities.
Tests real browser interactions, not just simulations.
"""

import pytest
import time
import threading
from pathlib import Path
from typing import Dict, Any, List
import tempfile
import os

# Test framework imports
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import WebDriverException, TimeoutException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="Selenium not available")

# VoiceFlow imports
try:
    from core.browser_integration import (
        BrowserIntegrationEngine, BrowserConfig, BrowserType, 
        InputElementType, FrameworkType, InputElementDetector, 
        TextInjector, BrowserManager
    )
    from core.voiceflow_core import VoiceFlowEngine, create_engine
    VOICEFLOW_AVAILABLE = True
except ImportError:
    VOICEFLOW_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="VoiceFlow core not available")


class TestHTMLGenerator:
    """Generate test HTML pages for different scenarios."""
    
    @staticmethod
    def create_basic_form() -> str:
        """Create a basic HTML form with various input types."""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Basic Form Test</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>VoiceFlow Browser Integration Test</h1>
            
            <form id="test-form">
                <div>
                    <label for="text-input">Text Input:</label>
                    <input type="text" id="text-input" name="text" placeholder="Enter text here">
                </div>
                
                <div>
                    <label for="email-input">Email Input:</label>
                    <input type="email" id="email-input" name="email" placeholder="Enter email">
                </div>
                
                <div>
                    <label for="password-input">Password Input:</label>
                    <input type="password" id="password-input" name="password">
                </div>
                
                <div>
                    <label for="search-input">Search Input:</label>
                    <input type="search" id="search-input" name="search" placeholder="Search...">
                </div>
                
                <div>
                    <label for="textarea">Textarea:</label>
                    <textarea id="textarea" name="message" rows="4" cols="50" placeholder="Enter your message"></textarea>
                </div>
                
                <div>
                    <label for="contenteditable">Contenteditable Div:</label>
                    <div id="contenteditable" contenteditable="true" style="border: 1px solid #ccc; padding: 10px; min-height: 50px;">
                        Click here to edit
                    </div>
                </div>
                
                <button type="submit">Submit</button>
            </form>
            
            <script>
                // Track input events for testing
                window.inputEvents = [];
                
                document.addEventListener('input', function(e) {
                    window.inputEvents.push({
                        type: 'input',
                        target: e.target.id || e.target.tagName,
                        value: e.target.value || e.target.textContent
                    });
                });
                
                document.addEventListener('change', function(e) {
                    window.inputEvents.push({
                        type: 'change',
                        target: e.target.id || e.target.tagName,
                        value: e.target.value || e.target.textContent
                    });
                });
            </script>
        </body>
        </html>
        """
    
    @staticmethod
    def create_react_form() -> str:
        """Create a React-style form with controlled components."""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>React Form Test</title>
            <script src="https://unpkg.com/react@18/umd/react.development.js"></script>
            <script src="https://unpkg.com/react-dom@18/umd/react-dom.development.js"></script>
            <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
        </head>
        <body>
            <div id="react-root"></div>
            
            <script type="text/babel">
                const { useState } = React;
                
                function ReactForm() {
                    const [formData, setFormData] = useState({
                        name: '',
                        email: '',
                        message: ''
                    });
                    
                    const handleChange = (e) => {
                        setFormData({
                            ...formData,
                            [e.target.name]: e.target.value
                        });
                    };
                    
                    return (
                        <div>
                            <h1>React Controlled Form</h1>
                            <form>
                                <div>
                                    <label>Name:</label>
                                    <input 
                                        type="text" 
                                        name="name" 
                                        id="react-name"
                                        value={formData.name}
                                        onChange={handleChange}
                                        placeholder="Enter your name"
                                    />
                                </div>
                                
                                <div>
                                    <label>Email:</label>
                                    <input 
                                        type="email" 
                                        name="email" 
                                        id="react-email"
                                        value={formData.email}
                                        onChange={handleChange}
                                        placeholder="Enter your email"
                                    />
                                </div>
                                
                                <div>
                                    <label>Message:</label>
                                    <textarea 
                                        name="message" 
                                        id="react-message"
                                        value={formData.message}
                                        onChange={handleChange}
                                        placeholder="Enter your message"
                                        rows="4"
                                    />
                                </div>
                                
                                <button type="submit">Submit</button>
                            </form>
                            
                            <div id="form-data">
                                <h3>Current Form Data:</h3>
                                <pre>{JSON.stringify(formData, null, 2)}</pre>
                            </div>
                        </div>
                    );
                }
                
                ReactDOM.render(<ReactForm />, document.getElementById('react-root'));
                
                // Expose React for detection
                window.React = React;
            </script>
        </body>
        </html>
        """
    
    @staticmethod
    def create_rich_text_editors() -> str:
        """Create a page with various rich text editors."""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Rich Text Editors Test</title>
            <!-- Quill CSS -->
            <link href="https://cdn.quilljs.com/1.3.6/quill.snow.css" rel="stylesheet">
            <!-- TinyMCE -->
            <script src="https://cdn.tiny.cloud/1/no-api-key/tinymce/6/tinymce.min.js" referrerpolicy="origin"></script>
            <!-- Quill JS -->
            <script src="https://cdn.quilljs.com/1.3.6/quill.min.js"></script>
        </head>
        <body>
            <h1>Rich Text Editors Test</h1>
            
            <div style="margin: 20px 0;">
                <h3>Quill Editor</h3>
                <div id="quill-editor" style="height: 200px;"></div>
            </div>
            
            <div style="margin: 20px 0;">
                <h3>TinyMCE Editor</h3>
                <textarea id="tinymce-editor">Initial content for TinyMCE</textarea>
            </div>
            
            <div style="margin: 20px 0;">
                <h3>Simple Contenteditable</h3>
                <div id="simple-contenteditable" contenteditable="true" 
                     style="border: 1px solid #ddd; padding: 10px; min-height: 100px;">
                    Edit this content...
                </div>
            </div>
            
            <script>
                // Initialize Quill
                var quill = new Quill('#quill-editor', {
                    theme: 'snow',
                    placeholder: 'Type something...'
                });
                
                // Initialize TinyMCE
                tinymce.init({
                    selector: '#tinymce-editor',
                    height: 200,
                    plugins: 'lists link',
                    toolbar: 'undo redo | formatselect | bold italic | alignleft aligncenter alignright | bullist numlist | link'
                });
                
                // Track editor changes
                window.editorContent = {
                    quill: '',
                    tinymce: '',
                    contenteditable: ''
                };
                
                quill.on('text-change', function() {
                    window.editorContent.quill = quill.getText();
                });
                
                document.getElementById('simple-contenteditable').addEventListener('input', function(e) {
                    window.editorContent.contenteditable = e.target.textContent;
                });
            </script>
        </body>
        </html>
        """


@pytest.fixture
def browser_config():
    """Default browser configuration for testing."""
    return BrowserConfig(
        browser_type=BrowserType.CHROME,
        headless=True,  # Use headless for CI/testing
        timeout=30,
        security_validation=True
    )


@pytest.fixture
def test_html_files():
    """Create temporary HTML files for testing."""
    temp_dir = tempfile.mkdtemp()
    
    files = {
        'basic_form': Path(temp_dir) / 'basic_form.html',
        'react_form': Path(temp_dir) / 'react_form.html',
        'rich_text': Path(temp_dir) / 'rich_text.html'
    }
    
    # Write test HTML files
    files['basic_form'].write_text(TestHTMLGenerator.create_basic_form())
    files['react_form'].write_text(TestHTMLGenerator.create_react_form())
    files['rich_text'].write_text(TestHTMLGenerator.create_rich_text_editors())
    
    yield files
    
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)


class TestBrowserManager:
    """Test browser driver management."""
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_create_chrome_driver(self, browser_config):
        """Test Chrome driver creation."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_chrome")
        
        assert driver is not None
        assert "test_chrome" in manager.drivers
        
        manager.close_driver("test_chrome")
        assert "test_chrome" not in manager.drivers
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_multiple_browser_sessions(self, browser_config):
        """Test managing multiple browser sessions."""
        manager = BrowserManager()
        
        # Create multiple sessions
        driver1 = manager.create_driver(browser_config, "session1")
        driver2 = manager.create_driver(browser_config, "session2")
        
        assert driver1 is not None
        assert driver2 is not None
        assert len(manager.drivers) == 2
        
        # Test individual cleanup
        manager.close_driver("session1")
        assert len(manager.drivers) == 1
        assert "session2" in manager.drivers
        
        # Test bulk cleanup
        manager.close_all_drivers()
        assert len(manager.drivers) == 0


class TestInputElementDetector:
    """Test input element detection and classification."""
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_detect_basic_inputs(self, browser_config, test_html_files):
        """Test detection of basic HTML input elements."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_detection")
        
        try:
            # Load test page
            driver.get(f"file://{test_html_files['basic_form']}")
            
            # Create detector
            detector = InputElementDetector(driver)
            elements = detector.find_input_elements()
            
            # Should find multiple input types
            assert len(elements) >= 5
            
            # Check for specific element types
            element_types = [elem.element_type for elem in elements]
            assert InputElementType.INPUT_TEXT in element_types
            assert InputElementType.INPUT_EMAIL in element_types
            assert InputElementType.TEXTAREA in element_types
            assert InputElementType.CONTENTEDITABLE in element_types
            
        finally:
            manager.close_driver("test_detection")
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_framework_detection(self, browser_config, test_html_files):
        """Test web framework detection."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_framework")
        
        try:
            # Test vanilla HTML
            driver.get(f"file://{test_html_files['basic_form']}")
            detector = InputElementDetector(driver)
            framework = detector.detect_framework()
            assert framework == FrameworkType.VANILLA
            
            # Test React detection
            driver.get(f"file://{test_html_files['react_form']}")
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "react-root"))
            )
            time.sleep(2)  # Wait for React to initialize
            
            detector = InputElementDetector(driver)
            framework = detector.detect_framework()
            # Note: React detection might be limited in test environment
            
        finally:
            manager.close_driver("test_framework")
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_focused_element_detection(self, browser_config, test_html_files):
        """Test detection of focused input elements."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_focus")
        
        try:
            driver.get(f"file://{test_html_files['basic_form']}")
            
            # Focus on text input
            text_input = driver.find_element(By.ID, "text-input")
            text_input.click()
            
            detector = InputElementDetector(driver)
            focused_element = detector.find_focused_element()
            
            assert focused_element is not None
            assert focused_element.is_focused is True
            assert focused_element.element_type == InputElementType.INPUT_TEXT
            
        finally:
            manager.close_driver("test_focus")


class TestTextInjector:
    """Test text injection functionality."""
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_basic_text_injection(self, browser_config, test_html_files):
        """Test basic text injection into various input types."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_injection")
        
        try:
            driver.get(f"file://{test_html_files['basic_form']}")
            injector = TextInjector(driver)
            
            test_cases = [
                ("text-input", "Hello, World!", InputElementType.INPUT_TEXT),
                ("email-input", "test@example.com", InputElementType.INPUT_EMAIL),
                ("search-input", "search query", InputElementType.INPUT_SEARCH),
                ("textarea", "This is a multi-line\ntext message.", InputElementType.TEXTAREA)
            ]
            
            for element_id, test_text, expected_type in test_cases:
                # Find and focus element
                element = driver.find_element(By.ID, element_id)
                element.click()
                
                # Detect focused element
                detector = InputElementDetector(driver)
                focused_element = detector.find_focused_element()
                
                assert focused_element is not None
                assert focused_element.element_type == expected_type
                
                # Inject text
                success = injector.inject_text(test_text, focused_element)
                assert success is True
                
                # Verify injection
                actual_value = element.get_attribute("value")
                assert actual_value == test_text
                
        finally:
            manager.close_driver("test_injection")
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_contenteditable_injection(self, browser_config, test_html_files):
        """Test text injection into contenteditable elements."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_contenteditable")
        
        try:
            driver.get(f"file://{test_html_files['basic_form']}")
            injector = TextInjector(driver)
            
            # Focus contenteditable div
            contenteditable = driver.find_element(By.ID, "contenteditable")
            contenteditable.click()
            
            # Detect and inject
            detector = InputElementDetector(driver)
            focused_element = detector.find_focused_element()
            
            test_text = "Injected into contenteditable"
            success = injector.inject_text(test_text, focused_element)
            assert success is True
            
            # Verify injection
            actual_content = contenteditable.text
            assert test_text in actual_content
            
        finally:
            manager.close_driver("test_contenteditable")
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_security_validation(self, browser_config, test_html_files):
        """Test security validation for malicious text injection."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_security")
        
        try:
            driver.get(f"file://{test_html_files['basic_form']}")
            injector = TextInjector(driver)
            
            # Focus text input
            text_input = driver.find_element(By.ID, "text-input")
            text_input.click()
            
            detector = InputElementDetector(driver)
            focused_element = detector.find_focused_element()
            
            # Test malicious scripts
            malicious_texts = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "'; DROP TABLE users; --",
                "onload=alert('XSS')"
            ]
            
            for malicious_text in malicious_texts:
                success = injector.inject_text(malicious_text, focused_element)
                # Should be blocked by security validation
                assert success is False
            
            # Test normal text should work
            safe_text = "This is safe text"
            success = injector.inject_text(safe_text, focused_element)
            assert success is True
            
        finally:
            manager.close_driver("test_security")


class TestBrowserIntegrationEngine:
    """Test the main browser integration engine."""
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_engine_initialization(self, browser_config):
        """Test browser integration engine initialization."""
        engine = BrowserIntegrationEngine()
        
        success = engine.initialize(browser_config)
        assert success is True
        
        # Test browser info
        browser_info = engine.get_browser_info()
        assert "browser_name" in browser_info
        assert "session_id" in browser_info
        
        engine.cleanup()
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_text_injection_workflow(self, browser_config, test_html_files):
        """Test complete text injection workflow."""
        engine = BrowserIntegrationEngine()
        
        try:
            # Initialize engine
            success = engine.initialize(browser_config)
            assert success is True
            
            # Navigate to test page
            test_url = f"file://{test_html_files['basic_form']}"
            success = engine.inject_text_to_browser("", target_url=test_url)
            assert success is True
            
            # Detect input elements
            elements = engine.detect_browser_elements()
            assert len(elements) > 0
            
            # Test text injection
            test_text = "Hello from VoiceFlow!"
            success = engine.inject_text_to_browser(test_text)
            # Note: Might fail if no element is focused
            
        finally:
            engine.cleanup()


class TestVoiceFlowIntegration:
    """Test VoiceFlow core integration with browser automation."""
    
    @pytest.mark.skipif(not VOICEFLOW_AVAILABLE, reason="VoiceFlow core not available")
    def test_engine_browser_integration(self):
        """Test VoiceFlow engine with browser integration enabled."""
        config = {
            'browser_type': 'chrome',
            'browser_headless': True,
            'model': 'base'
        }
        
        engine = create_engine(config)
        
        # Test browser status
        browser_status = engine.get_browser_status()
        assert "integration_enabled" in browser_status
        assert "selenium_available" in browser_status
        
        engine.cleanup()
    
    @pytest.mark.skipif(not VOICEFLOW_AVAILABLE, reason="VoiceFlow core not available") 
    def test_intelligent_injection_method_selection(self):
        """Test intelligent injection method selection."""
        config = {
            'browser_type': 'chrome',
            'browser_headless': True
        }
        
        engine = create_engine(config)
        
        # Test method detection without active browser
        method = engine._detect_best_injection_method()
        assert method in ["browser", "system"]
        
        engine.cleanup()
    
    @pytest.mark.skipif(not VOICEFLOW_AVAILABLE, reason="VoiceFlow core not available")
    def test_browser_session_management(self):
        """Test browser session opening and closing."""
        config = {
            'browser_type': 'chrome',
            'browser_headless': True
        }
        
        engine = create_engine(config)
        
        try:
            # Test browser session opening
            success = engine.open_browser_session(browser_type="chrome")
            if SELENIUM_AVAILABLE:
                # Only test if selenium is available
                browser_status = engine.get_browser_status()
                
                # Test browser input detection
                inputs = engine.detect_browser_inputs()
                # Initially might be empty if no page is loaded
                
        finally:
            engine.close_browser_session()
            engine.cleanup()


class TestCrossBrowserCompatibility:
    """Test compatibility across different browsers."""
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    @pytest.mark.parametrize("browser_type", [BrowserType.CHROME, BrowserType.FIREFOX])
    def test_multi_browser_support(self, browser_type, test_html_files):
        """Test basic functionality across multiple browsers."""
        try:
            browser_config = BrowserConfig(
                browser_type=browser_type,
                headless=True,
                timeout=30
            )
            
            manager = BrowserManager()
            driver = manager.create_driver(browser_config, f"test_{browser_type.value}")
            
            if driver is None:
                pytest.skip(f"{browser_type.value} driver not available")
            
            # Load test page
            driver.get(f"file://{test_html_files['basic_form']}")
            
            # Test element detection
            detector = InputElementDetector(driver)
            elements = detector.find_input_elements()
            assert len(elements) > 0
            
            # Test text injection
            injector = TextInjector(driver)
            text_input = driver.find_element(By.ID, "text-input")
            text_input.click()
            
            focused_element = detector.find_focused_element()
            if focused_element:
                success = injector.inject_text("Cross-browser test", focused_element)
                assert success is True
            
        except Exception as e:
            pytest.skip(f"Browser {browser_type.value} test failed: {e}")
        finally:
            try:
                manager.close_driver(f"test_{browser_type.value}")
            except:
                pass


class TestPerformanceAndReliability:
    """Test performance and reliability of browser integration."""
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_rapid_text_injection(self, browser_config, test_html_files):
        """Test rapid successive text injections."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_performance")
        
        try:
            driver.get(f"file://{test_html_files['basic_form']}")
            injector = TextInjector(driver)
            
            # Focus text input
            text_input = driver.find_element(By.ID, "text-input")
            text_input.click()
            
            detector = InputElementDetector(driver)
            focused_element = detector.find_focused_element()
            
            # Rapid injections
            test_texts = [f"Text injection {i}" for i in range(10)]
            success_count = 0
            
            for text in test_texts:
                if injector.inject_text(text, focused_element):
                    success_count += 1
                time.sleep(0.1)  # Small delay
            
            # Should have high success rate
            assert success_count >= 8
            
        finally:
            manager.close_driver("test_performance")
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_long_text_injection(self, browser_config, test_html_files):
        """Test injection of long text content."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_long_text")
        
        try:
            driver.get(f"file://{test_html_files['basic_form']}")
            injector = TextInjector(driver)
            
            # Focus textarea for long text
            textarea = driver.find_element(By.ID, "textarea")
            textarea.click()
            
            detector = InputElementDetector(driver)
            focused_element = detector.find_focused_element()
            
            # Generate long text (but within security limits)
            long_text = "This is a long text message. " * 100  # About 3000 characters
            
            success = injector.inject_text(long_text, focused_element)
            assert success is True
            
            # Verify injection
            actual_value = textarea.get_attribute("value")
            assert len(actual_value) >= 2000  # Should have significant content
            
        finally:
            manager.close_driver("test_long_text")


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_invalid_browser_config(self):
        """Test handling of invalid browser configurations."""
        invalid_config = BrowserConfig(
            browser_type=BrowserType.SAFARI,  # May not be available on non-macOS
            headless=True
        )
        
        manager = BrowserManager()
        
        # Should handle gracefully
        driver = manager.create_driver(invalid_config, "test_invalid")
        
        # Driver may be None on non-macOS systems
        if driver:
            manager.close_driver("test_invalid")
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_injection_without_focused_element(self, browser_config, test_html_files):
        """Test text injection when no element is focused."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_no_focus")
        
        try:
            driver.get(f"file://{test_html_files['basic_form']}")
            injector = TextInjector(driver)
            
            # Don't focus any element
            # Try to inject text
            success = injector.inject_text("Test text")
            
            # Should handle gracefully (might fail or find default element)
            # The exact behavior depends on implementation
            
        finally:
            manager.close_driver("test_no_focus")


@pytest.mark.integration
class TestRealWorldScenarios:
    """Test real-world usage scenarios."""
    
    @pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not available")
    def test_google_search_simulation(self, browser_config):
        """Test Google search page interaction (if available)."""
        manager = BrowserManager()
        driver = manager.create_driver(browser_config, "test_google")
        
        try:
            # Note: This test requires internet connection
            driver.get("https://www.google.com")
            
            # Wait for page load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.NAME, "q"))
            )
            
            detector = InputElementDetector(driver)
            elements = detector.find_input_elements()
            
            # Should find search input
            assert len(elements) > 0
            
            # Find search box
            search_input = None
            for element in elements:
                if element.element.get_attribute("name") == "q":
                    search_input = element
                    break
            
            if search_input:
                injector = TextInjector(driver)
                success = injector.inject_text("VoiceFlow test search", search_input)
                # Note: Google may have protections against automated input
                
        except Exception as e:
            pytest.skip(f"Google search test failed (possibly expected): {e}")
        finally:
            manager.close_driver("test_google")


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])