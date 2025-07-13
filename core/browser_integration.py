"""
VoiceFlow Browser Integration Engine

Comprehensive browser automation framework for intelligent text injection
across different browsers, web frameworks, and input element types.
"""

import os
import time
import platform
import threading
from typing import Optional, Dict, Any, List, Tuple, Union
from enum import Enum
from dataclasses import dataclass
from pathlib import Path
import logging

# Browser automation imports
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.webdriver.edge.service import Service as EdgeService
    from selenium.webdriver.safari.service import Service as SafariService
    from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException
    from webdriver_manager.chrome import ChromeDriverManager
    from webdriver_manager.firefox import GeckoDriverManager
    from webdriver_manager.microsoft import EdgeChromiumDriverManager
    from bs4 import BeautifulSoup
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# Setup logging
logger = logging.getLogger(__name__)


class BrowserType(Enum):
    """Supported browser types."""
    CHROME = "chrome"
    FIREFOX = "firefox"
    EDGE = "edge"
    SAFARI = "safari"
    CHROMIUM = "chromium"


class InputElementType(Enum):
    """Types of input elements that can receive text."""
    INPUT_TEXT = "input[type=text]"
    INPUT_EMAIL = "input[type=email]"
    INPUT_PASSWORD = "input[type=password]"
    INPUT_SEARCH = "input[type=search]"
    INPUT_URL = "input[type=url]"
    INPUT_TEL = "input[type=tel]"
    TEXTAREA = "textarea"
    CONTENTEDITABLE = "[contenteditable=true]"
    RICH_TEXT_EDITOR = ".rich-text-editor"
    TINYMCE = ".mce-content-body"
    QUILL = ".ql-editor"
    CKEDITOR = ".cke_editable"
    MONACO_EDITOR = ".monaco-editor"
    CODEMIRROR = ".CodeMirror"


class FrameworkType(Enum):
    """Web framework types for specialized handling."""
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    SVELTE = "svelte"
    VANILLA = "vanilla"


@dataclass
class InputElement:
    """Represents a detected input element."""
    element: Any  # WebElement
    element_type: InputElementType
    framework: FrameworkType
    selector: str
    is_focused: bool = False
    is_visible: bool = True
    react_props: Optional[Dict] = None
    angular_model: Optional[str] = None
    vue_model: Optional[str] = None


@dataclass
class BrowserConfig:
    """Browser configuration profile."""
    browser_type: BrowserType
    headless: bool = False
    user_data_dir: Optional[str] = None
    extensions: List[str] = None
    window_size: Tuple[int, int] = (1920, 1080)
    timeout: int = 10
    implicit_wait: int = 5
    enable_logging: bool = True
    security_validation: bool = True


class BrowserManager:
    """Manages browser instances and driver lifecycle."""
    
    def __init__(self):
        self.drivers: Dict[str, webdriver.Remote] = {}
        self.configs: Dict[str, BrowserConfig] = {}
        self._lock = threading.Lock()
    
    def create_driver(self, config: BrowserConfig, session_id: str = "default") -> Optional[webdriver.Remote]:
        """Create a WebDriver instance based on configuration."""
        if not SELENIUM_AVAILABLE:
            logger.error("Selenium not available - install selenium and webdriver-manager")
            return None
        
        try:
            driver = None
            options = None
            
            if config.browser_type == BrowserType.CHROME:
                options = webdriver.ChromeOptions()
                if config.headless:
                    options.add_argument("--headless")
                if config.user_data_dir:
                    options.add_argument(f"--user-data-dir={config.user_data_dir}")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--disable-web-security")
                options.add_argument("--allow-running-insecure-content")
                
                service = ChromeService(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=options)
                
            elif config.browser_type == BrowserType.FIREFOX:
                options = webdriver.FirefoxOptions()
                if config.headless:
                    options.add_argument("--headless")
                
                service = FirefoxService(GeckoDriverManager().install())
                driver = webdriver.Firefox(service=service, options=options)
                
            elif config.browser_type == BrowserType.EDGE:
                options = webdriver.EdgeOptions()
                if config.headless:
                    options.add_argument("--headless")
                if config.user_data_dir:
                    options.add_argument(f"--user-data-dir={config.user_data_dir}")
                
                service = EdgeService(EdgeChromiumDriverManager().install())
                driver = webdriver.Edge(service=service, options=options)
                
            elif config.browser_type == BrowserType.SAFARI:
                if platform.system() != "Darwin":
                    logger.error("Safari WebDriver only available on macOS")
                    return None
                driver = webdriver.Safari()
            
            if driver:
                driver.set_window_size(*config.window_size)
                driver.implicitly_wait(config.implicit_wait)
                
                with self._lock:
                    self.drivers[session_id] = driver
                    self.configs[session_id] = config
                
                logger.info(f"Created {config.browser_type.value} driver: {session_id}")
                return driver
                
        except Exception as e:
            logger.error(f"Failed to create {config.browser_type.value} driver: {e}")
            return None
    
    def get_driver(self, session_id: str = "default") -> Optional[webdriver.Remote]:
        """Get existing driver instance."""
        return self.drivers.get(session_id)
    
    def close_driver(self, session_id: str = "default"):
        """Close and cleanup driver instance."""
        with self._lock:
            if session_id in self.drivers:
                try:
                    self.drivers[session_id].quit()
                    logger.info(f"Closed driver: {session_id}")
                except Exception as e:
                    logger.error(f"Error closing driver {session_id}: {e}")
                finally:
                    del self.drivers[session_id]
                    if session_id in self.configs:
                        del self.configs[session_id]
    
    def close_all_drivers(self):
        """Close all driver instances."""
        session_ids = list(self.drivers.keys())
        for session_id in session_ids:
            self.close_driver(session_id)


class InputElementDetector:
    """Detects and classifies input elements on web pages."""
    
    def __init__(self, driver: webdriver.Remote):
        self.driver = driver
        self.wait = WebDriverWait(driver, 10)
    
    def detect_framework(self) -> FrameworkType:
        """Detect the web framework being used."""
        try:
            # Check for React
            react_indicators = [
                "window.React",
                "[data-reactroot]",
                "._reactInternalInstance",
                "__REACT_DEVTOOLS_GLOBAL_HOOK__"
            ]
            
            for indicator in react_indicators:
                if self._check_js_or_selector(indicator):
                    return FrameworkType.REACT
            
            # Check for Angular
            angular_indicators = [
                "window.ng",
                "angular",
                "[ng-app]",
                "[data-ng-app]",
                "ng-version"
            ]
            
            for indicator in angular_indicators:
                if self._check_js_or_selector(indicator):
                    return FrameworkType.ANGULAR
            
            # Check for Vue
            vue_indicators = [
                "window.Vue",
                "__VUE__",
                "[v-app]",
                "[data-v-]"
            ]
            
            for indicator in vue_indicators:
                if self._check_js_or_selector(indicator):
                    return FrameworkType.VUE
            
            # Check for Svelte
            if self._check_js_or_selector("window.__SVELTE_DEVTOOLS_GLOBAL_HOOK__"):
                return FrameworkType.SVELTE
            
            return FrameworkType.VANILLA
            
        except Exception as e:
            logger.warning(f"Framework detection failed: {e}")
            return FrameworkType.VANILLA
    
    def _check_js_or_selector(self, indicator: str) -> bool:
        """Check if JavaScript variable exists or CSS selector matches."""
        try:
            if indicator.startswith("window.") or indicator.startswith("__"):
                # JavaScript check
                result = self.driver.execute_script(f"return typeof {indicator} !== 'undefined';")
                return result
            else:
                # CSS selector check
                elements = self.driver.find_elements(By.CSS_SELECTOR, indicator)
                return len(elements) > 0
        except:
            return False
    
    def find_input_elements(self) -> List[InputElement]:
        """Find all input elements on the current page."""
        elements = []
        framework = self.detect_framework()
        
        # Define selectors for different input types
        selectors = {
            InputElementType.INPUT_TEXT: "input[type='text'], input:not([type])",
            InputElementType.INPUT_EMAIL: "input[type='email']",
            InputElementType.INPUT_PASSWORD: "input[type='password']",
            InputElementType.INPUT_SEARCH: "input[type='search']",
            InputElementType.INPUT_URL: "input[type='url']",
            InputElementType.INPUT_TEL: "input[type='tel']",
            InputElementType.TEXTAREA: "textarea",
            InputElementType.CONTENTEDITABLE: "[contenteditable='true'], [contenteditable='']",
            InputElementType.TINYMCE: ".mce-content-body, iframe[id*='mce']",
            InputElementType.QUILL: ".ql-editor",
            InputElementType.CKEDITOR: ".cke_editable, .cke_wysiwyg_frame",
            InputElementType.MONACO_EDITOR: ".monaco-editor .view-lines",
            InputElementType.CODEMIRROR: ".CodeMirror-code"
        }
        
        for element_type, selector in selectors.items():
            try:
                web_elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                
                for web_element in web_elements:
                    if self._is_element_visible_and_enabled(web_element):
                        input_element = InputElement(
                            element=web_element,
                            element_type=element_type,
                            framework=framework,
                            selector=selector,
                            is_visible=True,
                            is_focused=self._is_element_focused(web_element)
                        )
                        
                        # Add framework-specific metadata
                        if framework == FrameworkType.REACT:
                            input_element.react_props = self._get_react_props(web_element)
                        elif framework == FrameworkType.ANGULAR:
                            input_element.angular_model = self._get_angular_model(web_element)
                        elif framework == FrameworkType.VUE:
                            input_element.vue_model = self._get_vue_model(web_element)
                        
                        elements.append(input_element)
                        
            except Exception as e:
                logger.warning(f"Error finding {element_type.value} elements: {e}")
        
        logger.info(f"Found {len(elements)} input elements using {framework.value} framework")
        return elements
    
    def _is_element_visible_and_enabled(self, element) -> bool:
        """Check if element is visible and enabled."""
        try:
            return (element.is_displayed() and 
                   element.is_enabled() and 
                   element.size['height'] > 0 and 
                   element.size['width'] > 0)
        except:
            return False
    
    def _is_element_focused(self, element) -> bool:
        """Check if element is currently focused."""
        try:
            return self.driver.switch_to.active_element == element
        except:
            return False
    
    def _get_react_props(self, element) -> Optional[Dict]:
        """Extract React props from element."""
        try:
            script = """
            var element = arguments[0];
            var reactKey = Object.keys(element).find(key => key.startsWith('__reactInternalInstance'));
            if (reactKey) {
                return element[reactKey].memoizedProps;
            }
            return null;
            """
            return self.driver.execute_script(script, element)
        except:
            return None
    
    def _get_angular_model(self, element) -> Optional[str]:
        """Extract Angular model binding from element."""
        try:
            ng_model = element.get_attribute("ng-model")
            if not ng_model:
                ng_model = element.get_attribute("data-ng-model")
            return ng_model
        except:
            return None
    
    def _get_vue_model(self, element) -> Optional[str]:
        """Extract Vue model binding from element."""
        try:
            v_model = element.get_attribute("v-model")
            if not v_model:
                v_model = element.get_attribute("data-v-model")
            return v_model
        except:
            return None
    
    def find_focused_element(self) -> Optional[InputElement]:
        """Find the currently focused input element."""
        try:
            active_element = self.driver.switch_to.active_element
            
            # Check if active element is an input
            tag_name = active_element.tag_name.lower()
            input_type = active_element.get_attribute("type")
            contenteditable = active_element.get_attribute("contenteditable")
            
            element_type = None
            
            if tag_name == "input":
                if input_type in ["text", "email", "password", "search", "url", "tel"] or not input_type:
                    element_type = getattr(InputElementType, f"INPUT_{(input_type or 'text').upper()}")
            elif tag_name == "textarea":
                element_type = InputElementType.TEXTAREA
            elif contenteditable == "true":
                element_type = InputElementType.CONTENTEDITABLE
            
            if element_type:
                return InputElement(
                    element=active_element,
                    element_type=element_type,
                    framework=self.detect_framework(),
                    selector="",
                    is_focused=True,
                    is_visible=True
                )
                
        except Exception as e:
            logger.warning(f"Error finding focused element: {e}")
        
        return None


class TextInjector:
    """Advanced text injection engine with framework-specific support."""
    
    def __init__(self, driver: webdriver.Remote):
        self.driver = driver
        self.detector = InputElementDetector(driver)
        self.action_chains = ActionChains(driver)
    
    def inject_text(self, text: str, target_element: Optional[InputElement] = None, 
                   method: str = "auto") -> bool:
        """
        Inject text into input element using the most appropriate method.
        
        Args:
            text: Text to inject
            target_element: Specific element to target (if None, uses focused element)
            method: Injection method ('auto', 'selenium', 'javascript', 'native')
        
        Returns:
            True if injection succeeded, False otherwise
        """
        if not text:
            return False
        
        # Find target element
        if not target_element:
            target_element = self.detector.find_focused_element()
            
        if not target_element:
            logger.warning("No target element found for text injection")
            return False
        
        logger.info(f"Injecting text into {target_element.element_type.value} element")
        
        # Security validation
        if not self._validate_injection_security(text, target_element):
            logger.error("Text injection blocked by security validation")
            return False
        
        # Choose injection method
        if method == "auto":
            method = self._choose_injection_method(target_element)
        
        # Perform injection
        try:
            if method == "javascript":
                return self._inject_javascript(text, target_element)
            elif method == "framework":
                return self._inject_framework_specific(text, target_element)
            elif method == "native":
                return self._inject_native(text, target_element)
            else:  # selenium
                return self._inject_selenium(text, target_element)
                
        except Exception as e:
            logger.error(f"Text injection failed: {e}")
            return False
    
    def _validate_injection_security(self, text: str, element: InputElement) -> bool:
        """Validate text injection for security concerns."""
        # Check for potential XSS patterns
        dangerous_patterns = [
            "<script", "</script>", "javascript:", "data:text/html",
            "onload=", "onerror=", "onclick=", "onmouseover=",
            "eval(", "setTimeout(", "setInterval("
        ]
        
        text_lower = text.lower()
        for pattern in dangerous_patterns:
            if pattern in text_lower:
                logger.warning(f"Potentially dangerous pattern detected: {pattern}")
                return False
        
        # Check for SQL injection patterns
        sql_patterns = [
            "'; drop table", "union select", "or 1=1", "' or '1'='1",
            "insert into", "delete from", "update set"
        ]
        
        for pattern in sql_patterns:
            if pattern in text_lower:
                logger.warning(f"Potential SQL injection pattern: {pattern}")
                return False
        
        # Validate text length
        if len(text) > 10000:  # Reasonable limit
            logger.warning("Text too long for injection")
            return False
        
        return True
    
    def _choose_injection_method(self, element: InputElement) -> str:
        """Choose the best injection method for the element type and framework."""
        
        # Rich text editors need special handling
        if element.element_type in [InputElementType.TINYMCE, InputElementType.QUILL, 
                                   InputElementType.CKEDITOR, InputElementType.MONACO_EDITOR]:
            return "framework"
        
        # Framework-specific elements
        if element.framework in [FrameworkType.REACT, FrameworkType.ANGULAR, FrameworkType.VUE]:
            return "framework"
        
        # Contenteditable elements
        if element.element_type == InputElementType.CONTENTEDITABLE:
            return "javascript"
        
        # Standard input elements
        return "selenium"
    
    def _inject_selenium(self, text: str, element: InputElement) -> bool:
        """Standard Selenium text injection."""
        try:
            # Focus element
            self.action_chains.move_to_element(element.element).click().perform()
            
            # Clear existing content
            element.element.clear()
            
            # Type text
            element.element.send_keys(text)
            
            # Trigger change events
            self.driver.execute_script("arguments[0].dispatchEvent(new Event('input', {bubbles: true}));", element.element)
            self.driver.execute_script("arguments[0].dispatchEvent(new Event('change', {bubbles: true}));", element.element)
            
            return True
            
        except Exception as e:
            logger.error(f"Selenium injection failed: {e}")
            return False
    
    def _inject_javascript(self, text: str, element: InputElement) -> bool:
        """JavaScript-based text injection for contenteditable elements."""
        try:
            script = """
            var element = arguments[0];
            var text = arguments[1];
            
            // Focus element
            element.focus();
            
            // Set content based on element type
            if (element.contentEditable === 'true') {
                element.innerHTML = text;
            } else {
                element.value = text;
            }
            
            // Trigger events
            element.dispatchEvent(new Event('input', {bubbles: true}));
            element.dispatchEvent(new Event('change', {bubbles: true}));
            
            return true;
            """
            
            result = self.driver.execute_script(script, element.element, text)
            return bool(result)
            
        except Exception as e:
            logger.error(f"JavaScript injection failed: {e}")
            return False
    
    def _inject_framework_specific(self, text: str, element: InputElement) -> bool:
        """Framework-specific injection methods."""
        try:
            if element.framework == FrameworkType.REACT:
                return self._inject_react(text, element)
            elif element.framework == FrameworkType.ANGULAR:
                return self._inject_angular(text, element)
            elif element.framework == FrameworkType.VUE:
                return self._inject_vue(text, element)
            elif element.element_type == InputElementType.TINYMCE:
                return self._inject_tinymce(text, element)
            elif element.element_type == InputElementType.QUILL:
                return self._inject_quill(text, element)
            elif element.element_type == InputElementType.CKEDITOR:
                return self._inject_ckeditor(text, element)
            else:
                return self._inject_javascript(text, element)
                
        except Exception as e:
            logger.error(f"Framework-specific injection failed: {e}")
            return False
    
    def _inject_react(self, text: str, element: InputElement) -> bool:
        """React-specific injection with proper state updates."""
        script = """
        var element = arguments[0];
        var text = arguments[1];
        
        // Find React fiber
        var reactKey = Object.keys(element).find(key => key.startsWith('__reactInternalInstance') || key.startsWith('_reactInternalFiber'));
        if (reactKey) {
            var reactElement = element[reactKey];
            
            // Simulate user input to trigger React's synthetic events
            element.focus();
            
            // Set value
            element.value = text;
            
            // Trigger React events
            var inputEvent = new Event('input', { bubbles: true });
            var changeEvent = new Event('change', { bubbles: true });
            
            // Dispatch events that React listens for
            element.dispatchEvent(inputEvent);
            element.dispatchEvent(changeEvent);
            
            return true;
        }
        return false;
        """
        
        return bool(self.driver.execute_script(script, element.element, text))
    
    def _inject_angular(self, text: str, element: InputElement) -> bool:
        """Angular-specific injection with proper model updates."""
        script = """
        var element = arguments[0];
        var text = arguments[1];
        
        // Focus and set value
        element.focus();
        element.value = text;
        
        // Trigger Angular events
        element.dispatchEvent(new Event('input', {bubbles: true}));
        element.dispatchEvent(new Event('change', {bubbles: true}));
        element.dispatchEvent(new Event('blur', {bubbles: true}));
        
        // If Angular is available, trigger digest cycle
        if (window.angular) {
            var scope = window.angular.element(element).scope();
            if (scope) {
                scope.$apply();
            }
        }
        
        return true;
        """
        
        return bool(self.driver.execute_script(script, element.element, text))
    
    def _inject_vue(self, text: str, element: InputElement) -> bool:
        """Vue.js-specific injection with proper reactivity."""
        script = """
        var element = arguments[0];
        var text = arguments[1];
        
        // Focus and set value
        element.focus();
        element.value = text;
        
        // Trigger Vue events
        element.dispatchEvent(new Event('input', {bubbles: true}));
        element.dispatchEvent(new Event('change', {bubbles: true}));
        
        return true;
        """
        
        return bool(self.driver.execute_script(script, element.element, text))
    
    def _inject_tinymce(self, text: str, element: InputElement) -> bool:
        """TinyMCE rich text editor injection."""
        script = """
        var text = arguments[0];
        
        // Find TinyMCE instance
        if (window.tinymce) {
            var editors = tinymce.editors;
            for (var i = 0; i < editors.length; i++) {
                var editor = editors[i];
                if (editor.iframeElement && editor.iframeElement.contentDocument.activeElement) {
                    editor.setContent(text);
                    editor.fire('change');
                    return true;
                }
            }
        }
        return false;
        """
        
        return bool(self.driver.execute_script(script, text))
    
    def _inject_quill(self, text: str, element: InputElement) -> bool:
        """Quill editor injection."""
        script = """
        var element = arguments[0];
        var text = arguments[1];
        
        // Find Quill instance
        if (window.Quill) {
            var quill = element.__quill || element.closest('.ql-container').__quill;
            if (quill) {
                quill.setText(text);
                quill.focus();
                return true;
            }
        }
        
        // Fallback to direct content setting
        element.innerHTML = '<p>' + text + '</p>';
        element.dispatchEvent(new Event('input', {bubbles: true}));
        return true;
        """
        
        return bool(self.driver.execute_script(script, element.element, text))
    
    def _inject_ckeditor(self, text: str, element: InputElement) -> bool:
        """CKEditor injection."""
        script = """
        var text = arguments[0];
        
        // Find CKEditor instance
        if (window.CKEDITOR) {
            for (var instance in CKEDITOR.instances) {
                var editor = CKEDITOR.instances[instance];
                if (editor.document.$.activeElement) {
                    editor.setData(text);
                    editor.fire('change');
                    return true;
                }
            }
        }
        return false;
        """
        
        return bool(self.driver.execute_script(script, text))
    
    def _inject_native(self, text: str, element: InputElement) -> bool:
        """Native browser injection using clipboard and keyboard simulation."""
        try:
            # This would require additional clipboard handling
            # For now, fallback to selenium injection
            return self._inject_selenium(text, element)
            
        except Exception as e:
            logger.error(f"Native injection failed: {e}")
            return False


class BrowserIntegrationEngine:
    """Main browser integration engine combining all components."""
    
    def __init__(self):
        self.browser_manager = BrowserManager()
        self.default_config = BrowserConfig(
            browser_type=BrowserType.CHROME,
            headless=False,
            timeout=10,
            security_validation=True
        )
        self.current_session = "default"
    
    def initialize(self, config: Optional[BrowserConfig] = None) -> bool:
        """Initialize browser integration with configuration."""
        if not SELENIUM_AVAILABLE:
            logger.error("Browser integration requires selenium - run: pip install selenium webdriver-manager")
            return False
        
        config = config or self.default_config
        driver = self.browser_manager.create_driver(config, self.current_session)
        
        if driver:
            logger.info("Browser integration initialized successfully")
            return True
        else:
            logger.error("Failed to initialize browser integration")
            return False
    
    def inject_text_to_browser(self, text: str, target_url: Optional[str] = None) -> bool:
        """
        Inject text into the active browser element.
        
        Args:
            text: Text to inject
            target_url: Optional URL to navigate to first
            
        Returns:
            True if injection succeeded, False otherwise
        """
        driver = self.browser_manager.get_driver(self.current_session)
        if not driver:
            logger.error("No active browser session - call initialize() first")
            return False
        
        try:
            # Navigate to URL if specified
            if target_url:
                driver.get(target_url)
                time.sleep(2)  # Wait for page load
            
            # Create text injector
            injector = TextInjector(driver)
            
            # Inject text
            success = injector.inject_text(text)
            
            if success:
                logger.info(f"Successfully injected text: {text[:50]}...")
            else:
                logger.warning("Text injection failed")
            
            return success
            
        except Exception as e:
            logger.error(f"Browser text injection error: {e}")
            return False
    
    def detect_browser_elements(self) -> List[InputElement]:
        """Detect all input elements in the current browser session."""
        driver = self.browser_manager.get_driver(self.current_session)
        if not driver:
            return []
        
        detector = InputElementDetector(driver)
        return detector.find_input_elements()
    
    def get_browser_info(self) -> Dict[str, Any]:
        """Get information about the current browser session."""
        driver = self.browser_manager.get_driver(self.current_session)
        if not driver:
            return {}
        
        try:
            return {
                "browser_name": driver.capabilities.get("browserName", "unknown"),
                "browser_version": driver.capabilities.get("browserVersion", "unknown"),
                "current_url": driver.current_url,
                "title": driver.title,
                "session_id": self.current_session,
                "window_handles": len(driver.window_handles)
            }
        except:
            return {}
    
    def cleanup(self):
        """Clean up browser resources."""
        self.browser_manager.close_all_drivers()
        logger.info("Browser integration cleaned up")


# Global instance for easy access
browser_engine = BrowserIntegrationEngine()