# VoiceFlow Browser Integration

Advanced browser automation and text injection capabilities for VoiceFlow, enabling intelligent speech-to-text integration with web applications.

## Overview

The VoiceFlow Browser Integration system provides comprehensive support for injecting speech-to-text results directly into web forms, applications, and rich text editors. It replaces simulation-only testing with real browser automation using Selenium WebDriver.

## Features

### ✅ Real Browser Automation
- **WebDriver Integration**: Uses Selenium WebDriver for actual browser control
- **Multi-Browser Support**: Chrome, Firefox, Edge, and Safari compatibility
- **Headless Operation**: Can run with or without GUI for different use cases
- **Session Management**: Proper browser lifecycle management with cleanup

### ✅ Intelligent Input Detection
- **Element Classification**: Automatically detects and classifies input elements
- **Framework Detection**: Recognizes React, Angular, Vue, and vanilla frameworks
- **Rich Text Editor Support**: TinyMCE, Quill, CKEditor, Monaco, CodeMirror
- **Input Types**: text, email, password, search, textarea, contenteditable

### ✅ Advanced Text Injection
- **Multiple Methods**: Selenium, JavaScript, framework-specific, and fallback methods
- **Intelligent Selection**: Automatically chooses the best injection method
- **Framework Integration**: Proper event handling for React, Angular, Vue
- **Security Validation**: Prevents XSS and malicious code injection

### ✅ Cross-Browser Compatibility
- **Chrome**: Full support with extension capabilities
- **Firefox**: Native messaging API integration
- **Edge**: Chromium-based automation
- **Safari**: macOS-specific support

## Installation

### Requirements

```bash
# Core requirements
pip install selenium>=4.15.0
pip install webdriver-manager>=4.0.0
pip install beautifulsoup4>=4.12.0
pip install lxml>=4.9.0

# Testing requirements (optional)
pip install pytest-selenium>=4.1.0
pip install pytest-html>=3.2.0
```

### Automatic Installation

The browser integration dependencies are automatically included when you install VoiceFlow:

```bash
# Windows
pip install -r requirements_windows.txt

# Unix/Linux/macOS
pip install -r requirements_unix.txt

# Testing
pip install -r requirements_testing.txt
```

## Quick Start

### Basic Usage

```python
from core.voiceflow_core import create_engine

# Create engine with browser integration
config = {
    'model': 'base',
    'browser_type': 'chrome',
    'browser_headless': False,  # Set to True for headless mode
    'browser_timeout': 30
}

engine = create_engine(config)

# Open browser session
engine.open_browser_session(url="https://example.com")

# Process speech and inject text
speech_result = engine.process_speech()
if speech_result:
    success = engine.inject_text(speech_result, injection_method="auto")
    print(f"Text injection: {'success' if success else 'failed'}")

# Cleanup
engine.cleanup()
```

### Advanced Configuration

```python
from core.browser_integration import BrowserConfig, BrowserType

# Custom browser configuration
browser_config = BrowserConfig(
    browser_type=BrowserType.CHROME,
    headless=True,
    user_data_dir="/path/to/user/data",
    window_size=(1920, 1080),
    timeout=30,
    security_validation=True
)

engine = BrowserIntegrationEngine()
engine.initialize(browser_config)
```

## Text Injection Methods

### 1. Auto Method Selection (Recommended)

```python
# Automatically chooses the best method
engine.inject_text("Hello, World!", injection_method="auto")
```

The auto method intelligently selects between:
- **Browser method**: For web applications with detected input elements
- **System method**: For desktop applications and fallback scenarios
- **Fallback method**: Clipboard-based injection when other methods fail

### 2. Browser Method

```python
# Force browser-based injection
engine.inject_text("Hello, World!", injection_method="browser")
```

Uses advanced Selenium automation with:
- Element detection and classification
- Framework-specific event handling
- Rich text editor support
- Security validation

### 3. System Method

```python
# Traditional system-level injection
engine.inject_text("Hello, World!", injection_method="system")
```

Uses pyautogui for:
- Desktop application compatibility
- Simple text field injection
- Cross-platform support

### 4. Fallback Method

```python
# Clipboard-based fallback
engine.inject_text("Hello, World!", injection_method="fallback")
```

Copies text to clipboard when other methods fail.

## Supported Input Types

### Standard HTML Inputs
- `<input type="text">` - Text inputs
- `<input type="email">` - Email inputs
- `<input type="password">` - Password fields
- `<input type="search">` - Search boxes
- `<input type="url">` - URL inputs
- `<input type="tel">` - Phone number inputs
- `<textarea>` - Multi-line text areas

### Rich Text Editors
- **TinyMCE**: Popular WYSIWYG editor
- **Quill**: Modern rich text editor
- **CKEditor**: Classic rich text editor
- **Monaco Editor**: VS Code-style editor
- **CodeMirror**: Code editor

### Content Editable
- `<div contenteditable="true">` - Editable divs
- Custom rich text implementations

### Framework Components
- **React**: Controlled and uncontrolled components
- **Angular**: Reactive forms and template-driven forms
- **Vue.js**: v-model bindings
- **Svelte**: Reactive components

## Browser Detection

The system automatically detects:

### Framework Detection
```python
from core.browser_integration import InputElementDetector

detector = InputElementDetector(driver)
framework = detector.detect_framework()
# Returns: FrameworkType.REACT, ANGULAR, VUE, SVELTE, or VANILLA
```

### Element Detection
```python
elements = detector.find_input_elements()
for element in elements:
    print(f"Type: {element.element_type}")
    print(f"Framework: {element.framework}")
    print(f"Focused: {element.is_focused}")
    print(f"Visible: {element.is_visible}")
```

## Security Features

### XSS Prevention
- Automatically blocks script tags
- Validates JavaScript execution patterns
- Prevents malicious event handlers

### SQL Injection Prevention
- Detects common SQL injection patterns
- Blocks database manipulation attempts

### Content Validation
- Length limits on injected text
- Character encoding validation
- Safe HTML handling

## Testing

### Command Line Interface

```bash
# Run comprehensive test suite
python browser_integration_cli.py test

# Test specific browser
python browser_integration_cli.py test --browser firefox --no-headless

# Detect elements on webpage
python browser_integration_cli.py detect --url https://example.com

# Test text injection
python browser_integration_cli.py inject "Hello World" --url https://google.com

# Interactive testing session
python browser_integration_cli.py interactive --url https://example.com

# Create test HTML page
python browser_integration_cli.py create-test-page
```

### Automated Testing

```bash
# Run browser integration tests
pytest tests/test_browser_integration.py -v

# Run with specific browser
pytest tests/test_browser_integration.py::TestCrossBrowserCompatibility -v

# Generate HTML test report
pytest tests/test_browser_integration.py --html=report.html
```

### Manual Testing

```python
# Run example scripts
python examples/browser_integration_example.py
```

## Configuration Options

### VoiceFlow Engine Configuration

```python
config = {
    # Speech processing
    'model': 'base',
    'device': 'auto',
    
    # Browser integration
    'browser_type': 'chrome',  # chrome, firefox, edge, safari
    'browser_headless': False,  # True for headless mode
    'browser_timeout': 30,      # WebDriver timeout
    
    # Text injection
    'injection_method': 'auto', # auto, browser, system, fallback
    'security_validation': True # Enable security checks
}
```

### Browser-Specific Options

```python
# Chrome options
browser_config = BrowserConfig(
    browser_type=BrowserType.CHROME,
    headless=False,
    user_data_dir="/path/to/chrome/profile",
    extensions=["/path/to/extension.crx"],
    window_size=(1920, 1080),
    timeout=30
)

# Firefox options
browser_config = BrowserConfig(
    browser_type=BrowserType.FIREFOX,
    headless=True,
    timeout=30
)

# Edge options
browser_config = BrowserConfig(
    browser_type=BrowserType.EDGE,
    headless=False,
    user_data_dir="/path/to/edge/profile",
    timeout=30
)
```

## API Reference

### BrowserIntegrationEngine

```python
class BrowserIntegrationEngine:
    def initialize(self, config: BrowserConfig) -> bool:
        """Initialize browser with configuration"""
    
    def inject_text_to_browser(self, text: str, target_url: str = None) -> bool:
        """Inject text into browser element"""
    
    def detect_browser_elements(self) -> List[InputElement]:
        """Detect input elements on current page"""
    
    def get_browser_info(self) -> Dict[str, Any]:
        """Get current browser session information"""
    
    def cleanup(self):
        """Clean up browser resources"""
```

### VoiceFlowEngine Extensions

```python
class VoiceFlowEngine:
    def inject_text(self, text: str, injection_method: str = "auto") -> bool:
        """Enhanced text injection with method selection"""
    
    def open_browser_session(self, url: str = None, browser_type: str = "chrome") -> bool:
        """Open new browser session"""
    
    def close_browser_session(self):
        """Close current browser session"""
    
    def get_browser_status(self) -> Dict[str, Any]:
        """Get browser integration status"""
    
    def detect_browser_inputs(self) -> List[Dict[str, Any]]:
        """Detect input elements in browser"""
```

## Troubleshooting

### Common Issues

#### Selenium WebDriver Issues
```bash
# Update webdriver-manager
pip install --upgrade webdriver-manager

# Clear driver cache
rm -rf ~/.wdm/
```

#### Permission Errors
```bash
# Linux: Install required packages
sudo apt-get install chromium-browser firefox-esr

# macOS: Install browsers via Homebrew
brew install --cask google-chrome firefox
```

#### Headless Mode Issues
```python
# Try different window sizes
browser_config.window_size = (1280, 720)

# Disable GPU acceleration
options.add_argument("--disable-gpu")
options.add_argument("--no-sandbox")
```

### Debug Mode

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Browser integration debug
config['browser_debug'] = True
```

### Performance Optimization

```python
# Faster page load
browser_config.timeout = 10

# Disable images for faster loading
options.add_argument("--blink-settings=imagesEnabled=false")

# Use existing browser profile
browser_config.user_data_dir = "/path/to/profile"
```

## Best Practices

### 1. Resource Management
- Always call `cleanup()` when done
- Use context managers for automatic cleanup
- Close browser sessions when not needed

### 2. Error Handling
- Check browser integration availability
- Handle WebDriver exceptions gracefully
- Implement fallback methods

### 3. Security
- Enable security validation
- Validate user input before injection
- Use headless mode in production

### 4. Performance
- Reuse browser sessions when possible
- Use appropriate timeouts
- Consider headless mode for speed

### 5. Testing
- Test across multiple browsers
- Use automated test suites
- Validate injection accuracy

## Examples

See `examples/browser_integration_example.py` for comprehensive usage examples.

## License

This browser integration system is part of VoiceFlow and follows the same licensing terms.