# VoiceFlow VS Code Extension

Advanced voice-to-text integration with syntax-aware text injection and programming language support for Visual Studio Code.

## Features

### 🎤 Voice Input
- **Smart Voice Recording**: High-quality speech-to-text with noise reduction
- **Hotkey Support**: Quick activation with `Ctrl+Alt+V` (or `Cmd+Alt+V` on Mac)
- **Real-time Status**: Visual feedback in status bar during recording

### 🧠 Intelligent Code Generation
- **Context-Aware Processing**: Understands where you are in your code
- **Language-Specific Formatting**: Automatic formatting for Python, JavaScript, Java, C++, and more
- **AI-Enhanced Text**: Leverages AI to improve transcription accuracy and code quality

### 🎯 Syntax-Aware Text Injection
- **Preserves Syntax Highlighting**: Maintains code highlighting after text insertion
- **Smart Indentation**: Automatically matches current indentation level
- **Context Detection**: Recognizes comments, strings, functions, variables, and classes

### 🔧 Programming Language Support
- **Python**: Snake_case variables, proper function definitions, PEP 8 compliance
- **JavaScript/TypeScript**: CamelCase conventions, modern ES6+ syntax
- **Java**: CamelCase methods, PascalCase classes, proper access modifiers
- **C/C++**: Snake_case or camelCase, proper header inclusion
- **HTML/CSS**: Proper tag structure and attribute formatting

### ⚙️ Customizable Settings
- **Smart Mode**: Toggle intelligent context processing
- **Auto-Formatting**: Enable/disable automatic code formatting
- **AI Enhancement**: Control AI-powered text improvement
- **Debug Mode**: Detailed logging for troubleshooting

## Installation

### Prerequisites
1. **VoiceFlow Server**: Ensure the VoiceFlow server is running on your system
2. **VS Code**: Version 1.70.0 or higher

### From VSIX File
1. Download the latest `.vsix` file from releases
2. Open VS Code
3. Run command: `Extensions: Install from VSIX...`
4. Select the downloaded `.vsix` file

### Manual Installation
1. Clone this repository
2. Navigate to the extension directory:
   ```bash
   cd vscode-extension
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Compile TypeScript:
   ```bash
   npm run compile
   ```
5. Press `F5` to launch a new VS Code window with the extension loaded

## Configuration

Access settings via `File > Preferences > Settings` and search for "VoiceFlow":

```json
{
    "voiceflow.serverUrl": "http://localhost:8000",
    "voiceflow.smartMode": true,
    "voiceflow.autoFormat": true,
    "voiceflow.showStatusBar": true,
    "voiceflow.aiEnhancement": true,
    "voiceflow.languageSpecificPrompts": true,
    "voiceflow.preserveSyntaxHighlighting": true,
    "voiceflow.debugMode": false
}
```

### Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `serverUrl` | `http://localhost:8000` | VoiceFlow server URL |
| `smartMode` | `true` | Enable context-aware processing |
| `autoFormat` | `true` | Automatically format injected text |
| `showStatusBar` | `true` | Show status in VS Code status bar |
| `aiEnhancement` | `true` | Enable AI-powered text enhancement |
| `languageSpecificPrompts` | `true` | Use language-specific AI prompts |
| `preserveSyntaxHighlighting` | `true` | Maintain syntax highlighting |
| `debugMode` | `false` | Enable detailed logging |

## Usage

### Basic Voice Input
1. Place cursor where you want to insert text
2. Press `Ctrl+Alt+V` (or `Cmd+Alt+V` on Mac)
3. Speak your text
4. Press `Escape` to stop recording

### Smart Programming Mode
When Smart Mode is enabled, the extension automatically:
- Detects the programming language
- Analyzes the current code context
- Formats text according to language conventions
- Applies proper indentation and syntax

### Commands

Access via Command Palette (`Ctrl+Shift+P`):

- `VoiceFlow: Start Voice Input` - Begin voice recording
- `VoiceFlow: Stop Voice Input` - End voice recording
- `VoiceFlow: Inject Text at Cursor` - Manually input text
- `VoiceFlow: Toggle Smart Programming Mode` - Enable/disable smart mode
- `VoiceFlow: Show VoiceFlow Status` - Display status panel
- `VoiceFlow: Open VoiceFlow Settings` - Quick access to settings

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Alt+V` | Start voice input |
| `Escape` | Stop voice input (when listening) |
| `Ctrl+Alt+Shift+V` | Toggle smart mode |

## Language-Specific Examples

### Python
**Voice Input**: "hello world function"
**Generated Code**:
```python
def hello_world():
```

**Voice Input**: "user name variable"
**Generated Code**:
```python
user_name = 
```

### JavaScript
**Voice Input**: "calculate total function"
**Generated Code**:
```javascript
function calculateTotal() {
```

**Voice Input**: "user data variable"
**Generated Code**:
```javascript
const userData = 
```

### Java
**Voice Input**: "process data method"
**Generated Code**:
```java
public void processData() {
```

### Comments
**Voice Input**: "this calculates the total price"
**Generated Code**:
- Python: `# This calculates the total price`
- JavaScript: `// This calculates the total price`
- Java: `// This calculates the total price`

## Troubleshooting

### Connection Issues
1. Verify VoiceFlow server is running: `http://localhost:8000`
2. Check server URL in settings
3. Restart VS Code and the VoiceFlow server

### Voice Input Not Working
1. Check microphone permissions
2. Ensure audio drivers are up to date
3. Test voice input with other applications
4. Enable debug mode for detailed logs

### Formatting Issues
1. Disable auto-format temporarily
2. Check language detection accuracy
3. Manually specify language context

### Performance Issues
1. Disable AI enhancement if too slow
2. Reduce context window size
3. Check server performance

## Debug Information

Enable debug mode in settings to see detailed logs in the Output panel:
1. Open Output panel (`View > Output`)
2. Select "VoiceFlow" from dropdown
3. Enable `voiceflow.debugMode` in settings

## API Integration

The extension communicates with the VoiceFlow server via WebSocket and HTTP APIs:

### WebSocket Messages
- `start_listening`: Begin voice input session
- `stop_listening`: End voice input session
- `transcription`: Receive transcribed text
- `status`: Receive status updates
- `error`: Receive error notifications

### HTTP Endpoints
- `POST /api/enhance`: Text enhancement with context
- `GET /api/status`: Server status information
- `GET /api/languages`: Supported languages

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Development Setup
```bash
npm install
npm run compile
npm run watch  # For continuous compilation
```

## License

MIT License - see LICENSE file for details

## Support

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Comprehensive guides available in the docs folder
- **Community**: Join discussions in the project forums

---

**Note**: This extension requires the VoiceFlow server to be running. Ensure proper server setup before using the extension.