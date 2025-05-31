# Contributing to VoiceFlow

First off, thank you for considering contributing to VoiceFlow! It's people like you that make VoiceFlow such a great tool for everyone.

## Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [How Can I Contribute?](#how-can-i-contribute)
4. [Development Setup](#development-setup)
5. [Style Guidelines](#style-guidelines)
6. [Pull Request Process](#pull-request-process)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code:

- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a new branch for your feature/fix
4. Make your changes
5. Push to your fork and submit a pull request

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Screenshots (if applicable)
- System information (OS, GPU, Whisper model used)

**Bug Report Template**:
```markdown
## Description
Brief description of the bug

## Steps to Reproduce
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## Expected Behavior
What you expected to happen

## Actual Behavior
What actually happened

## System Information
- OS: [e.g. Windows 11]
- GPU: [e.g. RTX 4080]
- VoiceFlow Version: [e.g. 1.0.0]
- Whisper Model: [e.g. large-v3]
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- A clear and descriptive title
- A detailed description of the proposed enhancement
- Why this enhancement would be useful
- Possible implementation approach

### Code Contributions

#### Good First Issues
Look for issues labeled `good first issue` - these are specifically tagged for newcomers to the project.

#### Areas We Need Help
- **UI/UX improvements**: React components, styling
- **Performance optimization**: GPU utilization, memory management
- **Language support**: Adding new languages to Whisper
- **Documentation**: Tutorials, guides, translations
- **Testing**: Unit tests, integration tests
- **Platform support**: Linux/macOS versions

## Development Setup

### Prerequisites
- Node.js 16+
- Rust 1.70+
- Python 3.10+
- NVIDIA GPU with CUDA (for testing)
- Git

### Setting Up Your Development Environment

1. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/voiceflow.git
   cd voiceflow
   ```

2. **Install dependencies**
   ```bash
   # Install Node dependencies
   npm install
   
   # Install Python dependencies
   cd python
   pip install -r requirements.txt
   cd ..
   
   # Install Rust dependencies
   cd src-tauri
   cargo build
   cd ..
   ```

3. **Run in development mode**
   ```bash
   npm run dev
   ```

### Project Structure
```
voiceflow/
├── src/                 # React frontend
│   ├── components/      # React components
│   ├── hooks/          # Custom React hooks
│   ├── utils/          # Utility functions
│   └── App.jsx         # Main app component
├── src-tauri/          # Rust backend
│   ├── src/            # Rust source files
│   └── Cargo.toml      # Rust dependencies
├── python/             # Python STT server
│   ├── server.py       # WebSocket server
│   ├── stt_engine.py   # Whisper integration
│   └── processors/     # Audio processors
└── scripts/            # Build and utility scripts
```

## Style Guidelines

### JavaScript/React Style
- Use ES6+ features
- Functional components with hooks
- Meaningful variable and function names
- Comment complex logic

```javascript
// Good
const TranscriptionDisplay = ({ text, isProcessing }) => {
  const formattedText = useMemo(() => 
    formatTranscription(text), [text]
  );
  
  return (
    <div className={`transcription ${isProcessing ? 'processing' : ''}`}>
      {formattedText}
    </div>
  );
};

// Avoid
const TD = (props) => {
  return <div>{props.t}</div>
}
```

### Rust Style
- Follow Rust conventions
- Use `rustfmt` for formatting
- Meaningful error messages
- Document public APIs

```rust
// Good
pub fn register_hotkey(shortcut: &str) -> Result<(), HotkeyError> {
    // Implementation with proper error handling
}

// Document public functions
/// Registers a global hotkey for the application
/// 
/// # Arguments
/// * `shortcut` - The key combination (e.g., "Ctrl+Alt+Space")
/// 
/// # Returns
/// * `Ok(())` if successful
/// * `Err(HotkeyError)` if registration fails
```

### Python Style
- Follow PEP 8
- Type hints where applicable
- Docstrings for functions
- Async/await for I/O operations

```python
# Good
async def process_audio(
    audio_data: np.ndarray, 
    model_size: str = "base"
) -> TranscriptionResult:
    """
    Process audio data through Whisper model.
    
    Args:
        audio_data: NumPy array of audio samples
        model_size: Whisper model size to use
        
    Returns:
        TranscriptionResult with text and metadata
    """
    # Implementation
```

### Commit Messages
- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

```
Add GPU memory optimization for large models

- Implement dynamic batch sizing based on available VRAM
- Add fallback to smaller model when memory is low
- Fix memory leak in model switching

Fixes #123
```

## Pull Request Process

1. **Before submitting**
   - Ensure all tests pass
   - Update documentation if needed
   - Add tests for new functionality
   - Run linters and formatters

2. **PR Description**
   - Clearly describe what changes you've made
   - Link to related issues
   - Include screenshots for UI changes
   - List any breaking changes

3. **PR Template**
   ```markdown
   ## Description
   Brief description of changes
   
   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update
   
   ## Testing
   - [ ] My code follows the style guidelines
   - [ ] I have performed a self-review
   - [ ] I have added tests
   - [ ] All tests pass locally
   
   ## Screenshots (if applicable)
   
   ## Related Issues
   Fixes #(issue)
   ```

4. **Review Process**
   - A maintainer will review your PR
   - Address any feedback
   - Once approved, it will be merged

## Testing

### Running Tests
```bash
# Frontend tests
npm test

# Rust tests
cd src-tauri
cargo test

# Python tests
cd python
pytest
```

### Writing Tests
- Write tests for new features
- Ensure edge cases are covered
- Mock external dependencies
- Keep tests focused and fast

## Documentation

When adding new features:
1. Update the README if needed
2. Add to USER_GUIDE.md for user-facing features
3. Update ARCHITECTURE.md for structural changes
4. Add JSDoc/rustdoc/docstrings for new functions

## Questions?

Feel free to:
- Open an issue for discussion
- Ask in our Discord community
- Email the maintainers

Thank you for contributing to VoiceFlow! 🎉