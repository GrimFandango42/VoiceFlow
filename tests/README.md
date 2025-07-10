# VoiceFlow Unit Tests

This directory contains comprehensive unit tests for the VoiceFlow core modules.

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures and pytest configuration
├── test_voiceflow_core.py   # Tests for core engine functionality
├── test_ai_enhancement.py   # Tests for AI enhancement module
├── test_config.py          # Tests for configuration management
├── test_integration.py     # Integration tests
└── README.md              # This file
```

## Running Tests

### Quick Start

```bash
# Run all tests
python run_tests.py

# Run specific test suite
python run_tests.py core
python run_tests.py ai
python run_tests.py config
python run_tests.py integration

# Run with coverage
python run_tests.py --coverage

# Run only fast tests
python run_tests.py --fast

# Run only unit tests (skip integration)
python run_tests.py --unit
```

### Using pytest directly

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_voiceflow_core.py

# Run specific test
pytest tests/test_voiceflow_core.py::TestVoiceFlowEngine::test_initialization

# Run with coverage
pytest --cov=core --cov=utils --cov-report=html

# Run tests matching a pattern
pytest -k "audio"

# Run tests with specific marker
pytest -m "not slow"
pytest -m "not integration"
```

## Test Coverage

### Core Module Tests (`test_voiceflow_core.py`)

- **VoiceFlowEngine Initialization**
  - Default configuration
  - Custom configuration
  - Directory creation
  - Error handling

- **Database Operations**
  - Schema creation
  - Transcription storage
  - Error recovery

- **Audio Recorder Setup**
  - GPU/CPU fallback logic
  - Model selection
  - Parameter configuration
  - Complete failure handling

- **Speech Processing**
  - Successful transcription
  - Empty results
  - Rapid call prevention
  - Error handling
  - Callback integration

- **Text Injection**
  - Successful injection
  - System integration disabled
  - Error handling

- **Hotkey Management**
  - Registration
  - Custom callbacks
  - Default behavior
  - System integration disabled

- **Statistics Tracking**
  - Transcription counting
  - Word counting
  - Processing time tracking
  - Empty statistics

### AI Enhancement Tests (`test_ai_enhancement.py`)

- **AIEnhancer Initialization**
  - Default configuration
  - Custom configuration
  - Environment variables
  - Connection testing

- **Ollama Connection**
  - Successful connection
  - Model validation
  - Fallback to available models
  - Connection failures
  - Multiple URL attempts

- **Text Enhancement**
  - Successful enhancement
  - Different contexts (email, code, document, chat)
  - Empty input handling
  - Connection unavailable
  - Error responses
  - Request exceptions

- **Prompt Generation**
  - Context-aware prompts
  - Default prompts

- **Response Cleaning**
  - Quote removal
  - Prefix removal
  - Whitespace handling

- **Basic Formatting**
  - Capitalization
  - Punctuation
  - Text replacements
  - Special commands

### Configuration Tests (`test_config.py`)

- **Configuration Loading**
  - Default values
  - File loading
  - Environment variables
  - Priority ordering
  - Error handling

- **Configuration Access**
  - Get with defaults
  - Section retrieval
  - Runtime updates
  - Nonexistent keys

- **Configuration Persistence**
  - Saving to file
  - Creating examples
  - Error handling

- **Global Functions**
  - Singleton pattern
  - Helper functions
  - Configuration loading

### Integration Tests (`test_integration.py`)

- **Component Integration**
  - Engine with AI enhancement
  - Configuration flow
  - Full processing pipeline
  - Error cascading

- **Performance Tracking**
  - Multiple operations
  - Statistics aggregation
  - Database persistence

- **Environment Integration**
  - Variable propagation
  - Component coordination

## Test Markers

Tests are marked for easy filtering:

- `@pytest.mark.slow` - Long-running tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.requires_audio` - Tests needing audio hardware
- `@pytest.mark.requires_ollama` - Tests needing Ollama server

## Writing New Tests

### Test Structure

```python
class TestMyComponent:
    """Test suite for MyComponent."""
    
    @pytest.fixture
    def my_fixture(self):
        """Setup fixture for tests."""
        # Setup
        yield resource
        # Teardown
    
    def test_feature(self, my_fixture):
        """Test specific feature."""
        # Arrange
        expected = "expected_value"
        
        # Act
        result = my_fixture.do_something()
        
        # Assert
        assert result == expected
```

### Best Practices

1. **Isolation**: Each test should be independent
2. **Clarity**: Test names should describe what they test
3. **Simplicity**: One assertion per test when possible
4. **Completeness**: Test both success and failure cases
5. **Performance**: Mark slow tests appropriately

### Common Fixtures

From `conftest.py`:

- `temp_home_dir` - Temporary home directory
- `mock_audio_recorder` - Mocked AudioToTextRecorder
- `mock_requests` - Mocked HTTP requests
- `mock_system_integration` - Mocked system integration
- `sample_audio_data` - Sample audio for testing
- `mock_ollama_models` - Mock Ollama model list

## Continuous Integration

Tests are designed to run in CI environments:

```bash
# CI-friendly test run
pytest --tb=short --quiet --no-header

# Generate JUnit XML report
pytest --junitxml=test-results.xml

# Generate coverage XML for CI
pytest --cov --cov-report=xml
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure you're running from the project root
2. **Missing Dependencies**: Install test requirements: `pip install -r requirements_testing.txt`
3. **Permission Errors**: Some tests create temporary files - ensure write permissions
4. **Slow Tests**: Use `--fast` flag to skip slow tests during development

### Debugging

```bash
# Drop into debugger on failure
pytest --pdb

# Show local variables on failure
pytest -l

# Run previously failed tests
pytest --lf

# Verbose output
pytest -vv
```