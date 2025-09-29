# VoiceFlow Project Structure

## Root Directory (18 files - Clean!)
```
VoiceFlow/
├── README.md                    # Main project documentation
├── CLAUDE.md                    # Claude Code instructions
├── CONSTITUTION.md              # Development principles
├── PROJECT_STRUCTURE.md         # This file
├── tasks.md                     # Current tasks
├── pyproject.toml              # Python project configuration
├── pytest.ini                 # Test configuration
├── requirements.txt            # Python dependencies
├── icon.ico                    # Application icon
├── .env                        # Environment variables
├── .env.example               # Environment template
├── .gitignore                 # Git ignore rules
├── .claude_code_config.json   # Claude Code configuration
└── .coverage                  # Test coverage data
```

## Organized Directory Structure

### Core Application
```
src/voiceflow/
├── core/                      # Core functionality
│   ├── asr_production.py      # Production ASR (recommended)
│   ├── asr_modern.py          # Modern ASR (fallback)
│   ├── asr_enhanced.py        # Enhanced ASR features
│   ├── self_correcting_asr.py # AI self-correction
│   ├── smart_formatter.py     # Text formatting
│   ├── config.py              # Configuration management
│   ├── audio_enhanced.py      # Audio recording
│   ├── textproc.py           # Text processing
│   └── archive/              # Deprecated implementations
│
├── ui/                       # User interfaces
│   ├── cli_enhanced.py       # Main CLI interface
│   ├── cli_ultra_performance.py # Performance CLI
│   ├── enhanced_tray.py      # System tray
│   ├── visual_indicators.py  # Visual feedback
│   └── archive/              # Deprecated UIs
│
├── integrations/             # External integrations
│   ├── hotkeys_enhanced.py   # Hotkey handling
│   └── inject.py            # Text injection
│
├── utils/                    # Utilities
│   ├── logging_setup.py     # Logging configuration
│   ├── settings.py          # Settings management
│   ├── utils.py             # General utilities
│   ├── buffer_overflow_protection.py
│   ├── idle_aware_monitor.py
│   └── process_monitor.py
│
├── models/                   # Data models
└── stability/               # Stability modules
```

### Tools and Management
```
tools/
├── VoiceFlow_Control_Center.py  # Main GUI controller
├── quality_monitor.py           # Quality monitoring GUI
└── stability_test_runner.py     # Stability testing
```

### Documentation
```
docs/
├── guides/                   # User guides
│   ├── AGENTS.md
│   ├── APPLICATION_SPECIFIC_TEST_SCENARIOS.md
│   ├── CRITICAL_GUARDRAILS_USER_TESTING_GUIDE.md
│   └── LAUNCH_INSTRUCTIONS.md
│
├── reports/                  # Assessment reports
│   ├── COMPREHENSIVE_FIX_SUMMARY.md
│   ├── HOTKEY_FIX_SUMMARY.md
│   ├── NONETYPE_FIX_SUMMARY.md
│   ├── PRODUCTION_READINESS_EVALUATION.md
│   └── SECURITY_ASSESSMENT_REPORT.md
│
└── archive/                  # Archived documentation
    ├── CHANGELOG.md
    ├── IMPLEMENTATION_COMPLETE.md
    ├── IMPROVEMENT_PLAN.md
    └── research.md
```

### Scripts and Testing
```
scripts/
├── launcher/                 # Launch scripts
│   ├── LAUNCH_VOICEFLOW.bat
│   ├── START_VOICEFLOW.bat
│   └── temp_set_env.bat
│
├── testing/                  # Test scripts
│   ├── comprehensive_integration_test.py
│   ├── comprehensive_test_suite.py
│   ├── real_world_test.py
│   ├── simple_integration_test.py
│   ├── stress_test_long_sessions.py
│   ├── test_*.py files
│   ├── stability_test_results/
│   └── *.json test results
│
├── debugging/                # Debug utilities
│   ├── debug_hang_issue.py
│   └── debug_nonetype_issue.py
│
├── utilities/                # Utility scripts
│   ├── benchmark_asr.py
│   ├── minimal_voiceflow.py
│   ├── simple_transcriber.py
│   └── force_cleanup.py
│
└── setup/                    # Setup and installation
    └── installation_report.json
```

### Examples and Specifications
```
examples/
└── implementations/          # Example implementations
    ├── voiceflow_fixed.py    # Bug fix example
    ├── voiceflow_intelligent.py # AI enhancement example
    └── voiceflow_warm_start.py  # Cold start optimization

specs/                        # Project specifications
└── 002-comprehensive-voiceflow-stability/
    ├── spec.md
    ├── plan.md
    └── tasks.md
```

### Test Suites
```
tests/
├── unit/                     # Unit tests
├── integration/              # Integration tests
├── performance/              # Performance tests
├── stability/                # Stability tests
├── contract/                 # Contract tests
└── conftest.py              # Test configuration
```

## Key Benefits of This Structure

1. **Clean Root**: Reduced from 86 to 18 files in root directory
2. **Logical Organization**: Related files grouped by function
3. **Easy Navigation**: Clear hierarchy for finding code
4. **Archive Strategy**: Deprecated code preserved but organized
5. **Documentation Structure**: Guides, reports, and archives separated
6. **Testing Organization**: Different test types clearly separated
7. **Script Management**: Launch, test, debug, and utility scripts organized

## Active Components

### Production-Ready
- `src/voiceflow/core/asr_production.py` - Main ASR implementation
- `src/voiceflow/ui/cli_enhanced.py` - Primary CLI interface
- `tools/VoiceFlow_Control_Center.py` - GUI management
- `src/voiceflow/core/self_correcting_asr.py` - AI enhancements

### Working Examples
- `examples/implementations/voiceflow_intelligent.py` - Complete working solution
- `examples/implementations/voiceflow_warm_start.py` - Cold start optimization
- `examples/implementations/voiceflow_fixed.py` - State management fixes

### Utilities
- `scripts/utilities/force_cleanup.py` - Emergency cleanup
- `tools/quality_monitor.py` - Real-time quality monitoring
- `scripts/testing/comprehensive_test_suite.py` - Full test suite