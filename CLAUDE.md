# VoiceFlow Project Guide for Claude Code

## Development Framework: Specify Infrastructure

**PRIMARY APPROACH**: All development MUST follow the specify framework workflow:

### Core Workflow Commands
1. **`/constitution`** - Establish/update constitutional principles
2. **`/specify`** - Create feature specifications
3. **`/analyze`** - Cross-artifact consistency analysis
4. **`/plan`** - Implementation planning with constitutional compliance
5. **`/implement`** - Execute tasks following constitutional principles

### Constitutional Foundation
- **Constitution Location**: `.specify/memory/constitution.md`
- **Version**: 1.0.0 (AI-First Architecture + Performance Through Persistence + Practical-First Development)
- **Compliance**: All development MUST verify constitutional compliance before implementation

### Project Structure (Specify-Aligned)
```
VoiceFlow/
├── .specify/
│   ├── memory/
│   │   └── constitution.md          # Constitutional principles
│   └── templates/                   # Specify framework templates
├── specs/                           # Feature specifications
│   └── ###-feature-name/
│       ├── spec.md                  # Feature specification
│       ├── plan.md                  # Implementation plan
│       └── tasks.md                 # Execution tasks
├── src/voiceflow/                   # Core implementation
├── tools/                           # User-facing utilities
├── tests/                           # Test suites
└── docs/                           # Documentation
```

## Current Constitutional Principles

### I. AI-First Architecture
- State-of-the-art models (Whisper V3 Turbo, WhisperX) REQUIRED
- Advanced features: word-level timestamps, speaker diarization, context awareness
- Performance optimization: batched inference, GPU acceleration, memory efficiency

### II. Performance Through Persistence
- Load expensive resources once, keep in memory for repeated use
- Model persistence: load once, use for 100+ transcriptions
- Simple locks over complex pooling, graceful degradation required

### III. Practical-First Development
- Working solutions first, then optimize
- Direct fixes for user issues over theoretical edge cases
- Real-world testing with actual usage patterns

### IV. Production-Ready Defaults
- 24/7 operation with intermittent usage patterns
- Support 0.5s commands to 5-minute speeches
- Automatic error recovery without user intervention

### V. Evidence-Based Optimization
- Benchmark before changes, research current practices
- Validate improvements through testing
- Document lessons learned

## Development Commands

### Starting New Features
```bash
# 1. Create specification
/specify "feature description"

# 2. Analyze consistency
/analyze

# 3. Create implementation plan
/plan

# 4. Execute implementation
/implement
```

### Current System Management
```bash
# Launch Control Center (primary interface)
python tools/VoiceFlow_Control_Center.py

# Launch CLI directly
cd src && python -m voiceflow.ui.cli_enhanced

# Run constitutional compliance check
/analyze
```

## Key Implementation Files

### Production Components
- **`src/voiceflow/core/asr_production.py`** - WhisperX integration (constitutional compliance)
- **`src/voiceflow/ui/cli_enhanced.py`** - Primary interface
- **`tools/VoiceFlow_Control_Center.py`** - GUI management
- **`src/voiceflow/core/self_correcting_asr.py`** - AI enhancement layer

### Constitutional Evidence
- **`.specify/memory/constitution.md`** - Formal constitutional framework
- **`specs/002-comprehensive-voiceflow-stability/`** - Completed stability implementation
- **`examples/implementations/`** - Working solutions demonstrating principles

## Compliance Requirements

### Before Any Changes
1. Review `.specify/memory/constitution.md` for applicable principles
2. Run `/analyze` to check current project state
3. Use `/plan` for implementation planning with constitutional verification
4. Ensure performance benchmarking and validation

### Quality Standards
- 70x realtime transcription speed (constitutional requirement)
- 95%+ accuracy in typical conditions
- <5 second first transcription completion
- 24/7 operation capability with automatic recovery

## Framework Enforcement

**MANDATORY**: Use specify framework commands (`/constitution`, `/specify`, `/analyze`, `/plan`, `/implement`) for all development work.

**PROHIBITED**:
- Creating parallel documentation systems
- Bypassing constitutional compliance checks
- Implementing without specification and planning phases
- Making assumptions without evidence-based validation

## Current Status
- ✅ Constitutional framework established (v1.0.0)
- ✅ Production ASR implementation complete
- ✅ Project structure organized and cleaned
- ✅ Specify templates configured
- 🎯 Ready for specify workflow adoption

## Next Steps
1. Run `/analyze` to assess current project consistency
2. Use `/specify` for any new feature development
3. Follow `/plan` → `/implement` workflow for changes
4. Maintain constitutional compliance through framework