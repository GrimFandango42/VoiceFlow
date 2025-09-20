# User Testing Preferences

## Control Center Launch Preference

**CRITICAL MEMORY**: When ready for user testing, ALWAYS launch the GUI Control Center:
```
python tools/VoiceFlow_Control_Center.py
```

This is the **VoiceFlow Control Center GUI** - the proper testing interface with:
- Quick health checks and tests
- VoiceFlow launch options
- System validation before testing
- Interactive interface for all testing needs

**DO NOT use**:
- Command line scripts
- Simple text-based control centers
- Direct Python launcher calls

## Testing Workflow (REQUIRED)

1. Complete implementation and testing
2. Clean up any temporary scripts
3. **ALWAYS launch `python tools/VoiceFlow_Control_Center.py`**
4. Let user test through the proper GUI Control Center interface

## Directory Organization

- Keep root directory clean (only core files: `voiceflow.py`, `run_personal.py`)
- Move test scripts to `scripts/testing/`
- Use proper launcher structure in `tools/launchers/`

## Why This Matters

The user specifically prefers the GUI Control Center because it provides:
- Visual interface for testing
- Quick health checks before VoiceFlow launch
- Organized testing workflow
- Professional presentation of the system