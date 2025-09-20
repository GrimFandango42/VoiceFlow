# VoiceFlow Project Memories

## Critical Workflow Requirements

### 🚨 ALWAYS LAUNCH GUI CONTROL CENTER AFTER CHANGES
**This is the #1 most important workflow rule - DO NOT FORGET!**

- After making ANY changes to the VoiceFlow codebase
- After fixing issues, implementing features, or updating configurations
- User explicitly stated: "Remember that every time we're making changes, I shut the control center so that you can re-launch it for me once you're done making all changes"
- User gets frustrated when this is forgotten: "You again feel to launch the GUI Control Center? How do you keep forgetting that?"

**Control Center Locations:**
- Primary: `tools/VoiceFlow_Control_Center.py`
- Testing: `scripts/testing/launch_control_center.py` (has Unicode issues)
- Simple: `scripts/testing/simple_control_center.py` (backup option)

### Health Check Requirements
- Health checks and critical tests MUST pass before handoff
- User emphasized: "I really need to have you make sure that the health checks as well as the critical tests work before you hand off to me"
- Run: `python scripts/dev/quick_smoke_test.py`

### Testing Standards
- Test thoroughly before handing off to user
- User feedback: "Come on, please test thoroughly before handing off to me. This is frustrating."
- Verify all components work together, not just individual pieces

## Current Project Status

### Phase 2 Optimizations ✅ COMPLETED
- GPU acceleration with CUDA fallback
- Dual-model strategy (tiny.en → small.en)
- Advanced VAD for smart chunking
- Batched processing (12.5x speedup potential)
- Fixed visual indicators system
- All health checks passing

### Technical Architecture
- Main ASR: `src/voiceflow/core/advanced_performance_asr.py`
- Config: `src/voiceflow/core/config.py`
- Visual indicators: `src/voiceflow/ui/visual_indicators.py`
- Ultra performance CLI: `src/voiceflow/ui/cli_ultra_performance.py`

### User Testing Feedback History
1. "First sentence was slow" → Fixed with Phase 2 optimizations
2. "Visual indicators not working" → Fixed import and config issues
3. "Buffer issues" → No longer present, system stable
4. "Health checks must work" → All smoke tests now pass (7/7)

### Development Workflow
1. Make changes
2. Run health checks: `python scripts/dev/quick_smoke_test.py`
3. Test integration thoroughly
4. **🚨 LAUNCH GUI CONTROL CENTER** (most important step!)
5. Hand off to user for testing

## Key Lessons Learned
- Always prioritize the GUI Control Center launch
- Health checks are critical before handoff
- Visual system requires careful import handling
- CUDA fallback is essential for reliability
- User values thorough testing over speed