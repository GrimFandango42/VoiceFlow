# VoiceFlow Known Issues & Improvements

## 📋 Current Status: MVP Working

**Last Updated**: June 1, 2025  
**Version**: v1.0.0-mvp  
**Status**: ✅ Working MVP with known improvement areas

## 🔧 Known Issues (Post-MVP)

### 🔴 **Issue 1: Audio Tail-End Cutoff** (High Priority)

**Problem**: VoiceFlow often doesn't catch the tail end of speech, transcribing only ~90% of what was said.

**User Report**: "it often doesn't catch the tail end of what I'm saying. So ends up transcribing only 90% of what i said."

**Impact**: 
- Reduces transcription accuracy
- Frustrating user experience
- May cut off important words at sentence end

**Potential Causes**:
- Recording stops immediately when keys released
- Voice Activity Detection (VAD) too aggressive
- Audio buffer not capturing final speech segments
- Silence detection threshold too low

**Proposed Solutions**:
1. **Buffer Extension**: Add 0.5-1 second buffer after key release
2. **VAD Tuning**: Adjust silence detection sensitivity
3. **Smart End Detection**: Better algorithm for speech completion
4. **User Configurable**: Allow adjustment of recording tail time

**Priority**: 🔴 High - Core functionality issue

---

### 🟡 **Issue 2: Terminal Environment Compatibility** (Medium Priority)

**Problem**: Text injection doesn't work in terminal environments (specifically WSL terminal in VS Code).

**User Report**: "doesn't seem to work within a terminal environment (it didn't within the wsl terminal in vscode for claude code)"

**Impact**:
- Limits usage in development environments
- Reduces utility for developers who live in terminals
- Missing functionality in VS Code integrated terminal

**Technical Details**:
- Standard Windows text injection methods may not work in terminals
- WSL creates additional layer of complexity
- VS Code integrated terminal has different input handling

**Proposed Solutions**:
1. **Terminal Detection**: Identify terminal applications and use specialized injection
2. **Clipboard Fallback**: Enhanced clipboard integration for terminals
3. **Terminal API**: Direct terminal API integration where available
4. **VS Code Extension**: Consider VS Code-specific integration

**Priority**: 🟡 Medium - Important for developer workflow

---

## 🚀 Improvement Roadmap

### **Phase 1: Audio Quality Enhancement** (Current Sprint)
- [ ] Investigate recording buffer timing
- [ ] Implement configurable tail-end padding
- [ ] Test VAD sensitivity adjustments
- [ ] User testing with various speech patterns

### **Phase 2: Terminal Integration** (Next Sprint)
- [ ] Research terminal injection methods
- [ ] Implement WSL-specific handling
- [ ] Test with multiple terminal applications
- [ ] Develop fallback strategies

### **Phase 3: Advanced Features** (Future)
- [ ] Custom vocabulary training
- [ ] Voice commands beyond transcription
- [ ] Multi-language switching
- [ ] Advanced context awareness

## 🧪 Testing Notes

### **Audio Cutoff Testing**
- **Test Environment**: Various speech lengths and patterns
- **Metrics**: Percentage of speech captured
- **Success Criteria**: >95% speech capture rate

### **Terminal Compatibility Testing**
- **Test Environments**: 
  - VS Code integrated terminal
  - Windows Command Prompt
  - PowerShell
  - WSL bash
  - Git Bash
- **Success Criteria**: Text injection works in >80% of terminal types

## 💡 User Workarounds

### **For Audio Cutoff Issue**:
1. **Speak Slower**: Pause slightly before releasing keys
2. **Add Padding**: Say "period" or "end" to ensure completion
3. **Hold Longer**: Keep keys pressed for extra moment after finishing

### **For Terminal Issues**:
1. **Use Clipboard**: Manually paste (Ctrl+V) after transcription
2. **External Editor**: Transcribe in notepad, then copy to terminal
3. **Voice Note**: Use for planning, type manually in terminal

## 📊 Issue Tracking

| Issue | Priority | Status | Estimated Fix |
|-------|----------|--------|---------------|
| Audio Tail Cutoff | 🔴 High | Investigating | Week 1 |
| Terminal Injection | 🟡 Medium | Planning | Week 2 |

## 🔄 Feedback Loop

**How to Report Issues**:
1. Describe the specific problem
2. Include steps to reproduce
3. Note which applications it affects
4. Mention your speech patterns/style

**User Testing Requests**:
- Try different speaking speeds
- Test in various applications
- Note any patterns in transcription accuracy
- Report which applications work/don't work

---

**Note**: These are quality improvement issues for an already working MVP. VoiceFlow successfully replaces Wispr Flow for most use cases, and these improvements will make it excellent rather than just good.