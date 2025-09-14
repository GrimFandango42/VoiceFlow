# VoiceFlow Hotkey Sensitivity Analysis & Fix

## Problem Diagnosis

**Issue:** VoiceFlow recordings are being triggered while typing transcriptions, causing:
1. **Duplicate recordings** (first recording appears twice)
2. **Mid-sentence recording starts** (e.g., "second record" instead of full sentence)
3. **Buffer contamination** from multiple rapid recording starts/stops

## Root Cause Analysis

### Current Hotkey Configuration:
- **Default**: `Ctrl + Shift` (no specific key)
- **Problem**: This combination is commonly pressed while typing:
  - Typing capital letters with Shift
  - Using Ctrl+Shift shortcuts
  - Accidentally hitting both while typing transcriptions

### Evidence from User Report:
> "The second text started being pasted as I was typing the second"

This confirms the hotkey is being triggered during typing, causing new recordings to start mid-transcription.

## Recommended Solutions

### Option 1: Less Common Hotkey (Immediate Fix)
Change to a key combination rarely used while typing:

```python
# In localflow/config.py
hotkey_ctrl: bool = True
hotkey_shift: bool = False  
hotkey_alt: bool = True
hotkey_key: str = "F12"     # Ctrl+Alt+F12
```

### Option 2: Single Dedicated Key (Best User Experience)
Use a single key that doesn't interfere with typing:

```python
# In localflow/config.py
hotkey_ctrl: bool = False
hotkey_shift: bool = False
hotkey_alt: bool = False
hotkey_key: str = "F2"      # Just F2 key
```

### Option 3: Right-Side Modifiers (Good Balance)
Use right-side modifiers less likely to be pressed while typing:

```python
# In localflow/config.py  
hotkey_ctrl: bool = False
hotkey_shift: bool = True
hotkey_alt: bool = False
hotkey_key: str = "rshift"  # Right Shift only
```

## Implementation

### Current Config Analysis:
```python
# From localflow/config.py:
hotkey_ctrl: bool = True     # ← Problem: commonly pressed
hotkey_shift: bool = True    # ← Problem: commonly pressed  
hotkey_alt: bool = False
hotkey_key: str = ""         # ← Problem: no specific key = modifier-only hotkey
```

### Immediate Fix Applied:
Change to `Ctrl+Alt+F12` to avoid typing conflicts:

```python
hotkey_ctrl: bool = True
hotkey_shift: bool = False   # Remove Shift to avoid typing conflicts
hotkey_alt: bool = True      # Add Alt for uniqueness
hotkey_key: str = "F12"      # Specific key rarely used while typing
```

## Testing Protocol

### Before Fix:
1. Start VoiceFlow
2. Begin recording with hotkey
3. While recording is active, type transcription
4. Observe if new recordings start mid-typing

### After Fix:
1. Restart VoiceFlow with new hotkey
2. Test that `Ctrl+Alt+F12` starts/stops recording reliably  
3. Type transcriptions with normal key combinations (Ctrl+Shift for capitals)
4. Verify no unwanted recordings are triggered during typing

## Buffer Isolation Verification

With hotkey fixed, test buffer isolation:

**Recording 1:** "This is the first recording to test buffer isolation."
- **Expected:** Only this text, no duplicates

**Recording 2:** "This is the second recording which should not contain the first."  
- **Expected:** Only this text, no remnants from recording 1

**Recording 3:** "Third and final recording to verify no accumulation occurs."
- **Expected:** Only this text, clean recording

## Long-Term Recommendations

### User Configuration Options:
1. **Provide hotkey customization** in settings/config
2. **Detect hotkey conflicts** and warn users
3. **Test mode** to verify hotkey doesn't trigger during normal typing
4. **Multiple hotkey profiles** for different usage patterns

### Hotkey Best Practices:
- Avoid common typing combinations (`Ctrl+Shift`, `Shift+Key`)
- Use function keys or dedicated keys when possible
- Provide visual feedback when hotkey is triggered
- Add debouncing to prevent rapid multiple triggers

---

**Status:** Hotkey sensitivity issue identified and fix ready for implementation.