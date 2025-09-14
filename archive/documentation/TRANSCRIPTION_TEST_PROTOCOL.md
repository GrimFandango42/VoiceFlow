# VoiceFlow Transcription Accuracy Test Protocol

## Test Purpose
Objective evaluation of transcription accuracy by comparing provided test phrases with actual transcription output.

---

## Test Set 1: Basic Functionality
**Please read the following phrase clearly:**

> "The quick brown fox jumps over the lazy dog near the river bank."

**Expected words:** 13  
**Key vocabulary:** quick, brown, fox, jumps, lazy, dog, river, bank  
**Your transcription:** [PASTE HERE]

---

## Test Set 2: Technical Vocabulary
**Please read the following phrase clearly:**

> "Initialize the API endpoint with OAuth authentication tokens and configure the webhook callback URL."

**Expected words:** 13  
**Key technical terms:** Initialize, API, endpoint, OAuth, authentication, tokens, webhook, callback, URL  
**Your transcription:** [PASTE HERE]

---

## Test Set 3: Numbers and Punctuation Context
**Please read the following phrase clearly:**

> "The server responded with status code 404, indicating the resource was not found at port 8080."

**Expected words:** 15  
**Key elements:** 404, 8080, status code, port  
**Your transcription:** [PASTE HERE]

---

## Test Set 4: Complex Sentence Structure
**Please read the following phrase clearly:**

> "Although the implementation seems complex, we should refactor the database queries before deploying to production environment."

**Expected words:** 16  
**Key phrases:** Although, implementation, refactor, database queries, deploying, production environment  
**Your transcription:** [PASTE HERE]

---

## Test Set 5: Consecutive Recording Test (No Buffer Repeat)
**Recording 1 - Please read:**

> "This is the first recording to test buffer isolation."

**Your transcription:** [PASTE HERE]

**Recording 2 - Please read immediately after:**

> "This is the second recording which should not contain the first."

**Your transcription:** [PASTE HERE]

**Recording 3 - Please read immediately after:**

> "Third and final recording to verify no accumulation occurs."

**Your transcription:** [PASTE HERE]

---

## Test Set 6: Timing Variation Test
**Test 6A - Immediate speech (start speaking immediately after pressing key):**

> "Immediate speech after key press without any pause."

**Your transcription:** [PASTE HERE]

**Test 6B - Short pause (wait 0.5 seconds after pressing key):**

> "Short pause before speaking to test pre-buffer capture."

**Your transcription:** [PASTE HERE]

**Test 6C - Long pause (wait 1.5 seconds after pressing key):**

> "Long pause before speaking to verify timing robustness."

**Your transcription:** [PASTE HERE]

---

## Test Set 7: Natural Conversation Flow
**Please read naturally with normal pauses and intonation:**

> "So, I was thinking about the project timeline, and, um, we might need to adjust our approach. You know, the current implementation isn't quite meeting our performance targets, especially when handling large datasets."

**Expected key points:** project timeline, adjust approach, implementation, performance targets, large datasets  
**Your transcription:** [PASTE HERE]

---

## Evaluation Metrics

### Accuracy Score Calculation:
- **Word Accuracy Rate (WAR):** (Correct words / Total words) × 100%
- **Key Term Accuracy:** (Correct technical terms / Total technical terms) × 100%
- **Buffer Isolation:** Pass/Fail (no repetition from previous recordings)
- **Timing Robustness:** Pass/Fail (all timing variations captured correctly)

### Success Criteria:
- ✅ WAR > 95% for basic sentences
- ✅ WAR > 90% for technical vocabulary
- ✅ No buffer repetition across consecutive recordings
- ✅ All timing variations captured without truncation
- ✅ Natural speech patterns preserved

---

## How to Report Results

After each test, please provide:
1. The exact transcription you received
2. Any observations about timing or behavior
3. Whether audio was cut off at beginning or end
4. Any repeated content from previous recordings

Example format:
```
Test 1 Result:
Transcription: "the quick brown fox jumps over the lazy dog near the river bank"
Observations: Clean capture, no truncation
Issues: None
```

---

## Quick Test Command

To start testing:
```bash
python voiceflow.py --no-tray --lite
```

Then use your configured hotkey (default: Right Shift) to record each test phrase.

---

*This protocol ensures objective evaluation of transcription accuracy and buffer isolation fixes.*