# VoiceFlow User Guide

Welcome to VoiceFlow! This guide will help you get the most out of your voice transcription experience.

## Table of Contents
1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Settings](#settings)
4. [Tips & Tricks](#tips--tricks)
5. [Troubleshooting](#troubleshooting)
6. [Keyboard Shortcuts](#keyboard-shortcuts)

## Getting Started

### First Launch
1. Double-click `VoiceFlow.exe` or use the desktop shortcut
2. VoiceFlow will minimize to your system tray (bottom-right corner)
3. Look for the VoiceFlow icon (blue V) in your system tray
4. Right-click the icon to access the menu

### System Tray Menu
- **Show/Hide** - Toggle the main window
- **Start Recording** - Begin voice transcription
- **Settings** - Configure VoiceFlow
- **Statistics** - View your usage stats
- **Exit** - Close VoiceFlow completely

## Basic Usage

### Recording Voice
1. **Global Hotkey Method** (Recommended)
   - Press `Ctrl + Alt + Space` anywhere on your computer
   - Speak naturally
   - Press `Ctrl + Alt + Space` again to stop

2. **System Tray Method**
   - Right-click the tray icon
   - Click "Start Recording"
   - Click "Stop Recording" when done

3. **Main Window Method**
   - Open VoiceFlow window
   - Click the microphone button
   - Click again to stop

### Understanding the Interface

#### Recording Indicator
- **Blue pulsing dot**: Ready to record
- **Red pulsing dot**: Currently recording
- **Yellow dot**: Processing audio
- **Green checkmark**: Transcription complete

#### Transcription Display
- **Preview text** (gray): Fast, preliminary transcription
- **Final text** (black): Accurate, processed transcription
- **AI-enhanced text** (blue hint): Post-processed with punctuation

### Where Does the Text Go?
1. **Clipboard** - Automatically copied (can paste anywhere)
2. **Active window** - Auto-typed if enabled in settings
3. **History** - Saved in the app for later reference

## Settings

### General Settings
- **Auto-start**: Launch VoiceFlow when Windows starts
- **Start minimized**: Hide to system tray on launch
- **Show notifications**: Desktop alerts for transcriptions

### Transcription Settings

#### Model Selection
| Model | Best For | Speed | Accuracy |
|-------|----------|-------|----------|
| Tiny | Quick notes | Instant | Basic |
| Base | Casual use | Very fast | Good |
| Small | Daily use | Fast | Better |
| Medium | Professional | Moderate | Excellent |
| Large-v3 | Best quality | Slower | Best |

#### Language
- **Auto-detect**: Automatically identifies language
- **Specific language**: Force recognition in chosen language
- **Multi-language**: Switch between languages (Pro tip: use hotkeys)

### AI Enhancement
- **Enable/Disable**: Toggle DeepSeek post-processing
- **Punctuation**: Add periods, commas, question marks
- **Capitalization**: Proper case for sentences and names
- **Formatting**: Paragraph breaks and structure

### Output Settings
- **Copy to clipboard**: Always/Never/Ask
- **Auto-type**: Type into active window
- **Type delay**: Milliseconds between characters
- **Append mode**: Add to existing text vs replace

### Hotkey Customization
- Click "Change Hotkey"
- Press your desired combination
- Avoid conflicts with other apps

## Tips & Tricks

### For Best Results

#### Audio Quality
1. **Microphone Position**: 6-12 inches from mouth
2. **Background Noise**: Find a quiet environment
3. **Speaking Style**: Natural pace, clear pronunciation
4. **Microphone Type**: Headset or dedicated mic recommended

#### Optimal Settings by Use Case

**Email & Documents**
- Model: Large-v3
- AI Enhancement: Enabled
- Auto-type: Enabled

**Quick Notes**
- Model: Small
- AI Enhancement: Disabled
- Copy to clipboard: Enabled

**Code Comments**
- Model: Medium
- AI Enhancement: Disabled
- Language: English (forced)

**Multilingual Work**
- Model: Large-v3
- Language: Auto-detect
- AI Enhancement: Enabled

### Power User Features

#### Voice Commands (Experimental)
- "New paragraph" - Inserts paragraph break
- "Period" / "Comma" - Adds punctuation
- "Delete that" - Removes last sentence

#### Batch Processing
1. Record multiple segments
2. Review in history
3. Export all at once

#### Custom Vocabulary
- Add technical terms in Settings → Dictionary
- Import word lists from CSV
- Train on your writing style

## Troubleshooting

### Common Issues

#### No Audio Detected
1. Check Windows sound settings
2. Ensure microphone permissions granted
3. Try different microphone
4. Restart audio service

#### Poor Transcription Quality
1. Reduce background noise
2. Upgrade to larger model
3. Check language settings
4. Calibrate microphone volume

#### High GPU Usage
1. Use smaller model
2. Close other GPU apps
3. Enable GPU scheduling in Windows
4. Check temperature throttling

#### App Won't Start
1. Check if already running in tray
2. Restart computer
3. Run as administrator
4. Check antivirus settings

### Error Messages

**"GPU not found"**
- Install NVIDIA drivers
- Verify CUDA installation
- Try CPU mode (slower)

**"Model loading failed"**
- Check disk space
- Re-download models
- Verify file permissions

**"WebSocket connection failed"**
- Python server not running
- Port 5000 blocked
- Firewall interference

## Keyboard Shortcuts

### Global Shortcuts (Work Anywhere)
- `Ctrl + Alt + Space` - Toggle recording
- `Ctrl + Alt + V` - Show/hide window
- `Ctrl + Alt + S` - Quick settings

### In-App Shortcuts
- `Ctrl + N` - New transcription
- `Ctrl + S` - Save current text
- `Ctrl + E` - Export history
- `Ctrl + ,` - Open settings
- `Ctrl + Q` - Quit application
- `F1` - Help
- `F11` - Fullscreen

### Text Editing
- `Ctrl + A` - Select all
- `Ctrl + C` - Copy
- `Ctrl + V` - Paste
- `Ctrl + Z` - Undo
- `Ctrl + Y` - Redo

## Advanced Features

### Transcription History
- Automatic saving of all transcriptions
- Search by date, content, or duration
- Export to TXT, DOCX, or PDF
- Batch operations

### Statistics Dashboard
- Words per minute
- Total words transcribed
- Most active hours
- Language distribution
- Model usage stats

### Integration Options
- Send to Notion
- Save to Obsidian
- Post to Slack
- Email transcriptions

## Privacy & Security

### Your Data
- **100% Local**: No cloud processing
- **No Analytics**: We don't track usage
- **No Account**: No registration required
- **Your Control**: Delete anytime

### Data Storage
- Transcriptions: `%APPDATA%\VoiceFlow\history\`
- Settings: `%APPDATA%\VoiceFlow\config.json`
- Models: `%APPDATA%\VoiceFlow\models\`

## Getting Help

### Resources
- GitHub Issues: Report bugs
- Discord Community: Get help
- Documentation: Full technical details
- FAQ: Common questions

### Contact
- Email: support@voiceflow.local
- Discord: discord.gg/voiceflow
- GitHub: github.com/voiceflow

---

Thank you for using VoiceFlow! We hope it enhances your productivity and makes voice transcription effortless.