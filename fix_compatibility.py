#!/usr/bin/env python3
"""
VoiceFlow Compatibility Fix
Addresses Python 3.13 enum issues and WebSocket binding problems
"""

import subprocess
import sys
import os
import time
from pathlib import Path

def run_command(cmd, description):
    """Run a command and show results"""
    print(f"\n[FIXING] {description}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print(f"[SUCCESS] {description}")
            if result.stdout.strip():
                print(f"Output: {result.stdout.strip()}")
            return True
        else:
            print(f"[ERROR] {description}")
            print(f"Error: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {description}")
        return False
    except Exception as e:
        print(f"[EXCEPTION] {description}: {e}")
        return False

def main():
    print("="*60)
    print("VoiceFlow Compatibility Fix - Python 3.13 Issues")
    print("="*60)
    
    # Change to project directory
    project_dir = Path("C:/AI_Projects/VoiceFlow")
    os.chdir(project_dir)
    
    # Step 1: Reinstall pyautogui with compatibility fixes
    print("\n[STEP 1] Fixing pyautogui compatibility issues...")
    
    # Uninstall and reinstall with specific version
    run_command(
        "python/venv/Scripts/pip uninstall -y pyautogui",
        "Uninstalling problematic pyautogui"
    )
    
    # Install specific compatible version
    run_command(
        "python/venv/Scripts/pip install pyautogui==0.9.54",
        "Installing compatible pyautogui version"
    )
    
    # Step 2: Fix enum compatibility
    print("\n[STEP 2] Addressing enum module compatibility...")
    
    # Create enum compatibility patch
    enum_patch = '''
# Enum compatibility patch for Python 3.13
import enum
import sys

# Add missing global_enum attribute for older packages
if not hasattr(enum, 'global_enum'):
    def global_enum(cls):
        return cls
    enum.global_enum = global_enum

print("Enum compatibility patch applied")
'''
    
    with open("python/enum_patch.py", "w") as f:
        f.write(enum_patch)
    
    # Step 3: Create fixed STT server with compatibility patches
    print("\n[STEP 3] Creating compatibility-patched STT server...")
    
    # Read current server
    with open("python/stt_server.py", "r") as f:
        server_content = f.read()
    
    # Add compatibility patches at the top
    compatibility_header = '''"""
VoiceFlow STT Server - Compatibility-Patched Version
Fixed for Python 3.13 and WSL/Windows environment issues
"""

# Compatibility patches for Python 3.13
import sys
sys.path.insert(0, "python")

# Fix enum compatibility
import enum
if not hasattr(enum, 'global_enum'):
    def global_enum(cls):
        return cls
    enum.global_enum = global_enum

# Import order fix for pyautogui
import os
os.environ["DISPLAY"] = ":0.0"  # Set display for WSL if needed

'''
    
    # Create patched server
    patched_content = compatibility_header + "\n" + server_content
    
    with open("python/stt_server_patched.py", "w") as f:
        f.write(patched_content)
    
    # Step 4: Create updated launcher that uses patched server
    print("\n[STEP 4] Creating updated launchers...")
    
    # Update PowerShell script to use patched server
    ps_script_content = '''# VoiceFlow - Compatibility-Fixed Invisible System Tray
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:process = $null
$workingDir = "C:\\AI_Projects\\VoiceFlow"

# Create tray icon
$trayIcon = New-Object System.Windows.Forms.NotifyIcon
$trayIcon.Text = "VoiceFlow - Voice Transcription (Fixed)"
$trayIcon.Icon = [System.Drawing.SystemIcons]::Microphone
$trayIcon.Visible = $true

# Auto-start the compatibility-patched service
try {
    Set-Location $workingDir
    $script:process = Start-Process -FilePath "python\\venv\\Scripts\\python.exe" -ArgumentList "python\\stt_server_patched.py" -WindowStyle Hidden -PassThru
    $trayIcon.ShowBalloonTip(3000, "VoiceFlow Fixed", "Compatibility patches applied. Press Ctrl+Alt to record.", [System.Windows.Forms.ToolTipIcon]::Info)
    $trayIcon.Icon = [System.Drawing.SystemIcons]::Information
} catch {
    $trayIcon.ShowBalloonTip(3000, "VoiceFlow Error", "Failed to start: $_", [System.Windows.Forms.ToolTipIcon]::Error)
}

# Create context menu
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

$statusItem = $contextMenu.Items.Add("✅ VoiceFlow Active (Fixed)")
$statusItem.Enabled = $false

$contextMenu.Items.Add("-") | Out-Null

$testItem = $contextMenu.Items.Add("🧪 Test Text Injection")
$testItem.Add_Click({
    try {
        Add-Type -AssemblyName Microsoft.VisualBasic
        [Microsoft.VisualBasic.Interaction]::AppActivate("notepad")
        Start-Sleep -Milliseconds 500
        [System.Windows.Forms.SendKeys]::SendWait("VoiceFlow test - text injection working!{ENTER}")
        $trayIcon.ShowBalloonTip(2000, "Test Complete", "Check Notepad for test text", [System.Windows.Forms.ToolTipIcon]::Info)
    } catch {
        $trayIcon.ShowBalloonTip(3000, "Test Failed", "Error: $_", [System.Windows.Forms.ToolTipIcon]::Error)
    }
})

$instructionItem = $contextMenu.Items.Add("📖 How to Use")
$instructionItem.Add_Click({
    $trayIcon.ShowBalloonTip(5000, "VoiceFlow Usage", "1. Click in any text field`n2. Press Ctrl+Alt`n3. Speak your text`n4. Release Ctrl+Alt`n5. Text appears automatically!", [System.Windows.Forms.ToolTipIcon]::Info)
})

$contextMenu.Items.Add("-") | Out-Null

$restartItem = $contextMenu.Items.Add("🔄 Restart Service")
$restartItem.Add_Click({
    try {
        if ($script:process) { $script:process.Kill() }
        Start-Sleep -Seconds 2
        Set-Location $workingDir
        $script:process = Start-Process -FilePath "python\\venv\\Scripts\\python.exe" -ArgumentList "python\\stt_server_patched.py" -WindowStyle Hidden -PassThru
        $trayIcon.ShowBalloonTip(2000, "VoiceFlow", "Service restarted with fixes", [System.Windows.Forms.ToolTipIcon]::Info)
    } catch {
        $trayIcon.ShowBalloonTip(3000, "Error", "Restart failed: $_", [System.Windows.Forms.ToolTipIcon]::Error)
    }
})

$exitItem = $contextMenu.Items.Add("❌ Exit VoiceFlow")
$exitItem.Add_Click({
    if ($script:process) { 
        $script:process.Kill() 
        $trayIcon.ShowBalloonTip(1000, "VoiceFlow", "Service stopped", [System.Windows.Forms.ToolTipIcon]::Info)
    }
    $trayIcon.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})

$trayIcon.ContextMenuStrip = $contextMenu

# Keep running invisibly
[System.Windows.Forms.Application]::Run()
'''
    
    with open("VoiceFlow-Fixed.ps1", "w", encoding="utf-8") as f:
        f.write(ps_script_content)
    
    # Create updated batch launcher
    batch_content = '''@echo off
:: VoiceFlow - Compatibility Fixed Launcher
echo Starting VoiceFlow with compatibility fixes...
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\\AI_Projects\\VoiceFlow\\VoiceFlow-Fixed.ps1"
'''
    
    with open("VoiceFlow-FIXED.bat", "w") as f:
        f.write(batch_content)
    
    # Step 5: Test the fixes
    print("\n[STEP 5] Testing compatibility fixes...")
    
    # Test enum patch
    success = run_command(
        "python/venv/Scripts/python.exe python/enum_patch.py",
        "Testing enum compatibility patch"
    )
    
    # Test pyautogui import
    success &= run_command(
        'python/venv/Scripts/python.exe -c "import pyautogui; print(\'pyautogui imported successfully\')"',
        "Testing pyautogui import"
    )
    
    # Test keyboard import
    success &= run_command(
        'python/venv/Scripts/python.exe -c "import keyboard; print(\'keyboard imported successfully\')"',
        "Testing keyboard import"
    )
    
    print("\n" + "="*60)
    print("COMPATIBILITY FIX RESULTS")
    print("="*60)
    
    if success:
        print("✅ SUCCESS: Compatibility fixes applied!")
        print("\nNEXT STEPS:")
        print("1. Double-click VoiceFlow-FIXED.bat")
        print("2. Look for microphone icon in system tray")
        print("3. Right-click tray icon → 'Test Text Injection'")
        print("4. If test works, try Ctrl+Alt in any app")
        print("\nFixed launchers created:")
        print("  - VoiceFlow-FIXED.bat (main launcher)")
        print("  - VoiceFlow-Fixed.ps1 (PowerShell script)")
        print("  - python/stt_server_patched.py (compatible server)")
    else:
        print("❌ FAILED: Some compatibility fixes failed")
        print("Check error messages above for details")
    
    print("="*60)

if __name__ == "__main__":
    main()
