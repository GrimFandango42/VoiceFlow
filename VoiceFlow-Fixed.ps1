# VoiceFlow - Compatibility-Fixed Invisible System Tray
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:process = $null
$workingDir = "C:\AI_Projects\VoiceFlow"

Write-Host "Starting VoiceFlow with compatibility patches..."

# Create tray icon
$trayIcon = New-Object System.Windows.Forms.NotifyIcon
$trayIcon.Text = "VoiceFlow - Voice Transcription (Fixed)"
$trayIcon.Icon = [System.Drawing.SystemIcons]::Microphone
$trayIcon.Visible = $true

# Auto-start the compatibility-patched service
try {
    Set-Location $workingDir
    Write-Host "Launching patched STT server..."
    $script:process = Start-Process -FilePath "python\venv\Scripts\python.exe" -ArgumentList "python\stt_server_patched.py" -WindowStyle Hidden -PassThru
    $trayIcon.ShowBalloonTip(3000, "VoiceFlow Fixed", "Compatibility patches applied. Press Ctrl+Alt to record.", [System.Windows.Forms.ToolTipIcon]::Info)
    $trayIcon.Icon = [System.Drawing.SystemIcons]::Information
    Write-Host "VoiceFlow server started"
} catch {
    Write-Host "Error starting VoiceFlow: $_"
    $trayIcon.ShowBalloonTip(3000, "VoiceFlow Error", "Failed to start", [System.Windows.Forms.ToolTipIcon]::Error)
}

# Create context menu
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

$statusItem = $contextMenu.Items.Add("VoiceFlow Active (Fixed)")
$statusItem.Enabled = $false

$contextMenu.Items.Add("-") | Out-Null

$testItem = $contextMenu.Items.Add("Test Text Injection")
$testItem.Add_Click({
    try {
        Start-Process "notepad.exe"
        Start-Sleep -Milliseconds 1000
        Add-Type -AssemblyName Microsoft.VisualBasic
        [Microsoft.VisualBasic.Interaction]::AppActivate("notepad")
        Start-Sleep -Milliseconds 500
        [System.Windows.Forms.SendKeys]::SendWait("VoiceFlow test - text injection working!")
        $trayIcon.ShowBalloonTip(2000, "Test Complete", "Check Notepad for test text", [System.Windows.Forms.ToolTipIcon]::Info)
    } catch {
        $trayIcon.ShowBalloonTip(3000, "Test Failed", "Error occurred", [System.Windows.Forms.ToolTipIcon]::Error)
    }
})

$instructionItem = $contextMenu.Items.Add("How to Use")
$instructionItem.Add_Click({
    $trayIcon.ShowBalloonTip(5000, "VoiceFlow Usage", "1. Click in any text field, 2. Press Ctrl+Alt, 3. Speak your text, 4. Release Ctrl+Alt, 5. Text appears automatically!", [System.Windows.Forms.ToolTipIcon]::Info)
})

$contextMenu.Items.Add("-") | Out-Null

$restartItem = $contextMenu.Items.Add("Restart Service")
$restartItem.Add_Click({
    try {
        if ($script:process) { 
            $script:process.Kill() 
            $script:process.WaitForExit(5000)
        }
        Start-Sleep -Seconds 2
        Set-Location $workingDir
        $script:process = Start-Process -FilePath "python\venv\Scripts\python.exe" -ArgumentList "python\stt_server_patched.py" -WindowStyle Hidden -PassThru
        $trayIcon.ShowBalloonTip(2000, "VoiceFlow", "Service restarted", [System.Windows.Forms.ToolTipIcon]::Info)
    } catch {
        $trayIcon.ShowBalloonTip(3000, "Error", "Restart failed", [System.Windows.Forms.ToolTipIcon]::Error)
    }
})

$exitItem = $contextMenu.Items.Add("Exit VoiceFlow")
$exitItem.Add_Click({
    if ($script:process) { 
        $script:process.Kill() 
        $trayIcon.ShowBalloonTip(1000, "VoiceFlow", "Service stopped", [System.Windows.Forms.ToolTipIcon]::Info)
    }
    $trayIcon.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})

$trayIcon.ContextMenuStrip = $contextMenu

Write-Host "VoiceFlow system tray ready. Press Ctrl+Alt anywhere to use voice transcription."

# Keep running invisibly
[System.Windows.Forms.Application]::Run()
