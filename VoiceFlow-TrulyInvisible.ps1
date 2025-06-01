# VoiceFlow - True Invisible System Tray (No Web Interface)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:process = $null
$workingDir = "C:\AI_Projects\VoiceFlow"

# Create tray icon
$trayIcon = New-Object System.Windows.Forms.NotifyIcon
$trayIcon.Text = "VoiceFlow - Invisible Voice Transcription"
$trayIcon.Icon = [System.Drawing.SystemIcons]::Microphone
$trayIcon.Visible = $true

# Auto-start the service (no web interface)
try {
    Set-Location $workingDir
    $script:process = Start-Process -FilePath "python\venv\Scripts\python.exe" -ArgumentList "python\stt_server.py" -WindowStyle Hidden -PassThru
    $trayIcon.ShowBalloonTip(3000, "VoiceFlow Started", "Press Ctrl+Alt anywhere to record voice", [System.Windows.Forms.ToolTipIcon]::Info)
    $trayIcon.Icon = [System.Drawing.SystemIcons]::Information
} catch {
    $trayIcon.ShowBalloonTip(3000, "VoiceFlow Error", "Failed to start: $_", [System.Windows.Forms.ToolTipIcon]::Error)
}

# Create context menu
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

$statusItem = $contextMenu.Items.Add("✅ VoiceFlow Active")
$statusItem.Enabled = $false

$contextMenu.Items.Add("-") | Out-Null

$instructionItem = $contextMenu.Items.Add("📖 How to Use")
$instructionItem.Add_Click({
    $trayIcon.ShowBalloonTip(5000, "VoiceFlow Usage", "1. Click in any text field`n2. Press Ctrl+Alt`n3. Speak your text`n4. Press Ctrl+Alt again`n5. Text appears automatically!", [System.Windows.Forms.ToolTipIcon]::Info)
})

$contextMenu.Items.Add("-") | Out-Null

$restartItem = $contextMenu.Items.Add("🔄 Restart Service")
$restartItem.Add_Click({
    try {
        if ($script:process) { $script:process.Kill() }
        Start-Sleep -Seconds 2
        Set-Location $workingDir
        $script:process = Start-Process -FilePath "python\venv\Scripts\python.exe" -ArgumentList "python\stt_server.py" -WindowStyle Hidden -PassThru
        $trayIcon.ShowBalloonTip(2000, "VoiceFlow", "Service restarted", [System.Windows.Forms.ToolTipIcon]::Info)
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
