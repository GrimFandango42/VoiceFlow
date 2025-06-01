# VoiceFlow PowerShell Launcher with System Tray
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:running = $false
$script:process = $null

# Create tray icon
$trayIcon = New-Object System.Windows.Forms.NotifyIcon
$trayIcon.Text = "VoiceFlow"
$trayIcon.Icon = [System.Drawing.SystemIcons]::Information
$trayIcon.Visible = $true

# Create context menu
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

$toggleItem = $contextMenu.Items.Add("Start VoiceFlow")
$toggleItem.Add_Click({
    if ($script:running) {
        # Stop
        if ($script:process) { $script:process.Kill() }
        $script:running = $false
        $toggleItem.Text = "Start VoiceFlow"
        $trayIcon.ShowBalloonTip(1000, "VoiceFlow", "Stopped", [System.Windows.Forms.ToolTipIcon]::Info)
    } else {
        # Start
        $script:process = Start-Process -FilePath "python\venv\Scripts\python.exe" -ArgumentList "python\stt_server.py" -WindowStyle Hidden -PassThru
        $script:running = $true
        $toggleItem.Text = "Stop VoiceFlow"
        $trayIcon.ShowBalloonTip(1000, "VoiceFlow", "Started - Press Ctrl+Alt to record", [System.Windows.Forms.ToolTipIcon]::Info)
        Start-Sleep -Seconds 2
        Start-Process "http://localhost:8765"
    }
})

$contextMenu.Items.Add("-") | Out-Null

$exitItem = $contextMenu.Items.Add("Exit")
$exitItem.Add_Click({
    if ($script:process) { $script:process.Kill() }
    $trayIcon.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})

$trayIcon.ContextMenuStrip = $contextMenu

# Keep running
[System.Windows.Forms.Application]::Run()
