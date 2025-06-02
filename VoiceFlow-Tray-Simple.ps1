# VoiceFlow Simple System Tray
# Clean, focused voice transcription like Wispr Flow

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:running = $false
$script:process = $null
$script:voiceflowPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Create tray icon
$trayIcon = New-Object System.Windows.Forms.NotifyIcon
$trayIcon.Text = "VoiceFlow - Simple Voice Transcription"
$trayIcon.Icon = [System.Drawing.SystemIcons]::Information
$trayIcon.Visible = $true

# Create context menu
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

# Status
$statusItem = $contextMenu.Items.Add("VoiceFlow Simple")
$statusItem.Enabled = $false
$statusItem.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

$contextMenu.Items.Add("-") | Out-Null

# Start/Stop
$toggleItem = $contextMenu.Items.Add("Start VoiceFlow")
$toggleItem.Add_Click({
    if ($script:running) {
        # Stop
        if ($script:process -and !$script:process.HasExited) { 
            $script:process.Kill()
            Start-Sleep -Seconds 1
        }
        $script:running = $false
        $toggleItem.Text = "Start VoiceFlow"
        $statusItem.Text = "VoiceFlow Simple (Stopped)"
        $trayIcon.ShowBalloonTip(2000, "VoiceFlow", "Stopped", [System.Windows.Forms.ToolTipIcon]::Warning)
    } else {
        # Start
        try {
            Set-Location $script:voiceflowPath
            
            if (!(Test-Path "python\venv\Scripts\python.exe")) {
                [System.Windows.Forms.MessageBox]::Show("Python environment not found!`n`nRun INSTALL_ENHANCED_DEPS.bat first", "VoiceFlow Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                return
            }
            
            # Start streamlined server
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = "python\venv\Scripts\python.exe"
            $startInfo.Arguments = "python\simple_server.py"
            $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $startInfo.CreateNoWindow = $true
            $startInfo.UseShellExecute = $false
            $startInfo.WorkingDirectory = $script:voiceflowPath
            
            $script:process = [System.Diagnostics.Process]::Start($startInfo)
            $script:running = $true
            
            $toggleItem.Text = "Stop VoiceFlow"
            $statusItem.Text = "VoiceFlow Simple (Running)"
            $trayIcon.ShowBalloonTip(3000, "VoiceFlow Ready!", "✅ Press and hold Ctrl+Alt anywhere to record`n🎙️ Release keys to stop and inject text`n🤖 AI enhancement active", [System.Windows.Forms.ToolTipIcon]::Info)
            
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to start VoiceFlow:`n`n$($_.Exception.Message)", "VoiceFlow Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

# Test injection
$testItem = $contextMenu.Items.Add("Test Text Injection")
$testItem.Add_Click({
    if ($script:running) {
        $trayIcon.ShowBalloonTip(2000, "VoiceFlow Test", "Click in any text field and wait 2 seconds...", [System.Windows.Forms.ToolTipIcon]::Info)
        Start-Sleep -Seconds 2
        
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait("Test from VoiceFlow - text injection working perfectly!")
        
        $trayIcon.ShowBalloonTip(1500, "VoiceFlow", "✅ Text injection test completed", [System.Windows.Forms.ToolTipIcon]::Info)
    } else {
        $trayIcon.ShowBalloonTip(1500, "VoiceFlow", "❌ Start VoiceFlow first", [System.Windows.Forms.ToolTipIcon]::Warning)
    }
})

$contextMenu.Items.Add("-") | Out-Null

# Instructions
$helpItem = $contextMenu.Items.Add("How to Use")
$helpItem.Add_Click({
    $helpMessage = @"
VoiceFlow Simple - Easy Voice Transcription

🎙️ HOW TO USE:
   1. Position cursor where you want text
   2. Press and HOLD Ctrl+Alt
   3. Speak clearly while holding keys
   4. Release keys when done
   5. Text appears instantly!

✨ FEATURES:
   • Works in any Windows application
   • AI enhancement for proper punctuation
   • Completely free and private
   • No cloud dependency
   • Simple and reliable

💡 TIPS:
   • Keep sentences short for best results
   • Speak clearly and at normal pace
   • Works great for emails, chat, documents
   • Try it in different apps!

🔧 TROUBLESHOOTING:
   • Make sure microphone is working
   • Check that cursor is in a text field
   • Try the "Test Text Injection" option
"@
    [System.Windows.Forms.MessageBox]::Show($helpMessage, "VoiceFlow - How to Use", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

# Data folder
$dataItem = $contextMenu.Items.Add("Open Data Folder")
$dataItem.Add_Click({
    $dataPath = Join-Path $env:USERPROFILE ".voiceflow"
    if (Test-Path $dataPath) {
        Start-Process "explorer.exe" -ArgumentList $dataPath
    } else {
        $trayIcon.ShowBalloonTip(1500, "VoiceFlow", "Data folder not created yet", [System.Windows.Forms.ToolTipIcon]::Info)
    }
})

# Exit
$exitItem = $contextMenu.Items.Add("Exit VoiceFlow")
$exitItem.Add_Click({
    if ($script:process -and !$script:process.HasExited) { 
        $script:process.Kill() 
    }
    $trayIcon.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})

$trayIcon.ContextMenuStrip = $contextMenu

# Double-click to toggle
$trayIcon.Add_DoubleClick({
    $toggleItem.PerformClick()
})

# Auto-start
$trayIcon.ShowBalloonTip(2000, "VoiceFlow", "Starting voice transcription service...", [System.Windows.Forms.ToolTipIcon]::Info)
$toggleItem.PerformClick()

# Keep running
try {
    [System.Windows.Forms.Application]::Run()
} finally {
    if ($script:process -and !$script:process.HasExited) { 
        $script:process.Kill() 
    }
    $trayIcon.Visible = $false
}