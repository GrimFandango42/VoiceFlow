# Enhanced VoiceFlow PowerShell Launcher with System Tray
# Runs invisibly like Wispr Flow with global Ctrl+Alt+Space hotkey

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:running = $false
$script:process = $null
$script:voiceflowPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Create notification icon
$trayIcon = New-Object System.Windows.Forms.NotifyIcon
$trayIcon.Text = "Enhanced VoiceFlow - Global Voice Transcription"
$trayIcon.Icon = [System.Drawing.SystemIcons]::Information
$trayIcon.Visible = $true

# Show initial notification
$trayIcon.ShowBalloonTip(3000, "Enhanced VoiceFlow", "Starting global voice transcription...`nPress Ctrl+Alt+Space anywhere to record", [System.Windows.Forms.ToolTipIcon]::Info)

# Create context menu
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

# Status item
$statusItem = $contextMenu.Items.Add("Enhanced VoiceFlow")
$statusItem.Enabled = $false
$statusItem.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)

$contextMenu.Items.Add("-") | Out-Null

# Start/Stop toggle
$toggleItem = $contextMenu.Items.Add("Start Enhanced VoiceFlow")
$toggleItem.Add_Click({
    if ($script:running) {
        # Stop
        if ($script:process -and !$script:process.HasExited) { 
            $script:process.Kill()
            Start-Sleep -Seconds 1
        }
        $script:running = $false
        $toggleItem.Text = "Start Enhanced VoiceFlow"
        $statusItem.Text = "Enhanced VoiceFlow (Stopped)"
        $trayIcon.ShowBalloonTip(2000, "Enhanced VoiceFlow", "Stopped", [System.Windows.Forms.ToolTipIcon]::Warning)
    } else {
        # Start
        try {
            # Change to VoiceFlow directory
            Set-Location $script:voiceflowPath
            
            # Check if Python environment exists
            if (!(Test-Path "python\venv\Scripts\python.exe")) {
                [System.Windows.Forms.MessageBox]::Show("Python environment not found!`n`nPlease run INSTALL_DEPS.bat first.", "Enhanced VoiceFlow Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                return
            }
            
            # Start enhanced server
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = "python\venv\Scripts\python.exe"
            $startInfo.Arguments = "python\enhanced_stt_server.py"
            $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $startInfo.CreateNoWindow = $true
            $startInfo.UseShellExecute = $false
            $startInfo.WorkingDirectory = $script:voiceflowPath
            
            $script:process = [System.Diagnostics.Process]::Start($startInfo)
            $script:running = $true
            
            $toggleItem.Text = "Stop Enhanced VoiceFlow"
            $statusItem.Text = "Enhanced VoiceFlow (Running)"
            $trayIcon.ShowBalloonTip(3000, "Enhanced VoiceFlow", "✅ Ready for voice transcription!`n`n🎙️ Press Ctrl+Alt+Space in any app to record`n🤖 AI enhancement via Ollama`n🚀 Instant text injection", [System.Windows.Forms.ToolTipIcon]::Info)
            
            # Monitor process
            Register-ObjectEvent -InputObject $script:process -EventName "Exited" -Action {
                $script:running = $false
                $toggleItem.Text = "Start Enhanced VoiceFlow"
                $statusItem.Text = "Enhanced VoiceFlow (Crashed)"
                $trayIcon.ShowBalloonTip(2000, "Enhanced VoiceFlow", "Process stopped unexpectedly", [System.Windows.Forms.ToolTipIcon]::Error)
            } | Out-Null
            
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to start Enhanced VoiceFlow:`n`n$($_.Exception.Message)", "Enhanced VoiceFlow Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$contextMenu.Items.Add("-") | Out-Null

# Test injection item
$testItem = $contextMenu.Items.Add("Test Text Injection")
$testItem.Add_Click({
    if ($script:running) {
        # Give user time to focus target application
        $trayIcon.ShowBalloonTip(2000, "Enhanced VoiceFlow", "Click in any text field and wait 3 seconds...", [System.Windows.Forms.ToolTipIcon]::Info)
        Start-Sleep -Seconds 3
        
        # Use keyboard simulation to type test text
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait("Test from Enhanced VoiceFlow - Global text injection working!")
        
        $trayIcon.ShowBalloonTip(2000, "Enhanced VoiceFlow", "✅ Text injection test completed", [System.Windows.Forms.ToolTipIcon]::Info)
    } else {
        $trayIcon.ShowBalloonTip(2000, "Enhanced VoiceFlow", "❌ Please start Enhanced VoiceFlow first", [System.Windows.Forms.ToolTipIcon]::Warning)
    }
})

# Open data folder item
$dataItem = $contextMenu.Items.Add("Open Data Folder")
$dataItem.Add_Click({
    $dataPath = Join-Path $env:USERPROFILE ".voiceflow"
    if (Test-Path $dataPath) {
        Start-Process "explorer.exe" -ArgumentList $dataPath
    } else {
        $trayIcon.ShowBalloonTip(2000, "Enhanced VoiceFlow", "Data folder not created yet", [System.Windows.Forms.ToolTipIcon]::Info)
    }
})

# View logs item
$logsItem = $contextMenu.Items.Add("View Logs")
$logsItem.Add_Click({
    $logPath = Join-Path $script:voiceflowPath "enhanced_voiceflow.log"
    if (Test-Path $logPath) {
        Start-Process "notepad.exe" -ArgumentList $logPath
    } else {
        $trayIcon.ShowBalloonTip(2000, "Enhanced VoiceFlow", "No logs found", [System.Windows.Forms.ToolTipIcon]::Info)
    }
})

$contextMenu.Items.Add("-") | Out-Null

# Instructions item
$helpItem = $contextMenu.Items.Add("How to Use")
$helpItem.Add_Click({
    $helpMessage = @"
Enhanced VoiceFlow - Wispr Flow Compatible

🎙️ GLOBAL VOICE TRANSCRIPTION:
   Press Ctrl+Alt+Space in ANY application to record
   
🚀 HOW IT WORKS:
   1. Press Ctrl+Alt+Space
   2. Start speaking
   3. Pause when done
   4. Text appears instantly where your cursor is!

✨ FEATURES:
   • Works in Word, Excel, browsers, chat apps, etc.
   • AI enhancement for proper punctuation
   • Context-aware formatting
   • Completely free and private
   • No cloud dependency

🔧 TROUBLESHOOTING:
   • Make sure Python environment is installed
   • Check that microphone permissions are enabled
   • Ensure Ollama is running for AI enhancement

💡 TIP:
   Position your cursor where you want text to appear
   before pressing the hotkey!
"@
    [System.Windows.Forms.MessageBox]::Show($helpMessage, "Enhanced VoiceFlow - Instructions", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})

# Exit item
$exitItem = $contextMenu.Items.Add("Exit Enhanced VoiceFlow")
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

# Auto-start Enhanced VoiceFlow
$toggleItem.PerformClick()

# Keep the script running
try {
    [System.Windows.Forms.Application]::Run()
} finally {
    if ($script:process -and !$script:process.HasExited) { 
        $script:process.Kill() 
    }
    $trayIcon.Visible = $false
}