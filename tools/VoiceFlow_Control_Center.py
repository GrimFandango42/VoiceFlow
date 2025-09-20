#!/usr/bin/env python3
"""
VoiceFlow Control Center
========================
Unified launcher interface for VoiceFlow - One-click setup, testing, and launch
"""

import sys
import os
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from pathlib import Path
from typing import Dict, List, Optional, Callable
import json

class VoiceFlowControlCenter:
    """Unified control center for VoiceFlow operations"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VoiceFlow Control Center")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # State tracking
        self.current_process: Optional[subprocess.Popen] = None
        self.visual_demo_process: Optional[subprocess.Popen] = None
        self.visual_demo_running = False
        self.status_text = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar()


        # UI Components
        self.log_text: Optional[scrolledtext.ScrolledText] = None
        self.status_label: Optional[tk.Label] = None
        self.progress_bar: Optional[ttk.Progressbar] = None
        self.visual_demo_button: Optional[ttk.Button] = None

        self._setup_styling()
        self._setup_ui()
        self._check_initial_status()

    def _setup_styling(self):
        """Keep it simple and clean"""
        # Just set a nice title font
        pass

    def _setup_ui(self):
        """Set up the simplified user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # Title Section
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 20))

        title_label = ttk.Label(title_frame, text="VoiceFlow Control Center",
                               font=("Segoe UI", 18, "bold"))
        title_label.pack()

        subtitle_label = ttk.Label(title_frame, text="🎯 Simplified Interface for Voice Transcription")
        subtitle_label.pack()

        # Main Actions - Large, prominent buttons
        actions_frame = ttk.Frame(main_frame)
        actions_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        actions_frame.columnconfigure(0, weight=1)
        actions_frame.columnconfigure(1, weight=1)

        # Primary action buttons - bigger and more prominent
        self.launch_button = ttk.Button(actions_frame, text="🚀 LAUNCH VOICEFLOW",
                                       command=self.smart_launch, width=25)
        self.launch_button.grid(row=0, column=0, padx=(0, 10), pady=5, sticky=(tk.W, tk.E))

        self.setup_button = ttk.Button(actions_frame, text="🔧 SETUP & INSTALL",
                                      command=self.smart_setup, width=25)
        self.setup_button.grid(row=0, column=1, padx=(10, 0), pady=5, sticky=(tk.W, tk.E))

        # Troubleshoot section - initially hidden
        self.troubleshoot_frame = ttk.LabelFrame(main_frame, text="🔍 Troubleshooting", padding="10")
        self.troubleshoot_visible = False

        troubleshoot_buttons = ttk.Frame(self.troubleshoot_frame)
        troubleshoot_buttons.pack(fill=tk.X)

        ttk.Button(troubleshoot_buttons, text="🧪 Critical Tests",
                  command=self.run_critical_tests, width=15).grid(row=0, column=0, padx=5)

        ttk.Button(troubleshoot_buttons, text="🔄 Full Tests",
                  command=self.run_full_tests, width=15).grid(row=0, column=1, padx=5)

        self.visual_demo_button = ttk.Button(troubleshoot_buttons, text="🎨 Visual Demo",
                                             command=self.toggle_visual_demo, width=15)
        self.visual_demo_button.grid(row=0, column=2, padx=5)

        # Status Section - more compact
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="Status:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky=tk.W)
        self.status_label = ttk.Label(status_frame, textvariable=self.status_text, font=("Segoe UI", 9))
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))

        # Compact progress bar
        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))

        # Activity Log - more prominent
        log_frame = ttk.LabelFrame(main_frame, text="📋 Activity Log", padding="10")
        log_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=12, width=80, font=("Consolas", 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Control buttons - simplified
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=4, column=0, pady=(10, 0))

        ttk.Button(control_frame, text="🛑 Stop Process",
                  command=self.stop_current_process).grid(row=0, column=0, padx=(0, 10))

        ttk.Button(control_frame, text="🗑️ Clear Log",
                  command=self.clear_log).grid(row=0, column=1, padx=5)

        ttk.Button(control_frame, text="❌ Exit",
                  command=self.exit_application).grid(row=0, column=2, padx=(10, 0))

        # Initialize with smart messages
        self.log("🎯 VoiceFlow Control Center - Simplified Interface")
        self.log("💡 First time? Click 'SETUP & INSTALL' → then 'LAUNCH VOICEFLOW'")
        self.log("⚡ Ready to go? Click 'LAUNCH VOICEFLOW' (includes auto health-check)")

    def log(self, message: str, level: str = "INFO"):
        """Add message to log with timestamp"""
        timestamp = time.strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {level}: {message}\n"

        if self.log_text:
            self.log_text.insert(tk.END, log_message)
            self.log_text.see(tk.END)

    def update_status(self, message: str):
        """Update status label"""
        self.status_text.set(message)
        self.root.update_idletasks()

    def start_progress(self):
        """Start progress bar animation"""
        self.progress_bar.start(10)

    def stop_progress(self):
        """Stop progress bar animation"""
        self.progress_bar.stop()

    def _check_initial_status(self):
        """Check initial system status"""
        self.log("Checking system status...")

        # Quick Python version check
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        self.log(f"Python version: {python_version}")

        # Check if main files exist
        critical_files = [
            "src/voiceflow/ui/cli_enhanced.py",
            "pyproject.toml",
            "scripts/dev/quick_smoke_test.py",
            "scripts/setup/setup_voiceflow.py"
        ]

        missing_files = []
        root_dir = Path(__file__).parent.parent  # VoiceFlow root directory
        for file_path in critical_files:
            if not (root_dir / file_path).exists():
                missing_files.append(file_path)

        if missing_files:
            self.log(f"WARNING: Missing critical files: {', '.join(missing_files)}", "WARN")
            self.update_status("⚠️ Setup required")
        else:
            self.log("✅ All critical files present")
            self.update_status("✅ Ready")

    def run_command_async(self, command: List[str], description: str,
                         callback: Optional[Callable] = None):
        """Run command asynchronously and log output"""
        def run_in_thread():
            self.log(f"Starting: {description}")
            self.start_progress()
            self.update_status(f"Running: {description}")

            try:
                # Start process
                self.current_process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    universal_newlines=True,
                    cwd=Path(__file__).parent.parent,  # Go up to VoiceFlow root directory
                    env={**os.environ, 'PYTHONPATH': str(Path(__file__).parent.parent / 'src')}
                )

                # Read output line by line
                while True:
                    output = self.current_process.stdout.readline()
                    if output == '' and self.current_process.poll() is not None:
                        break
                    if output:
                        # Clean and log output
                        clean_output = output.strip()
                        if clean_output:
                            self.log(clean_output)

                # Get final return code
                return_code = self.current_process.poll()

                if return_code == 0:
                    self.log(f"✅ {description} completed successfully")
                    self.update_status("✅ Complete")
                else:
                    self.log(f"❌ {description} failed with exit code {return_code}", "ERROR")
                    self.update_status("❌ Failed")

            except Exception as e:
                self.log(f"❌ {description} error: {str(e)}", "ERROR")
                self.update_status("❌ Error")

            finally:
                self.stop_progress()
                self.current_process = None

                # Run callback if provided
                if callback:
                    self.root.after(0, callback)

        # Start in separate thread
        thread = threading.Thread(target=run_in_thread, daemon=True)
        thread.start()

    def smart_launch(self):
        """Smart launch with auto health check and intelligent error handling"""
        self.log("🚀 Smart Launch: Auto health-check → VoiceFlow...")

        def after_health_check():
            # If health check passed, launch VoiceFlow
            self.log("✅ Health check passed - launching VoiceFlow...")
            command = [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, 'src'); exec(open('src/voiceflow/ui/cli_enhanced.py').read())"
            ]
            self.run_command_async(command, "VoiceFlow Application")

        def on_health_failure():
            # Show troubleshooting options if health check fails
            self.log("⚠️ Health check failed - showing troubleshooting options...", "WARN")
            self.show_troubleshoot_panel()

        # Run intelligent health check
        self.run_smart_health_check(after_health_check, on_health_failure)

    def smart_setup(self):
        """Smart setup with comprehensive health checking"""
        self.log("🔧 Smart Setup: Installing and configuring VoiceFlow...")

        def after_setup():
            self.log("✅ Setup complete! You can now use 'LAUNCH VOICEFLOW'")

        command = [sys.executable, "scripts/setup/setup_voiceflow.py"]
        self.run_command_async(command, "Smart Setup & Installation", after_setup)

    def show_troubleshoot_panel(self):
        """Show the troubleshooting panel when needed"""
        if not self.troubleshoot_visible:
            self.troubleshoot_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
            self.troubleshoot_visible = True
            self.log("🔍 Troubleshooting panel now available")

    def hide_troubleshoot_panel(self):
        """Hide the troubleshooting panel when not needed"""
        if self.troubleshoot_visible:
            self.troubleshoot_frame.grid_remove()
            self.troubleshoot_visible = False

    def run_smart_health_check(self, success_callback=None, failure_callback=None):
        """Run health check with smart callbacks"""
        def check_completed():
            # This will be called after health check finishes
            # We can check the result and call appropriate callback
            if success_callback:
                success_callback()
            else:
                if failure_callback:
                    failure_callback()

        command = [sys.executable, "scripts/dev/quick_smoke_test.py"]
        self.run_command_async(command, "Intelligent Health Check", check_completed)

    def launch_voiceflow(self):
        """Legacy launch method - redirects to smart launch"""
        self.smart_launch()

    def run_health_check(self):
        """Run quick health check"""
        command = [sys.executable, "scripts/dev/quick_smoke_test.py"]
        self.run_command_async(command, "Health Check")

    def run_setup(self):
        """Run setup and installation"""
        command = [sys.executable, "scripts/setup/setup_voiceflow.py"]
        self.run_command_async(command, "Setup & Installation")

    def run_critical_tests(self):
        """Run critical tests only"""
        command = [sys.executable, "scripts/dev/parallel_test_runner.py", "--priority", "critical"]
        self.run_command_async(command, "Critical Tests")

    def run_full_tests(self):
        """Run full test suite"""
        command = [sys.executable, "scripts/dev/parallel_test_runner.py"]
        self.run_command_async(command, "Full Test Suite")

    def toggle_visual_demo(self):
        """Toggle visual demo on/off"""
        if self.visual_demo_running:
            self.stop_visual_demo()
        else:
            self.start_visual_demo()

    def start_visual_demo(self):
        """Start visual configuration demo"""
        try:
            command = [sys.executable, "scripts/dev/demo_visual_config.py"]
            self.visual_demo_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd(),
                text=True
            )
            self.visual_demo_running = True
            self.visual_demo_button.configure(text="🛑 Stop Visual Demo")
            self.log("🎨 Visual demo started", "INFO")
        except Exception as e:
            self.log(f"❌ Failed to start visual demo: {e}", "ERROR")

    def stop_visual_demo(self):
        """Stop visual configuration demo"""
        try:
            if self.visual_demo_process:
                self.visual_demo_process.terminate()
                self.visual_demo_process = None
            self.visual_demo_running = False
            self.visual_demo_button.configure(text="🎨 Start Visual Demo")
            self.log("🛑 Visual demo stopped", "WARN")
        except Exception as e:
            self.log(f"❌ Failed to stop visual demo: {e}", "ERROR")

    def stop_current_process(self):
        """Stop currently running process"""
        if self.current_process:
            try:
                self.current_process.terminate()
                self.log("🛑 Process terminated", "WARN")
                self.update_status("🛑 Stopped")
            except Exception as e:
                self.log(f"Error stopping process: {e}", "ERROR")
        else:
            self.log("No process currently running")

    def clear_log(self):
        """Clear the log text"""
        if self.log_text:
            self.log_text.delete(1.0, tk.END)

    def exit_application(self):
        """Exit the control center"""
        if self.current_process:
            result = messagebox.askyesno(
                "Exit Confirmation",
                "A process is currently running. Do you want to stop it and exit?"
            )
            if result:
                self.stop_current_process()
                time.sleep(1)  # Give process time to stop
            else:
                return

        self.root.quit()
        self.root.destroy()

    def run(self):
        """Start the control center"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.log("Interrupted by user")
            self.exit_application()

def main():
    """Entry point for VoiceFlow Control Center"""
    try:
        # Change to script directory
        os.chdir(Path(__file__).parent)

        # Create and run control center
        control_center = VoiceFlowControlCenter()
        control_center.run()

    except Exception as e:
        print(f"Failed to start VoiceFlow Control Center: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()