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

        # Enhanced styling
        self.colors = {
            'primary': '#007ACC',      # Blue
            'success': '#4CAF50',      # Green
            'warning': '#FF9800',      # Orange
            'danger': '#F44336',       # Red
            'info': '#2196F3',         # Light Blue
            'secondary': '#6C757D'     # Gray
        }

        # UI Components
        self.log_text: Optional[scrolledtext.ScrolledText] = None
        self.status_label: Optional[tk.Label] = None
        self.progress_bar: Optional[ttk.Progressbar] = None
        self.visual_demo_button: Optional[ttk.Button] = None

        self._setup_styling()
        self._setup_ui()
        self._check_initial_status()

    def _setup_styling(self):
        """Setup enhanced styling and themes"""
        style = ttk.Style()

        # Configure button styles with colors
        style.configure('Primary.TButton',
                       background=self.colors['primary'],
                       foreground='white',
                       font=('Segoe UI', 9, 'bold'))

        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground='white',
                       font=('Segoe UI', 9, 'bold'))

        style.configure('Warning.TButton',
                       background=self.colors['warning'],
                       foreground='white',
                       font=('Segoe UI', 9, 'bold'))

        style.configure('Info.TButton',
                       background=self.colors['info'],
                       foreground='white',
                       font=('Segoe UI', 9, 'bold'))

        # Configure frame styles
        style.configure('Header.TLabelFrame.Label', font=('Segoe UI', 10, 'bold'))

        # Root window styling
        self.root.configure(bg='#f5f5f5')

    def _setup_ui(self):
        """Set up the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)

        # Title
        title_label = ttk.Label(main_frame, text="VoiceFlow Control Center",
                              font=("Segoe UI", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))

        # Quick Actions Section
        actions_frame = ttk.LabelFrame(main_frame, text="Quick Actions", padding="10")
        actions_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        actions_frame.columnconfigure(1, weight=1)

        # Action buttons with enhanced styling
        ttk.Button(actions_frame, text="🚀 Launch VoiceFlow",
                  command=self.launch_voiceflow, width=20, style='Primary.TButton').grid(row=0, column=0, padx=(0, 10))

        ttk.Button(actions_frame, text="⚡ Quick Health Check",
                  command=self.run_health_check, width=20, style='Success.TButton').grid(row=0, column=1, padx=5)

        ttk.Button(actions_frame, text="🔧 Setup & Install",
                  command=self.run_setup, width=20, style='Warning.TButton').grid(row=0, column=2, padx=(10, 0))

        # Testing Section
        testing_frame = ttk.LabelFrame(main_frame, text="Testing & Validation", padding="10")
        testing_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Button(testing_frame, text="🧪 Run Critical Tests",
                  command=self.run_critical_tests, width=20).grid(row=0, column=0, padx=(0, 10))

        ttk.Button(testing_frame, text="🔄 Full Test Suite",
                  command=self.run_full_tests, width=20).grid(row=0, column=1, padx=5)

        self.visual_demo_button = ttk.Button(testing_frame, text="🎨 Start Visual Demo",
                                             command=self.toggle_visual_demo, width=20, style='Info.TButton')
        self.visual_demo_button.grid(row=0, column=2, padx=(10, 0))

        # Status Section
        status_frame = ttk.LabelFrame(main_frame, text="System Status", padding="10")
        status_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, sticky=tk.W)
        self.status_label = ttk.Label(status_frame, textvariable=self.status_text,
                                    font=("Segoe UI", 9, "bold"))
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))

        # Progress bar
        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        # Log Section
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=80)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=5, column=0, columnspan=3, pady=(10, 0))

        ttk.Button(control_frame, text="Clear Log",
                  command=self.clear_log).grid(row=0, column=0, padx=(0, 10))

        ttk.Button(control_frame, text="Stop Process",
                  command=self.stop_current_process).grid(row=0, column=1, padx=5)

        ttk.Button(control_frame, text="Exit",
                  command=self.exit_application).grid(row=0, column=2, padx=(10, 0))

        # Initial log message
        self.log("VoiceFlow Control Center initialized")
        self.log("Click 'Setup & Install' if this is your first time using VoiceFlow")

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

    def launch_voiceflow(self):
        """Launch VoiceFlow with visual indicators"""
        self.log("🚀 Launching VoiceFlow...")

        # First run a quick health check
        def after_health_check():
            # Then launch VoiceFlow using direct file execution method that works
            command = [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, 'src'); exec(open('src/voiceflow/ui/cli_enhanced.py').read())"
            ]
            self.run_command_async(command, "VoiceFlow Application")

        # Run quick health check first
        command = [sys.executable, "scripts/dev/quick_smoke_test.py"]
        self.run_command_async(command, "Pre-launch Health Check", after_health_check)

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