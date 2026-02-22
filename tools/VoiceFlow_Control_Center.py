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

class VoiceFlowControlCenter:
    """Unified control center for VoiceFlow operations"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VoiceFlow Control Center")
        self.root.geometry("1000x720")
        self.root.minsize(920, 650)
        self.root.resizable(True, True)

        # State tracking
        self.current_process: Optional[subprocess.Popen] = None
        self.visual_demo_process: Optional[subprocess.Popen] = None
        self.visual_demo_running = False
        self.status_text = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar()

        # Process monitoring and restart capability
        self.auto_restart_enabled = True
        self.process_start_time = None
        self.restart_count = 0
        self.max_restarts = 3
        self.restart_cooldown = 30  # seconds

        self.system_status_vars: Dict[str, tk.StringVar] = {
            "Python": tk.StringVar(value="Pending"),
            "Core Files": tk.StringVar(value="Pending"),
            "Environment": tk.StringVar(value="Pending"),
            "GPU": tk.StringVar(value="Pending"),
            "Last Check": tk.StringVar(value="Pending"),
        }

        self.palette = {
            "bg": "#F3F6FA",
            "surface": "#FFFFFF",
            "surface_alt": "#EFF3F8",
            "hero": "#10233A",
            "accent": "#1570EF",
            "accent_hover": "#175CD3",
            "accent_pressed": "#1849A9",
            "text_primary": "#0F172A",
            "text_secondary": "#334155",
            "text_muted": "#64748B",
            "border": "#D0D7E2",
            "log_bg": "#0C111D",
            "log_fg": "#D6DEEB",
        }


        # UI Components
        self.log_text: Optional[scrolledtext.ScrolledText] = None
        self.status_label: Optional[ttk.Label] = None
        self.progress_bar: Optional[ttk.Progressbar] = None
        self.visual_demo_button: Optional[ttk.Button] = None

        self._setup_styling()
        self._setup_ui()
        self._check_initial_status()

    def _setup_styling(self):
        """Modern, restrained UI styling for a guided workflow."""
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("Main.TFrame", background=self.palette["bg"])
        style.configure("Hero.TFrame", background=self.palette["hero"], relief=tk.FLAT)
        style.configure("Card.TFrame", background=self.palette["surface"], relief=tk.SOLID, borderwidth=1)

        style.configure("Panel.TLabelframe", background=self.palette["surface"], borderwidth=1, relief=tk.SOLID)
        style.configure(
            "Panel.TLabelframe.Label",
            background=self.palette["surface"],
            foreground=self.palette["text_secondary"],
            font=("Segoe UI", 10, "bold"),
        )

        style.configure(
            "HeroTitle.TLabel",
            background=self.palette["hero"],
            foreground="#F8FAFC",
            font=("Segoe UI Semibold", 22),
        )
        style.configure(
            "HeroSub.TLabel",
            background=self.palette["hero"],
            foreground="#C8D4E6",
            font=("Segoe UI", 10),
        )
        style.configure(
            "CardTitle.TLabel",
            background=self.palette["surface"],
            foreground=self.palette["text_primary"],
            font=("Segoe UI Semibold", 12),
        )
        style.configure(
            "Body.TLabel",
            background=self.palette["surface"],
            foreground=self.palette["text_secondary"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Meta.TLabel",
            background=self.palette["surface"],
            foreground=self.palette["text_muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "StatusValue.TLabel",
            background=self.palette["surface"],
            foreground=self.palette["text_secondary"],
            font=("Segoe UI", 9, "bold"),
        )

        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(16, 10),
            relief=tk.FLAT,
            background=self.palette["accent"],
            foreground="#FFFFFF",
            borderwidth=0,
        )
        style.map(
            "Primary.TButton",
            background=[
                ("pressed", self.palette["accent_pressed"]),
                ("active", self.palette["accent_hover"]),
                ("disabled", "#9FB6D9"),
            ],
            foreground=[("disabled", "#E2E8F0")],
        )

        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 9, "bold"),
            padding=(12, 8),
            relief=tk.FLAT,
            background=self.palette["surface_alt"],
            foreground=self.palette["text_secondary"],
            borderwidth=1,
        )
        style.map(
            "Secondary.TButton",
            background=[
                ("pressed", "#DCE5F2"),
                ("active", "#E4EBF5"),
            ],
        )

        style.configure(
            "Danger.TButton",
            font=("Segoe UI", 9, "bold"),
            padding=(12, 8),
            relief=tk.FLAT,
            background="#FEE4E2",
            foreground="#B42318",
            borderwidth=1,
        )
        style.map(
            "Danger.TButton",
            background=[
                ("pressed", "#FDC5C0"),
                ("active", "#FDD8D3"),
            ],
        )

    def _setup_ui(self):
        """Set up a polished, guided interface for daily operation."""
        self.root.configure(bg=self.palette["bg"])

        main_frame = ttk.Frame(self.root, style="Main.TFrame", padding=(20, 20, 20, 16))
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)

        hero = ttk.Frame(main_frame, style="Hero.TFrame", padding=(22, 18, 22, 18))
        hero.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 14))
        hero.columnconfigure(0, weight=1)

        ttk.Label(hero, text="VoiceFlow Control Center", style="HeroTitle.TLabel").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(
            hero,
            text="Launch, validate, and troubleshoot VoiceFlow from one guided interface.",
            style="HeroSub.TLabel",
        ).grid(row=1, column=0, sticky=tk.W, pady=(6, 0))
        ttk.Label(
            hero,
            text="Quick start: 1) Setup & Install   2) Launch VoiceFlow   3) Review activity log if needed.",
            style="HeroSub.TLabel",
        ).grid(row=2, column=0, sticky=tk.W, pady=(3, 0))

        top_grid = ttk.Frame(main_frame, style="Main.TFrame")
        top_grid.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 12))
        top_grid.columnconfigure(0, weight=3)
        top_grid.columnconfigure(1, weight=2)

        actions_card = ttk.Frame(top_grid, style="Card.TFrame", padding=(16, 14, 16, 14))
        actions_card.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 8))
        actions_card.columnconfigure(0, weight=1)
        actions_card.columnconfigure(1, weight=1)
        actions_card.columnconfigure(2, weight=1)

        ttk.Label(actions_card, text="Quick Actions", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=3, sticky=tk.W)
        ttk.Label(
            actions_card,
            text="Use setup for first-run environments. Launch runs a health check before starting VoiceFlow.",
            style="Body.TLabel",
        ).grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(4, 12))

        self.launch_button = ttk.Button(
            actions_card,
            text="Launch VoiceFlow",
            style="Primary.TButton",
            command=self.smart_launch,
        )
        self.launch_button.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), padx=(0, 8), pady=(0, 8))

        self.setup_button = ttk.Button(
            actions_card,
            text="Setup & Install",
            style="Secondary.TButton",
            command=self.smart_setup,
        )
        self.setup_button.grid(row=2, column=2, sticky=(tk.W, tk.E), pady=(0, 8))

        ttk.Button(
            actions_card,
            text="Health Check",
            style="Secondary.TButton",
            command=self.run_health_check,
        ).grid(row=3, column=0, sticky=(tk.W, tk.E), padx=(0, 8))

        ttk.Button(
            actions_card,
            text="Open Logs",
            style="Secondary.TButton",
            command=self.open_logs_folder,
        ).grid(row=3, column=1, sticky=(tk.W, tk.E), padx=(0, 8))

        ttk.Button(
            actions_card,
            text="Toggle Troubleshooting",
            style="Secondary.TButton",
            command=self.toggle_troubleshoot_panel,
        ).grid(row=3, column=2, sticky=(tk.W, tk.E))

        health_card = ttk.Frame(top_grid, style="Card.TFrame", padding=(16, 14, 16, 14))
        health_card.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(8, 0))
        health_card.columnconfigure(1, weight=1)

        ttk.Label(health_card, text="System Snapshot", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=2, sticky=tk.W)
        ttk.Label(
            health_card,
            text="Live checks for environment readiness.",
            style="Body.TLabel",
        ).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(4, 10))

        for row_idx, key in enumerate(self.system_status_vars.keys(), start=2):
            ttk.Label(health_card, text=key, style="Meta.TLabel").grid(row=row_idx, column=0, sticky=tk.W, pady=2)
            ttk.Label(
                health_card,
                textvariable=self.system_status_vars[key],
                style="StatusValue.TLabel",
            ).grid(row=row_idx, column=1, sticky=tk.W, pady=2, padx=(8, 0))

        status_strip = ttk.Frame(main_frame, style="Card.TFrame", padding=(14, 10, 14, 10))
        status_strip.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        status_strip.columnconfigure(1, weight=1)

        ttk.Label(status_strip, text="Status", style="Meta.TLabel").grid(row=0, column=0, sticky=tk.W)
        self.status_label = ttk.Label(status_strip, textvariable=self.status_text, style="StatusValue.TLabel")
        self.status_label.grid(row=0, column=1, sticky=tk.W, padx=(8, 0))

        self.progress_bar = ttk.Progressbar(status_strip, mode="indeterminate")
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(7, 0))

        self.troubleshoot_frame = ttk.LabelFrame(
            main_frame,
            text="Troubleshooting",
            style="Panel.TLabelframe",
            padding=12,
        )
        self.troubleshoot_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        self.troubleshoot_frame.columnconfigure(0, weight=1)
        self.troubleshoot_frame.columnconfigure(1, weight=1)
        self.troubleshoot_frame.columnconfigure(2, weight=1)
        self.troubleshoot_frame.grid_remove()
        self.troubleshoot_visible = False

        ttk.Button(
            self.troubleshoot_frame,
            text="Critical Tests",
            style="Secondary.TButton",
            command=self.run_critical_tests,
        ).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 8))

        ttk.Button(
            self.troubleshoot_frame,
            text="Full Test Suite",
            style="Secondary.TButton",
            command=self.run_full_tests,
        ).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 8))

        self.visual_demo_button = ttk.Button(
            self.troubleshoot_frame,
            text="Start Visual Demo",
            style="Secondary.TButton",
            command=self.toggle_visual_demo,
        )
        self.visual_demo_button.grid(row=0, column=2, sticky=(tk.W, tk.E))

        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", style="Panel.TLabelframe", padding=10)
        log_frame.grid(row=4, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=14,
            width=120,
            font=("Consolas", 9),
            bg=self.palette["log_bg"],
            fg=self.palette["log_fg"],
            insertbackground=self.palette["log_fg"],
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#23324C",
            wrap=tk.WORD,
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        control_frame = ttk.Frame(main_frame, style="Main.TFrame")
        control_frame.grid(row=5, column=0, sticky=tk.E)

        ttk.Button(
            control_frame,
            text="Stop Process",
            style="Danger.TButton",
            command=self.stop_current_process,
        ).grid(row=0, column=0, padx=(0, 8))

        ttk.Button(
            control_frame,
            text="Clear Log",
            style="Secondary.TButton",
            command=self.clear_log,
        ).grid(row=0, column=1, padx=(0, 8))

        ttk.Button(
            control_frame,
            text="Exit",
            style="Secondary.TButton",
            command=self.exit_application,
        ).grid(row=0, column=2)

        self.log("VoiceFlow Control Center ready.")
        self.log("Suggested first-run flow: Setup & Install -> Launch VoiceFlow.")

    @staticmethod
    def _status_badge(ok: bool, warn: bool = False) -> str:
        if ok:
            return "OK"
        if warn:
            return "WARN"
        return "ERROR"

    def _set_system_status(self, key: str, value: str, ok: bool = True, warn: bool = False) -> None:
        var = self.system_status_vars.get(key)
        if var is None:
            return
        var.set(f"{self._status_badge(ok=ok, warn=warn)}  {value}")

    def log(self, message: str, level: str = "INFO"):
        """Add message to log with timestamp"""
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, lambda m=message, l=level: self.log(m, l))
            return

        timestamp = time.strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {level}: {message}\n"

        if self.log_text:
            self.log_text.insert(tk.END, log_message)
            self.log_text.see(tk.END)

    def update_status(self, message: str):
        """Update status label"""
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, lambda m=message: self.update_status(m))
            return
        self.status_text.set(message)
        self.root.update_idletasks()

    def start_progress(self):
        """Start progress bar animation"""
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, self.start_progress)
            return
        if self.progress_bar:
            self.progress_bar.start(10)

    def stop_progress(self):
        """Stop progress bar animation"""
        if threading.current_thread() is not threading.main_thread():
            self.root.after(0, self.stop_progress)
            return
        if self.progress_bar:
            self.progress_bar.stop()

    def _check_initial_status(self):
        """Check initial system status"""
        self.log("Checking system status.")

        # Quick Python version check
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        self.log(f"Python version: {python_version}")
        self._set_system_status("Python", python_version, ok=True)

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
            self.log(f"Missing critical files: {', '.join(missing_files)}", "WARN")
            self._set_system_status("Core Files", f"Missing {len(missing_files)} file(s)", ok=False)
            self.update_status("Setup required")
        else:
            self.log("All critical files present.")
            self._set_system_status("Core Files", "All required files present", ok=True)
            self.update_status("Ready")

        env_state = "System Python"
        if (root_dir / ".venv-gpu" / "Scripts" / "python.exe").exists():
            env_state = ".venv-gpu detected"
        elif (root_dir / "venv" / "Scripts" / "python.exe").exists():
            env_state = "venv detected"
        self._set_system_status("Environment", env_state, ok=True)

        gpu_detected = False
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.returncode == 0:
                names = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
                if names:
                    self._set_system_status("GPU", names[0], ok=True)
                    gpu_detected = True
        except Exception:
            gpu_detected = False

        if not gpu_detected:
            self._set_system_status("GPU", "Not detected", ok=True, warn=True)

        self._set_system_status("Last Check", time.strftime("%Y-%m-%d %H:%M:%S"), ok=True)

    def run_command_async(self, command: List[str], description: str,
                         callback: Optional[Callable[[bool], None]] = None):
        """Run command asynchronously and log output"""
        def run_in_thread():
            self.log(f"Starting: {description}")
            self.start_progress()
            self.update_status(f"Running: {description}")
            success = False
            process: Optional[subprocess.Popen] = None

            try:
                # Start process
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    universal_newlines=True,
                    cwd=Path(__file__).parent.parent,  # Go up to VoiceFlow root directory
                    env={**os.environ, 'PYTHONPATH': str(Path(__file__).parent.parent / 'src')}
                )
                self.current_process = process
                if self.auto_restart_enabled and process:
                    self.start_process_monitoring(process)

                # Read output line by line
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        # Clean and log output
                        clean_output = output.strip()
                        if clean_output:
                            self.log(clean_output)

                # Get final return code
                return_code = process.poll()

                if return_code == 0:
                    self.log(f"{description} completed successfully")
                    self.update_status("Complete")
                    success = True
                else:
                    self.log(f"{description} failed with exit code {return_code}", "ERROR")
                    self.update_status("Failed")

            except Exception as e:
                self.log(f"{description} error: {str(e)}", "ERROR")
                self.update_status("Error")

            finally:
                self.stop_progress()
                if process is not None and self.current_process is process:
                    self.current_process = None

                # Run callback if provided
                if callback:
                    self.root.after(0, lambda ok=success: callback(ok))

        # Start in separate thread
        thread = threading.Thread(target=run_in_thread, daemon=True)
        thread.start()

    def smart_launch(self):
        """Smart launch with auto health check and intelligent error handling"""
        self.log("Smart launch: health-check then VoiceFlow runtime.")

        # CRITICAL: Clean up any persistent visual indicators from previous sessions
        try:
            self.log("Cleaning up visual indicator state from prior session.")
            python_cleanup = [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, 'src'); "
                "from voiceflow.ui.visual_indicators import ensure_clean_startup; "
                "ensure_clean_startup()"
            ]
            subprocess.run(python_cleanup, timeout=5, capture_output=True)
            self.log("Visual cleanup completed.")
        except Exception as e:
            self.log(f"Visual cleanup warning: {e}", "WARN")

        def after_health_check(passed: bool):
            if passed:
                self.hide_troubleshoot_panel()
                self.log("Health check passed - launching VoiceFlow.")
                self.process_start_time = time.time()  # Track start time
                command = [
                    sys.executable,
                    "-m",
                    "voiceflow.ui.cli_enhanced",
                ]
                self.run_command_async(command, "VoiceFlow Enhanced Application")
            else:
                self.log("Health check failed - troubleshooting options enabled.", "WARN")
                self.show_troubleshoot_panel()

        # Run intelligent health check
        self.run_smart_health_check(after_health_check)

    def smart_setup(self):
        """Smart setup with comprehensive health checking"""
        self.log("Setup: installing and configuring VoiceFlow.")

        def after_setup(_passed: bool):
            self.log("Setup complete. You can now use 'Launch VoiceFlow'.")

        command = [sys.executable, "scripts/setup/setup_voiceflow.py"]
        self.run_command_async(command, "Smart Setup & Installation", after_setup)

    def show_troubleshoot_panel(self):
        """Show the troubleshooting panel when needed"""
        if not self.troubleshoot_visible:
            self.troubleshoot_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
            self.troubleshoot_visible = True
            self.log("Troubleshooting panel now available.")

    def hide_troubleshoot_panel(self):
        """Hide the troubleshooting panel when not needed"""
        if self.troubleshoot_visible:
            self.troubleshoot_frame.grid_remove()
            self.troubleshoot_visible = False
            self.log("Troubleshooting panel hidden.")

    def toggle_troubleshoot_panel(self):
        if self.troubleshoot_visible:
            self.hide_troubleshoot_panel()
        else:
            self.show_troubleshoot_panel()

    def run_smart_health_check(self, completion_callback: Optional[Callable[[bool], None]] = None):
        """Run quick smoke-based health check before launch."""
        command = [sys.executable, "scripts/dev/quick_smoke_test.py"]
        self.run_command_async(command, "Intelligent Health Check", completion_callback)

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

    def open_logs_folder(self):
        """Open LocalFlow logs folder in Explorer."""
        try:
            local = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
            logs_dir = local / "LocalFlow" / "logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            os.startfile(str(logs_dir))  # type: ignore[attr-defined]
            self.log(f"Opened logs folder: {logs_dir}")
        except Exception as e:
            self.log(f"Failed to open logs folder: {e}", "ERROR")

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
            self.visual_demo_button.configure(text="Stop Visual Demo")
            self.log("Visual demo started", "INFO")
        except Exception as e:
            self.log(f"Failed to start visual demo: {e}", "ERROR")

    def stop_visual_demo(self):
        """Stop visual configuration demo"""
        try:
            if self.visual_demo_process:
                self.visual_demo_process.terminate()
                self.visual_demo_process = None
            self.visual_demo_running = False
            self.visual_demo_button.configure(text="Start Visual Demo")
            self.log("Visual demo stopped", "WARN")
        except Exception as e:
            self.log(f"Failed to stop visual demo: {e}", "ERROR")

    def stop_current_process(self):
        """Stop currently running process"""
        if self.current_process:
            try:
                self.current_process.terminate()
                self.log("Process terminated", "WARN")
                self.update_status("Stopped")
            except Exception as e:
                self.log(f"Error stopping process: {e}", "ERROR")
        else:
            self.log("No process currently running")

    def clear_log(self):
        """Clear the log text"""
        if self.log_text:
            self.log_text.delete(1.0, tk.END)

    def start_process_monitoring(self, process: subprocess.Popen):
        """Start monitoring a specific process for hangs and crashes."""
        if not process:
            return

        def monitor_process():
            """Monitor process health in background thread"""
            check_interval = 60  # Check every minute
            last_status_time = time.time()

            while process.poll() is None:
                try:
                    current_time = time.time()
                    uptime = current_time - (self.process_start_time or time.time())

                    # Log health status every 10 minutes (not 5)
                    if current_time - last_status_time > 600:  # 10 minutes
                        self.log(f"[MONITOR] Process healthy, uptime: {uptime/60:.1f} minutes", "INFO")
                        last_status_time = current_time

                    time.sleep(check_interval)

                except Exception as e:
                    self.log(f"[MONITOR] Monitoring error: {e}", "ERROR")
                    break

            # Process ended - check if restart needed
            if process.poll() is not None and process is self.current_process:
                return_code = process.poll()
                if return_code != 0 and self.auto_restart_enabled:
                    self.schedule_restart(f"Process crashed with exit code {return_code}")

        # Start monitoring thread
        monitor_thread = threading.Thread(target=monitor_process, daemon=True)
        monitor_thread.start()

    def schedule_restart(self, reason: str):
        """Schedule an automatic restart if conditions are met"""
        if self.restart_count >= self.max_restarts:
            self.log(f"[RESTART] Max restarts ({self.max_restarts}) reached. Manual intervention required.", "ERROR")
            return

        self.log(f"[RESTART] Scheduling restart: {reason}", "WARN")
        self.restart_count += 1

        def do_restart():
            self.log(f"[RESTART] Attempting restart {self.restart_count}/{self.max_restarts}...", "INFO")

            # Stop current process
            self.stop_current_process()
            time.sleep(2)  # Brief pause

            # Restart VoiceFlow
            self.smart_launch()

        # Schedule restart after cooldown
        restart_timer = threading.Timer(self.restart_cooldown, do_restart)
        restart_timer.start()

    def reset_restart_counter(self):
        """Reset restart counter after successful operation"""
        if self.restart_count > 0:
            self.log(f"[RESTART] Reset counter after successful operation", "INFO")
            self.restart_count = 0

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
