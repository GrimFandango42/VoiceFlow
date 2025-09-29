#!/usr/bin/env python3
"""
VoiceFlow Quality Monitor
========================
Real-time quality monitoring and improvement suggestions for transcriptions.

Features:
- Live quality metrics
- Correction suggestions
- Learning progress tracking
- Performance analytics
"""

import sys
import time
import json
import threading
from pathlib import Path
from typing import Dict, List, Any
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime, timedelta

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

class QualityMonitorGUI:
    """Real-time quality monitoring GUI"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VoiceFlow Quality Monitor")
        self.root.geometry("800x600")

        # Data storage
        self.quality_history = []
        self.recent_transcriptions = []
        self.correction_suggestions = []

        # Setup GUI
        self._setup_gui()

        # Start monitoring
        self.monitoring = True
        self._start_monitoring()

    def _setup_gui(self):
        """Setup the GUI layout"""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Quality Overview Tab
        self.overview_frame = ttk.Frame(notebook)
        notebook.add(self.overview_frame, text="Quality Overview")
        self._setup_overview_tab()

        # Transcriptions Tab
        self.transcriptions_frame = ttk.Frame(notebook)
        notebook.add(self.transcriptions_frame, text="Recent Transcriptions")
        self._setup_transcriptions_tab()

        # Suggestions Tab
        self.suggestions_frame = ttk.Frame(notebook)
        notebook.add(self.suggestions_frame, text="Improvement Suggestions")
        self._setup_suggestions_tab()

        # Learning Tab
        self.learning_frame = ttk.Frame(notebook)
        notebook.add(self.learning_frame, text="Learning Progress")
        self._setup_learning_tab()

    def _setup_overview_tab(self):
        """Setup quality overview tab"""
        # Quality metrics frame
        metrics_frame = ttk.LabelFrame(self.overview_frame, text="Current Quality Metrics")
        metrics_frame.pack(fill=tk.X, padx=5, pady=5)

        # Quality indicators
        self.confidence_var = tk.StringVar(value="Confidence: --")
        self.accuracy_var = tk.StringVar(value="Accuracy: --")
        self.speed_var = tk.StringVar(value="Speed: --")
        self.errors_var = tk.StringVar(value="Errors: --")

        ttk.Label(metrics_frame, textvariable=self.confidence_var, font=("Arial", 12)).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(metrics_frame, textvariable=self.accuracy_var, font=("Arial", 12)).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(metrics_frame, textvariable=self.speed_var, font=("Arial", 12)).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(metrics_frame, textvariable=self.errors_var, font=("Arial", 12)).pack(anchor=tk.W, padx=10, pady=2)

        # Real-time status
        status_frame = ttk.LabelFrame(self.overview_frame, text="System Status")
        status_frame.pack(fill=tk.X, padx=5, pady=5)

        self.status_var = tk.StringVar(value="Status: Monitoring...")
        self.last_update_var = tk.StringVar(value="Last Update: --")

        ttk.Label(status_frame, textvariable=self.status_var, font=("Arial", 10)).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(status_frame, textvariable=self.last_update_var, font=("Arial", 10)).pack(anchor=tk.W, padx=10, pady=2)

        # Quality trend chart (simplified)
        chart_frame = ttk.LabelFrame(self.overview_frame, text="Quality Trend")
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.trend_text = scrolledtext.ScrolledText(chart_frame, height=10, width=50)
        self.trend_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _setup_transcriptions_tab(self):
        """Setup recent transcriptions tab"""
        # Controls
        controls_frame = ttk.Frame(self.transcriptions_frame)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(controls_frame, text="Refresh", command=self._refresh_transcriptions).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Clear History", command=self._clear_transcriptions).pack(side=tk.LEFT, padx=5)

        # Transcriptions list
        list_frame = ttk.LabelFrame(self.transcriptions_frame, text="Recent Transcriptions")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create treeview for transcriptions
        columns = ("Time", "Text", "Quality", "Confidence")
        self.transcriptions_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)

        # Configure columns
        self.transcriptions_tree.heading("Time", text="Time")
        self.transcriptions_tree.heading("Text", text="Transcription")
        self.transcriptions_tree.heading("Quality", text="Quality Score")
        self.transcriptions_tree.heading("Confidence", text="Confidence")

        self.transcriptions_tree.column("Time", width=100)
        self.transcriptions_tree.column("Text", width=400)
        self.transcriptions_tree.column("Quality", width=100)
        self.transcriptions_tree.column("Confidence", width=100)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.transcriptions_tree.yview)
        self.transcriptions_tree.configure(yscrollcommand=scrollbar.set)

        self.transcriptions_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _setup_suggestions_tab(self):
        """Setup improvement suggestions tab"""
        # Current suggestions
        current_frame = ttk.LabelFrame(self.suggestions_frame, text="Current Suggestions")
        current_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.suggestions_text = scrolledtext.ScrolledText(current_frame, height=10, width=50)
        self.suggestions_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Controls
        controls_frame = ttk.Frame(self.suggestions_frame)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(controls_frame, text="Apply Suggestions", command=self._apply_suggestions).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Dismiss All", command=self._dismiss_suggestions).pack(side=tk.LEFT, padx=5)

        # Common patterns
        patterns_frame = ttk.LabelFrame(self.suggestions_frame, text="Common Correction Patterns")
        patterns_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.patterns_text = scrolledtext.ScrolledText(patterns_frame, height=8, width=50)
        self.patterns_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _setup_learning_tab(self):
        """Setup learning progress tab"""
        # Learning stats
        stats_frame = ttk.LabelFrame(self.learning_frame, text="Learning Statistics")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)

        self.vocab_size_var = tk.StringVar(value="Vocabulary Size: --")
        self.corrections_var = tk.StringVar(value="Total Corrections: --")
        self.effectiveness_var = tk.StringVar(value="Learning Effectiveness: --")

        ttk.Label(stats_frame, textvariable=self.vocab_size_var, font=("Arial", 12)).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(stats_frame, textvariable=self.corrections_var, font=("Arial", 12)).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Label(stats_frame, textvariable=self.effectiveness_var, font=("Arial", 12)).pack(anchor=tk.W, padx=10, pady=2)

        # Learning log
        log_frame = ttk.LabelFrame(self.learning_frame, text="Learning Activity Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.learning_log = scrolledtext.ScrolledText(log_frame, height=15, width=50)
        self.learning_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Controls
        controls_frame = ttk.Frame(self.learning_frame)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(controls_frame, text="Export Learning Data", command=self._export_learning_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Reset Learning", command=self._reset_learning).pack(side=tk.LEFT, padx=5)

    def _start_monitoring(self):
        """Start the monitoring thread"""
        def monitor_loop():
            while self.monitoring:
                try:
                    self._update_data()
                    time.sleep(2)  # Update every 2 seconds
                except Exception as e:
                    print(f"Monitoring error: {e}")
                    time.sleep(5)

        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()

    def _update_data(self):
        """Update monitoring data"""
        # Check for learning data file
        learning_file = Path("voiceflow_learning.json")
        if learning_file.exists():
            try:
                with open(learning_file, 'r') as f:
                    learning_data = json.load(f)

                # Update learning stats
                vocab_size = len(learning_data.get('domain_vocabulary', {}))
                corrections = len(learning_data.get('correction_pairs', []))

                self.root.after(0, lambda: self.vocab_size_var.set(f"Vocabulary Size: {vocab_size}"))
                self.root.after(0, lambda: self.corrections_var.set(f"Total Corrections: {corrections}"))

                # Update patterns display
                patterns = self._format_patterns(learning_data.get('correction_pairs', []))
                self.root.after(0, lambda: self._update_patterns_display(patterns))

            except Exception as e:
                print(f"Error reading learning data: {e}")

        # Update status
        current_time = datetime.now().strftime("%H:%M:%S")
        self.root.after(0, lambda: self.last_update_var.set(f"Last Update: {current_time}"))

        # Simulate quality metrics (in real implementation, get from ASR)
        self._update_quality_metrics()

    def _update_quality_metrics(self):
        """Update quality metrics display"""
        # In real implementation, get from actual ASR
        confidence = 85.2
        accuracy = 92.1
        speed = "70x realtime"
        errors = 3

        self.root.after(0, lambda: self.confidence_var.set(f"Confidence: {confidence:.1f}%"))
        self.root.after(0, lambda: self.accuracy_var.set(f"Accuracy: {accuracy:.1f}%"))
        self.root.after(0, lambda: self.speed_var.set(f"Speed: {speed}"))
        self.root.after(0, lambda: self.errors_var.set(f"Recent Errors: {errors}"))

        # Update trend
        trend_entry = f"{datetime.now().strftime('%H:%M:%S')} - Quality: {accuracy:.1f}%, Confidence: {confidence:.1f}%\n"
        self.root.after(0, lambda: self._append_to_trend(trend_entry))

    def _append_to_trend(self, text):
        """Append text to trend display"""
        self.trend_text.insert(tk.END, text)
        self.trend_text.see(tk.END)

        # Keep only last 50 lines
        lines = self.trend_text.get("1.0", tk.END).split('\n')
        if len(lines) > 50:
            self.trend_text.delete("1.0", "2.0")

    def _format_patterns(self, correction_pairs):
        """Format correction patterns for display"""
        if not correction_pairs:
            return "No correction patterns learned yet."

        # Count frequency of patterns
        pattern_counts = {}
        for original, corrected in correction_pairs[-50:]:  # Recent patterns
            pattern = f"{original} → {corrected}"
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        # Sort by frequency
        sorted_patterns = sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)

        formatted = "Most Common Correction Patterns:\n\n"
        for pattern, count in sorted_patterns[:10]:
            formatted += f"{pattern} (×{count})\n"

        return formatted

    def _update_patterns_display(self, patterns):
        """Update patterns display"""
        self.patterns_text.delete("1.0", tk.END)
        self.patterns_text.insert("1.0", patterns)

    def _refresh_transcriptions(self):
        """Refresh transcriptions list"""
        # Clear existing items
        for item in self.transcriptions_tree.get_children():
            self.transcriptions_tree.delete(item)

        # Add sample data (in real implementation, get from actual transcriptions)
        sample_data = [
            ("12:34:56", "Hello, this is a test transcription", "92.1%", "88.5%"),
            ("12:35:12", "The quality monitoring system is working well", "95.3%", "91.2%"),
            ("12:35:45", "Python code review completed successfully", "89.7%", "85.1%"),
        ]

        for item in sample_data:
            self.transcriptions_tree.insert("", tk.END, values=item)

    def _clear_transcriptions(self):
        """Clear transcriptions history"""
        for item in self.transcriptions_tree.get_children():
            self.transcriptions_tree.delete(item)

    def _apply_suggestions(self):
        """Apply current suggestions"""
        self.suggestions_text.insert(tk.END, "\n[System] Suggestions applied to learning model.\n")
        self.suggestions_text.see(tk.END)

    def _dismiss_suggestions(self):
        """Dismiss all suggestions"""
        self.suggestions_text.delete("1.0", tk.END)
        self.suggestions_text.insert("1.0", "No current suggestions.\n")

    def _export_learning_data(self):
        """Export learning data"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_msg = f"[{timestamp}] Learning data exported to voiceflow_export_{timestamp}.json\n"
        self.learning_log.insert(tk.END, export_msg)
        self.learning_log.see(tk.END)

    def _reset_learning(self):
        """Reset learning data"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        reset_msg = f"[{timestamp}] Learning data reset. Starting fresh learning session.\n"
        self.learning_log.insert(tk.END, reset_msg)
        self.learning_log.see(tk.END)

    def run(self):
        """Run the quality monitor"""
        print("Starting VoiceFlow Quality Monitor...")
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            print("Quality monitor stopped.")
        finally:
            self.monitoring = False

def main():
    """Main function"""
    try:
        monitor = QualityMonitorGUI()
        monitor.run()
    except Exception as e:
        print(f"Error starting quality monitor: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()