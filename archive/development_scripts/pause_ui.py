#!/usr/bin/env python3
"""
VoiceFlow Pause Detection User Interface
=======================================

User experience improvements including visual feedback, pause behavior 
customization, and real-time pause analysis display.

Features:
- Real-time pause detection visualization
- Interactive pause threshold adjustment
- Context switching interface
- Performance monitoring dashboard
- User guidance for optimal pause duration
- Customizable pause profiles per application context
"""

import time
import threading
import json
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import os
import sys

# Try to import rich for better terminal output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.layout import Layout
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Import pause detection modules
try:
    from pause_analyzer import PauseType, ContextType, PauseEvent
    from vad_profiles import VADProfileManager, PerformanceMetric
    PAUSE_MODULES_AVAILABLE = True
except ImportError:
    PAUSE_MODULES_AVAILABLE = False


class UITheme(Enum):
    """UI color themes"""
    DEFAULT = "default"
    DARK = "dark"
    LIGHT = "light"
    MINIMAL = "minimal"


@dataclass
class PauseVisualizationConfig:
    """Configuration for pause visualization"""
    show_real_time: bool = True
    show_confidence: bool = True
    show_context: bool = True
    show_statistics: bool = True
    update_interval: float = 0.5
    max_history: int = 20


class PauseVisualization:
    """Real-time pause detection visualization"""
    
    def __init__(self, config: PauseVisualizationConfig = None):
        self.config = config or PauseVisualizationConfig()
        self.console = Console() if RICH_AVAILABLE else None
        self.is_running = False
        self.update_thread = None
        
        # Data tracking
        self.current_pause_event = None
        self.pause_history = []
        self.current_context = ContextType.CHAT
        self.recording_state = "idle"  # idle, recording, processing
        self.pause_start_time = None
        
        # Statistics
        self.session_start = time.time()
        self.total_pauses = 0
        self.pause_type_counts = {pause_type: 0 for pause_type in PauseType}
        
        # Callbacks
        self.on_pause_detected: Optional[Callable] = None
        self.on_context_changed: Optional[Callable] = None
    
    def start(self):
        """Start the visualization"""
        if not RICH_AVAILABLE:
            print("⚠️  Rich library not available. Using basic output.")
            return
        
        self.is_running = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        print("🎯 Pause visualization started")
    
    def stop(self):
        """Stop the visualization"""
        self.is_running = False
        if self.update_thread:
            self.update_thread.join(timeout=1.0)
        print("⏹️  Pause visualization stopped")
    
    def update_pause_event(self, pause_event: PauseEvent):
        """Update with new pause event"""
        self.current_pause_event = pause_event
        self.pause_history.append(pause_event)
        
        # Keep history limited
        if len(self.pause_history) > self.config.max_history:
            self.pause_history.pop(0)
        
        # Update statistics
        self.total_pauses += 1
        self.pause_type_counts[pause_event.classification] += 1
        
        # Trigger callback
        if self.on_pause_detected:
            self.on_pause_detected(pause_event)
    
    def set_recording_state(self, state: str):
        """Update recording state (idle, recording, processing)"""
        self.recording_state = state
        if state == "recording":
            self.pause_start_time = None
        elif state == "idle":
            self.pause_start_time = time.time()
    
    def set_context(self, context: ContextType):
        """Update current context"""
        self.current_context = context
        if self.on_context_changed:
            self.on_context_changed(context)
    
    def _update_loop(self):
        """Main update loop for live visualization"""
        if not RICH_AVAILABLE:
            return
        
        with Live(self._create_layout(), refresh_per_second=2, console=self.console) as live:
            while self.is_running:
                try:
                    live.update(self._create_layout())
                    time.sleep(self.config.update_interval)
                except KeyboardInterrupt:
                    break
    
    def _create_layout(self) -> Layout:
        """Create the main layout for visualization"""
        layout = Layout()
        
        # Split into header, main, and footer
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=5)
        )
        
        # Split main area
        layout["main"].split_row(
            Layout(name="status", ratio=1),
            Layout(name="history", ratio=2)
        )
        
        # Populate sections
        layout["header"].update(self._create_header())
        layout["status"].update(self._create_status_panel())
        layout["history"].update(self._create_history_panel())
        layout["footer"].update(self._create_footer())
        
        return layout
    
    def _create_header(self) -> Panel:
        """Create header panel"""
        session_time = time.time() - self.session_start
        status_color = {
            "idle": "yellow",
            "recording": "red",
            "processing": "blue"
        }.get(self.recording_state, "white")
        
        header_text = Text()
        header_text.append("VoiceFlow Pause Detection", style="bold blue")
        header_text.append(f" | Session: {session_time/60:.1f}m", style="dim")
        header_text.append(f" | Status: ", style="dim")
        header_text.append(self.recording_state.upper(), style=f"bold {status_color}")
        header_text.append(f" | Context: {self.current_context.value}", style="green")
        
        return Panel(header_text, box=box.ROUNDED, style="blue")
    
    def _create_status_panel(self) -> Panel:
        """Create current status panel"""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Label", style="cyan")
        table.add_column("Value", style="white")
        
        # Current pause info
        if self.current_pause_event:
            pe = self.current_pause_event
            table.add_row("Last Pause", f"{pe.classification.value}")
            table.add_row("Duration", f"{pe.duration:.2f}s")
            table.add_row("Confidence", f"{pe.confidence:.1%}")
            table.add_row("Context", pe.context.value)
        elif self.pause_start_time and self.recording_state == "idle":
            current_pause = time.time() - self.pause_start_time
            table.add_row("Current Pause", f"{current_pause:.1f}s")
            table.add_row("Status", "Listening...")
        else:
            table.add_row("Status", "Ready for speech")
        
        table.add_row("", "")  # Separator
        table.add_row("Total Pauses", str(self.total_pauses))
        
        # Top pause types
        if self.pause_type_counts:
            sorted_types = sorted(
                self.pause_type_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:3]
            
            for pause_type, count in sorted_types:
                if count > 0:
                    table.add_row(pause_type.value, str(count))
        
        return Panel(table, title="Current Status", box=box.ROUNDED)
    
    def _create_history_panel(self) -> Panel:
        """Create pause history panel"""
        table = Table(box=None)
        table.add_column("Time", style="dim", width=8)
        table.add_column("Type", style="yellow", width=15)
        table.add_column("Duration", style="cyan", width=8)
        table.add_column("Confidence", style="green", width=10)
        table.add_column("Context", style="blue", width=12)
        
        # Show recent pause history
        recent_pauses = self.pause_history[-10:] if self.pause_history else []
        
        for pause_event in recent_pauses:
            time_str = datetime.fromtimestamp(pause_event.start_time).strftime("%H:%M:%S")
            confidence_str = f"{pause_event.confidence:.1%}"
            
            # Color code based on confidence
            confidence_style = "green" if pause_event.confidence > 0.7 else "yellow" if pause_event.confidence > 0.4 else "red"
            
            table.add_row(
                time_str,
                pause_event.classification.value,
                f"{pause_event.duration:.2f}s",
                Text(confidence_str, style=confidence_style),
                pause_event.context.value
            )
        
        if not recent_pauses:
            table.add_row("--", "No pauses detected yet", "--", "--", "--")
        
        return Panel(table, title="Pause History", box=box.ROUNDED)
    
    def _create_footer(self) -> Panel:
        """Create footer with controls"""
        controls = [
            "🎤 [red]Ctrl+C[/red] Stop",
            "🎯 [blue]c[/blue] Change Context", 
            "⚙️  [green]p[/green] Profiles",
            "📊 [yellow]s[/yellow] Stats"
        ]
        
        footer_text = " | ".join(controls)
        return Panel(footer_text, box=box.ROUNDED, style="dim")


class InteractivePauseConfig:
    """Interactive pause configuration interface"""
    
    def __init__(self, vad_manager: 'VADProfileManager' = None):
        self.vad_manager = vad_manager
        self.console = Console() if RICH_AVAILABLE else None
        self.current_settings = {}
    
    def show_configuration_menu(self):
        """Show interactive configuration menu"""
        while True:
            if RICH_AVAILABLE:
                self._show_rich_menu()
            else:
                self._show_basic_menu()
            
            try:
                choice = input("\nEnter your choice (q to quit): ").strip().lower()
                
                if choice == 'q':
                    break
                elif choice == '1':
                    self._configure_context()
                elif choice == '2':
                    self._configure_vad_profile()
                elif choice == '3':
                    self._adjust_thresholds()
                elif choice == '4':
                    self._view_performance()
                elif choice == '5':
                    self._export_import_profiles()
                else:
                    print("❌ Invalid choice")
            
            except KeyboardInterrupt:
                break
    
    def _show_rich_menu(self):
        """Show configuration menu with rich formatting"""
        if not self.console:
            return
        
        table = Table(title="Pause Detection Configuration", box=box.ROUNDED)
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white")
        table.add_column("Current", style="green")
        
        table.add_row("1", "Change Context Type", str(self.current_settings.get('context', 'chat')))
        table.add_row("2", "Select VAD Profile", str(self.current_settings.get('vad_profile', 'balanced')))
        table.add_row("3", "Adjust Thresholds", "Custom settings")
        table.add_row("4", "View Performance", "Analytics")
        table.add_row("5", "Manage Profiles", "Import/Export")
        table.add_row("q", "Quit", "Exit configuration")
        
        self.console.print(table)
    
    def _show_basic_menu(self):
        """Show basic text menu"""
        print("\n" + "="*50)
        print("  VoiceFlow Pause Detection Configuration")
        print("="*50)
        print("1. Change Context Type")
        print("2. Select VAD Profile") 
        print("3. Adjust Thresholds")
        print("4. View Performance")
        print("5. Manage Profiles")
        print("q. Quit")
    
    def _configure_context(self):
        """Configure conversation context"""
        print("\n🎯 Context Configuration")
        print("Available contexts:")
        
        contexts = list(ContextType)
        for i, context in enumerate(contexts, 1):
            print(f"  {i}. {context.value} - {self._get_context_description(context)}")
        
        try:
            choice = int(input(f"\nSelect context (1-{len(contexts)}): "))
            if 1 <= choice <= len(contexts):
                selected_context = contexts[choice - 1]
                self.current_settings['context'] = selected_context.value
                print(f"✅ Context set to: {selected_context.value}")
            else:
                print("❌ Invalid choice")
        except ValueError:
            print("❌ Please enter a number")
    
    def _get_context_description(self, context: ContextType) -> str:
        """Get description for context type"""
        descriptions = {
            ContextType.CODING: "Technical dictation with longer thinking pauses",
            ContextType.WRITING: "Creative writing with varied pause patterns",
            ContextType.CHAT: "Casual conversation with shorter pauses",
            ContextType.PRESENTATION: "Formal speaking with structured pauses",
            ContextType.DICTATION: "Pure transcription with minimal pauses"
        }
        return descriptions.get(context, "General purpose context")
    
    def _configure_vad_profile(self):
        """Configure VAD profile"""
        if not self.vad_manager:
            print("❌ VAD manager not available")
            return
        
        print("\n⚙️  VAD Profile Configuration")
        profiles = self.vad_manager.list_profiles()
        
        print("Available profiles:")
        profile_list = list(profiles['profiles'].keys())
        
        for i, (name, info) in enumerate(profiles['profiles'].items(), 1):
            active_marker = " ✅" if info['is_active'] else ""
            print(f"  {i}. {name} ({info['type']}){active_marker}")
            print(f"     {info['description']}")
        
        try:
            choice = int(input(f"\nSelect profile (1-{len(profile_list)}): "))
            if 1 <= choice <= len(profile_list):
                selected_profile = profile_list[choice - 1]
                if self.vad_manager.set_active_profile(selected_profile):
                    self.current_settings['vad_profile'] = selected_profile
                    print(f"✅ VAD profile set to: {selected_profile}")
                else:
                    print("❌ Failed to set profile")
            else:
                print("❌ Invalid choice")
        except ValueError:
            print("❌ Please enter a number")
    
    def _adjust_thresholds(self):
        """Adjust pause thresholds"""
        print("\n🎛️  Threshold Adjustment")
        print("Current thresholds:")
        
        if self.vad_manager:
            config = self.vad_manager.get_profile_config()
            
            adjustable_params = [
                ('post_speech_silence_duration', 'Silence Duration', 's', 0.1, 5.0),
                ('silero_sensitivity', 'Silero Sensitivity', '', 0.1, 1.0),
                ('min_length_of_recording', 'Min Recording Length', 's', 0.05, 2.0)
            ]
            
            for param, label, unit, min_val, max_val in adjustable_params:
                current_val = config.get(param, 0)
                print(f"  {label}: {current_val:.2f}{unit}")
            
            # Allow adjustment
            print("\nAdjust parameters (enter to skip):")
            
            new_config = {}
            for param, label, unit, min_val, max_val in adjustable_params:
                current_val = config.get(param, 0)
                try:
                    user_input = input(f"{label} ({min_val}-{max_val}{unit}, current: {current_val:.2f}): ")
                    if user_input.strip():
                        new_val = float(user_input)
                        if min_val <= new_val <= max_val:
                            new_config[param] = new_val
                        else:
                            print(f"  ⚠️ Value {new_val} out of range, keeping current")
                except ValueError:
                    print(f"  ⚠️ Invalid value, keeping current")
            
            if new_config:
                # Create custom profile with adjustments
                profile_name = f"custom_{int(time.time())}"
                if self.vad_manager.create_custom_profile(profile_name, modifications=new_config):
                    print(f"✅ Created custom profile: {profile_name}")
                    self.current_settings['vad_profile'] = profile_name
                else:
                    print("❌ Failed to create custom profile")
        else:
            print("❌ VAD manager not available")
    
    def _view_performance(self):
        """View performance analytics"""
        print("\n📊 Performance Analytics")
        
        if self.vad_manager:
            # Show profile performance
            analysis = self.vad_manager.analyze_profile_performance()
            
            print(f"Current Profile: {analysis.get('profile_name', 'unknown')}")
            print(f"Performance Score: {analysis.get('performance_score', 0):.1%}")
            
            # Show recent statistics
            stats = analysis.get('recent_statistics', {})
            if stats:
                print("\nRecent Performance (24h):")
                for metric, data in stats.items():
                    if data.get('status') != 'no_data':
                        avg_val = data.get('average', 0)
                        print(f"  {metric}: {avg_val:.2f} (avg)")
            else:
                print("  No performance data available")
            
            # Show recommendations
            recommendations = analysis.get('recommendations', [])
            if recommendations:
                print("\nRecommendations:")
                for rec in recommendations:
                    print(f"  💡 {rec}")
        else:
            print("❌ VAD manager not available")
    
    def _export_import_profiles(self):
        """Handle profile import/export"""
        print("\n📁 Profile Management")
        print("1. Export current profile")
        print("2. Import profile from file")
        print("3. Delete user profile")
        
        try:
            choice = input("Choose option (1-3): ").strip()
            
            if choice == '1':
                filename = input("Export filename (e.g., my_profile.json): ").strip()
                if filename and self.vad_manager:
                    active_profile = self.vad_manager.active_profile
                    if self.vad_manager.export_profile(active_profile, filename):
                        print(f"✅ Profile exported to {filename}")
                    else:
                        print("❌ Export failed")
                        
            elif choice == '2':
                filename = input("Import filename: ").strip()
                if filename and os.path.exists(filename) and self.vad_manager:
                    new_name = input("New profile name (optional): ").strip() or None
                    if self.vad_manager.import_profile(filename, new_name):
                        print("✅ Profile imported successfully")
                    else:
                        print("❌ Import failed")
                        
            elif choice == '3':
                if self.vad_manager:
                    profiles = self.vad_manager.list_profiles()
                    user_profiles = [name for name, info in profiles['profiles'].items() 
                                   if info['type'] == 'user']
                    
                    if user_profiles:
                        print("User profiles:")
                        for i, name in enumerate(user_profiles, 1):
                            print(f"  {i}. {name}")
                        
                        try:
                            idx = int(input(f"Delete which profile (1-{len(user_profiles)}): ")) - 1
                            if 0 <= idx < len(user_profiles):
                                profile_name = user_profiles[idx]
                                confirm = input(f"Delete '{profile_name}'? (y/N): ").strip().lower()
                                if confirm == 'y':
                                    if self.vad_manager.delete_user_profile(profile_name):
                                        print(f"✅ Deleted profile: {profile_name}")
                                    else:
                                        print("❌ Deletion failed")
                        except ValueError:
                            print("❌ Invalid selection")
                    else:
                        print("No user profiles to delete")
        
        except Exception as e:
            print(f"❌ Error: {e}")


class PauseGuidanceSystem:
    """Provides guidance for optimal pause duration"""
    
    def __init__(self):
        self.context_guidance = {
            ContextType.CODING: {
                "optimal_pause": 2.5,
                "tips": [
                    "Take longer pauses when thinking through logic",
                    "Brief pauses for variable names are normal",
                    "Extended pauses for debugging are expected"
                ]
            },
            ContextType.WRITING: {
                "optimal_pause": 1.8,
                "tips": [
                    "Natural sentence breaks improve flow",
                    "Longer pauses for creative thinking",
                    "Short pauses for word selection"
                ]
            },
            ContextType.CHAT: {
                "optimal_pause": 1.0,
                "tips": [
                    "Keep pauses natural and conversational",
                    "Brief thinking pauses are normal",
                    "Longer pauses may seem awkward"
                ]
            },
            ContextType.PRESENTATION: {
                "optimal_pause": 2.0,
                "tips": [
                    "Strategic pauses for emphasis",
                    "Allow time for audience processing",
                    "Longer pauses between topics"
                ]
            }
        }
    
    def get_guidance(self, context: ContextType) -> Dict[str, Any]:
        """Get pause guidance for specific context"""
        return self.context_guidance.get(context, self.context_guidance[ContextType.CHAT])
    
    def analyze_user_patterns(self, pause_events: List[PauseEvent]) -> Dict[str, Any]:
        """Analyze user's pause patterns and provide feedback"""
        if not pause_events:
            return {"status": "no_data"}
        
        # Group by context
        context_groups = {}
        for event in pause_events:
            context = event.context
            if context not in context_groups:
                context_groups[context] = []
            context_groups[context].append(event)
        
        analysis = {}
        for context, events in context_groups.items():
            durations = [e.duration for e in events]
            optimal = self.context_guidance.get(context, {}).get("optimal_pause", 1.5)
            
            avg_duration = sum(durations) / len(durations)
            deviation = abs(avg_duration - optimal) / optimal
            
            analysis[context.value] = {
                "average_duration": avg_duration,
                "optimal_duration": optimal,
                "deviation_percent": deviation * 100,
                "sample_size": len(events),
                "recommendation": self._get_recommendation(deviation, optimal, avg_duration)
            }
        
        return analysis
    
    def _get_recommendation(self, deviation: float, optimal: float, actual: float) -> str:
        """Generate recommendation based on deviation from optimal"""
        if deviation < 0.2:
            return "Your pause timing is excellent!"
        elif actual > optimal:
            if deviation > 0.5:
                return "Consider shortening pauses for better flow"
            else:
                return "Slightly long pauses, but still natural"
        else:
            if deviation > 0.5:
                return "Try allowing slightly longer pauses"
            else:
                return "Pauses are a bit quick but acceptable"


# Factory functions for easy integration
def create_pause_visualization(config: PauseVisualizationConfig = None) -> PauseVisualization:
    """Create pause visualization system"""
    return PauseVisualization(config)

def create_interactive_config(vad_manager=None) -> InteractivePauseConfig:
    """Create interactive configuration interface"""
    return InteractivePauseConfig(vad_manager)

def create_guidance_system() -> PauseGuidanceSystem:
    """Create pause guidance system"""
    return PauseGuidanceSystem()