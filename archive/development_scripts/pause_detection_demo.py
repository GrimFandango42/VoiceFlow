#!/usr/bin/env python3
"""
VoiceFlow Pause Detection Integration Demo
=========================================

Comprehensive demonstration of the intelligent pause detection system
showcasing all features and capabilities.

This demo shows:
- Intelligent pause classification
- Context-aware VAD adaptation  
- Session state management
- Visual feedback and monitoring
- Performance analytics
- User customization options
"""

import asyncio
import time
import threading
from typing import Dict, Any, Optional
import sys
import os

# Import all pause detection components
try:
    from pause_analyzer import create_pause_analyzer, PauseType, ContextType
    from context_manager import create_context_manager, InterruptionType
    from vad_profiles import create_vad_profile_manager
    from pause_ui import create_pause_visualization, create_interactive_config, create_guidance_system
    
    # Try to import core VoiceFlow for integration
    try:
        from core.voiceflow_core import VoiceFlowEngine
        CORE_AVAILABLE = True
    except ImportError:
        try:
            from voiceflow_personal import PersonalVoiceFlow
            PERSONAL_AVAILABLE = True
            CORE_AVAILABLE = False
        except ImportError:
            PERSONAL_AVAILABLE = False
            CORE_AVAILABLE = False
    
    COMPONENTS_AVAILABLE = True
    
except ImportError as e:
    print(f"❌ Missing pause detection components: {e}")
    COMPONENTS_AVAILABLE = False
    CORE_AVAILABLE = False
    PERSONAL_AVAILABLE = False


class PauseDetectionDemo:
    """Comprehensive demo of pause detection capabilities"""
    
    def __init__(self):
        if not COMPONENTS_AVAILABLE:
            raise RuntimeError("Pause detection components not available")
        
        # Initialize components
        self.pause_classifier, self.vad_manager = create_pause_analyzer("demo_user")
        self.context_manager = create_context_manager(max_context_size=100)
        self.profile_manager = create_vad_profile_manager("demo_user")
        self.visualization = create_pause_visualization()
        self.guidance_system = create_guidance_system()
        
        # Demo state
        self.current_context = ContextType.CHAT
        self.demo_running = False
        
        print("🚀 VoiceFlow Pause Detection Demo Initialized")
        print("=" * 60)
    
    async def run_comprehensive_demo(self):
        """Run comprehensive demonstration of all features"""
        print("🎯 Starting Comprehensive Pause Detection Demo")
        print("\nThis demo will showcase:")
        print("  • Intelligent pause classification")
        print("  • Context-aware adaptation")
        print("  • Session state management")  
        print("  • Performance monitoring")
        print("  • User customization")
        print("\nPress Enter to continue...")
        input()
        
        try:
            # Demo 1: Basic pause classification
            await self._demo_basic_classification()
            
            # Demo 2: Context-aware adaptation
            await self._demo_context_adaptation()
            
            # Demo 3: Interruption handling
            await self._demo_interruption_handling()
            
            # Demo 4: VAD profile optimization
            await self._demo_vad_optimization()
            
            # Demo 5: Performance analytics
            await self._demo_performance_analytics()
            
            # Demo 6: User guidance
            await self._demo_user_guidance()
            
            print("\n🎉 Demo completed successfully!")
            print("=" * 60)
            
        except KeyboardInterrupt:
            print("\n⏹️  Demo interrupted by user")
        except Exception as e:
            print(f"\n❌ Demo error: {e}")
        finally:
            self._cleanup()
    
    async def _demo_basic_classification(self):
        """Demonstrate basic pause classification"""
        print("\n" + "="*60)
        print("📊 DEMO 1: Basic Pause Classification")
        print("="*60)
        
        print("Testing pause classification with different durations...")
        
        test_cases = [
            (0.3, "Quick breath pause"),
            (1.2, "Thinking pause"),
            (2.5, "Sentence break"),
            (4.0, "Topic transition"),
            (6.5, "Intentional stop")
        ]
        
        for duration, description in test_cases:
            pause_event = self.pause_classifier.classify_pause(
                duration=duration,
                speech_before="Previous speech segment",
                speech_after="Following speech segment",
                vad_sources=['silero', 'webrtc']
            )
            
            print(f"  📏 {duration}s pause → {pause_event.classification.value}")
            print(f"     {description} (confidence: {pause_event.confidence:.1%})")
            
            # Add to context manager
            self.context_manager.add_context(
                f"Pause test: {duration}s",
                speaker="system",
                context_type="metadata"
            )
            
            await asyncio.sleep(0.5)  # Brief pause for visibility
        
        # Show learned patterns
        stats = self.pause_classifier.get_pause_statistics()
        if stats.get("pattern_learned"):
            print(f"\n🧠 Learning Progress:")
            print(f"  • Session pauses: {stats['session_pauses']}")
            print(f"  • Average confidence: {stats['avg_confidence']:.1%}")
        
        print("\nPress Enter to continue to next demo...")
        input()
    
    async def _demo_context_adaptation(self):
        """Demonstrate context-aware adaptation"""
        print("\n" + "="*60)
        print("🎯 DEMO 2: Context-Aware Adaptation")
        print("="*60)
        
        contexts = [ContextType.CHAT, ContextType.CODING, ContextType.PRESENTATION]
        
        for context in contexts:
            print(f"\n🎪 Testing context: {context.value}")
            
            # Set context
            self.pause_classifier.set_context(context)
            self.current_context = context
            
            # Get adaptive VAD config
            vad_config = self.vad_manager.get_config_for_context(context)
            
            print(f"  Adaptive VAD settings:")
            print(f"    • Silence duration: {vad_config['post_speech_silence_duration']:.1f}s")
            print(f"    • Silero sensitivity: {vad_config['silero_sensitivity']:.2f}")
            print(f"    • Min recording: {vad_config['min_length_of_recording']:.2f}s")
            
            # Test same pause in different contexts
            test_duration = 2.0
            pause_event = self.pause_classifier.classify_pause(
                duration=test_duration,
                speech_before=f"Context-specific speech for {context.value}",
                speech_after="Continuation in same context"
            )
            
            print(f"  📊 {test_duration}s pause classified as: {pause_event.classification.value}")
            print(f"     Context-aware confidence: {pause_event.confidence:.1%}")
            
            await asyncio.sleep(1)
        
        print("\nPress Enter to continue to next demo...")
        input()
    
    async def _demo_interruption_handling(self):
        """Demonstrate interruption and recovery handling"""
        print("\n" + "="*60)
        print("⏸️  DEMO 3: Interruption Handling & Recovery")
        print("="*60)
        
        # Add some conversation context
        conversation = [
            "We were discussing the new project requirements",
            "The deadline is set for next Friday",
            "I think we should prioritize the user interface components",
            "The backend API integration can come later"
        ]
        
        print("Building conversation context...")
        for i, text in enumerate(conversation):
            self.context_manager.add_context(text, importance=1.0)
            print(f"  {i+1}. {text}")
            await asyncio.sleep(0.3)
        
        print(f"\n📞 Simulating phone call interruption...")
        
        # Simulate interruption
        self.context_manager.handle_interruption_start(InterruptionType.PHONE_CALL)
        
        print("  ⏸️  Interruption started - context preserved")
        await asyncio.sleep(2)  # Simulate interruption duration
        
        # Resume after interruption
        print("📱 Phone call ended - resuming conversation...")
        recovery_info = self.context_manager.handle_interruption_end()
        
        print(f"  📊 Context preservation: {recovery_info['context_preservation_score']:.1%}")
        print(f"  💡 Suggested continuation: {recovery_info['suggested_continuation'][:80]}...")
        
        # Test continuation detection
        test_continuations = [
            "And furthermore, we need to consider the mobile version",
            "What time is the meeting tomorrow?",
            "Those API components we mentioned earlier"
        ]
        
        print(f"\n🔄 Testing continuation detection:")
        for continuation in test_continuations:
            result = self.context_manager.detect_continuation_intent(continuation)
            is_continuation = result.get('is_continuation', False)
            confidence = result.get('confidence', 0)
            
            print(f"  {'✅' if is_continuation else '❌'} \"{continuation[:40]}...\"")
            print(f"     Continuation confidence: {confidence:.1%}")
        
        print("\nPress Enter to continue to next demo...")
        input()
    
    async def _demo_vad_optimization(self):
        """Demonstrate VAD profile optimization"""
        print("\n" + "="*60)
        print("⚙️  DEMO 4: VAD Profile Optimization")
        print("="*60)
        
        # Show available profiles
        profiles = self.profile_manager.list_profiles()
        print("Available VAD profiles:")
        
        for name, info in profiles['profiles'].items():
            marker = " ✅" if info['is_active'] else ""
            print(f"  • {name} ({info['type']}){marker}")
            print(f"    {info['description']}")
        
        # Demonstrate profile switching
        print(f"\n🔄 Demonstrating profile adaptation...")
        
        test_profiles = ['conservative', 'balanced', 'aggressive']
        for profile_name in test_profiles:
            print(f"\n📐 Testing profile: {profile_name}")
            
            if self.profile_manager.set_active_profile(profile_name):
                config = self.profile_manager.get_profile_config(profile_name)
                
                print(f"  Settings:")
                print(f"    • Silence duration: {config['post_speech_silence_duration']:.1f}s")
                print(f"    • Silero sensitivity: {config['silero_sensitivity']:.2f}")
                print(f"    • Response threshold: {config.get('start_threshold', 0.3):.2f}")
                
                # Simulate performance data
                self.profile_manager.record_performance_data(
                    metric=self.profile_manager.PerformanceMetric.CUTOFF_RATE,
                    value=0.05 if profile_name == 'conservative' else 0.12,
                    context=profile_name
                )
        
        # Show performance comparison
        print(f"\n📊 Simulated performance comparison:")
        for profile_name in test_profiles:
            cutoff_rate = 0.05 if profile_name == 'conservative' else 0.15 if profile_name == 'aggressive' else 0.08
            print(f"  {profile_name}: {cutoff_rate:.1%} cutoff rate")
        
        print("\nPress Enter to continue to next demo...")
        input()
    
    async def _demo_performance_analytics(self):
        """Demonstrate performance analytics"""
        print("\n" + "="*60)
        print("📈 DEMO 5: Performance Analytics")
        print("="*60)
        
        # Generate some sample performance data
        print("Generating performance data...")
        
        import random
        metrics = [
            self.profile_manager.PerformanceMetric.CUTOFF_RATE,
            self.profile_manager.PerformanceMetric.FALSE_POSITIVE_RATE,
            self.profile_manager.PerformanceMetric.RESPONSE_TIME,
            self.profile_manager.PerformanceMetric.CONTINUATION_ACCURACY
        ]
        
        for i in range(20):
            for metric in metrics:
                # Generate realistic values based on metric type
                if metric == self.profile_manager.PerformanceMetric.CUTOFF_RATE:
                    value = random.uniform(0.02, 0.15)
                elif metric == self.profile_manager.PerformanceMetric.FALSE_POSITIVE_RATE:
                    value = random.uniform(0.05, 0.20)
                elif metric == self.profile_manager.PerformanceMetric.RESPONSE_TIME:
                    value = random.uniform(0.3, 1.2)
                else:  # CONTINUATION_ACCURACY
                    value = random.uniform(0.75, 0.95)
                
                self.profile_manager.record_performance_data(
                    metric=metric,
                    value=value,
                    context="demo_session"
                )
        
        # Analyze performance
        analysis = self.profile_manager.analyze_profile_performance()
        
        print(f"\n📊 Performance Analysis:")
        print(f"  Profile: {analysis['profile_name']}")
        print(f"  Overall Score: {analysis['performance_score']:.1%}")
        
        stats = analysis.get('recent_statistics', {})
        if stats:
            print(f"\n📈 Recent Statistics:")
            for metric_name, data in stats.items():
                if data.get('status') != 'no_data':
                    avg_val = data.get('average', 0)
                    print(f"  • {metric_name}: {avg_val:.3f} average")
        
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            print(f"\n💡 Recommendations:")
            for rec in recommendations:
                print(f"  • {rec}")
        
        print("\nPress Enter to continue to next demo...")
        input()
    
    async def _demo_user_guidance(self):
        """Demonstrate user guidance system"""
        print("\n" + "="*60)
        print("🎯 DEMO 6: User Guidance System")
        print("="*60)
        
        # Get guidance for different contexts
        contexts = [ContextType.CHAT, ContextType.CODING, ContextType.PRESENTATION]
        
        for context in contexts:
            guidance = self.guidance_system.get_guidance(context)
            
            print(f"\n🎪 Guidance for {context.value}:")
            print(f"  Optimal pause: {guidance['optimal_pause']:.1f}s")
            print(f"  Tips:")
            for tip in guidance['tips']:
                print(f"    • {tip}")
        
        # Simulate user pattern analysis
        print(f"\n🔍 Analyzing simulated user patterns...")
        
        # Create sample pause events for analysis
        from pause_analyzer import PauseEvent
        import random
        
        sample_events = []
        for context in contexts:
            for _ in range(10):
                # Generate realistic pause durations for each context
                if context == ContextType.CODING:
                    duration = random.uniform(1.5, 4.0)
                elif context == ContextType.CHAT:
                    duration = random.uniform(0.5, 2.0)
                else:  # PRESENTATION
                    duration = random.uniform(1.0, 3.0)
                
                event = PauseEvent(
                    start_time=time.time(),
                    duration=duration,
                    classification=PauseType.THINKING_PAUSE,
                    confidence=random.uniform(0.6, 0.9),
                    context=context
                )
                sample_events.append(event)
        
        # Analyze patterns
        pattern_analysis = self.guidance_system.analyze_user_patterns(sample_events)
        
        print(f"\n📊 Pattern Analysis Results:")
        for context_name, analysis in pattern_analysis.items():
            if isinstance(analysis, dict) and 'average_duration' in analysis:
                print(f"  {context_name}:")
                print(f"    • Average duration: {analysis['average_duration']:.2f}s")
                print(f"    • Optimal duration: {analysis['optimal_duration']:.2f}s")
                print(f"    • Deviation: {analysis['deviation_percent']:.1f}%")
                print(f"    • Recommendation: {analysis['recommendation']}")
        
        print("\nPress Enter to finish demo...")
        input()
    
    def _cleanup(self):
        """Clean up demo resources"""
        try:
            if hasattr(self, 'context_manager'):
                self.context_manager.cleanup()
            if hasattr(self, 'visualization'):
                self.visualization.stop()
            print("🧹 Demo cleanup completed")
        except Exception as e:
            print(f"⚠️  Cleanup warning: {e}")
    
    def run_interactive_demo(self):
        """Run interactive demo with user choices"""
        print("\n🎮 Interactive Pause Detection Demo")
        print("=" * 60)
        
        while True:
            print("\nChoose a demo:")
            print("1. 📊 Basic pause classification")
            print("2. 🎯 Context adaptation")
            print("3. ⏸️  Interruption handling")
            print("4. ⚙️  VAD optimization")
            print("5. 📈 Performance analytics")
            print("6. 🎯 User guidance")
            print("7. 🎛️  Interactive configuration")
            print("8. 🧪 Run comprehensive test")
            print("q. Quit")
            
            choice = input("\nEnter your choice: ").strip().lower()
            
            try:
                if choice == 'q':
                    break
                elif choice == '1':
                    asyncio.run(self._demo_basic_classification())
                elif choice == '2':
                    asyncio.run(self._demo_context_adaptation())
                elif choice == '3':
                    asyncio.run(self._demo_interruption_handling())
                elif choice == '4':
                    asyncio.run(self._demo_vad_optimization())
                elif choice == '5':
                    asyncio.run(self._demo_performance_analytics())
                elif choice == '6':
                    asyncio.run(self._demo_user_guidance())
                elif choice == '7':
                    config_interface = create_interactive_config(self.profile_manager)
                    config_interface.show_configuration_menu()
                elif choice == '8':
                    asyncio.run(self.run_comprehensive_demo())
                else:
                    print("❌ Invalid choice")
            
            except KeyboardInterrupt:
                print("\n⏹️  Demo interrupted")
                break
            except Exception as e:
                print(f"❌ Demo error: {e}")
        
        self._cleanup()


def demonstrate_voiceflow_integration():
    """Demonstrate integration with main VoiceFlow systems"""
    print("\n🔗 VoiceFlow Integration Examples")
    print("=" * 60)
    
    if CORE_AVAILABLE:
        print("✅ VoiceFlow Core integration available")
        print("   Example usage:")
        print("   ```python")
        print("   from core.voiceflow_core import create_engine")
        print("   ")
        print("   # Create engine with pause detection")
        print("   config = {")
        print("       'enable_pause_detection': True,")
        print("       'context_type': 'coding',")
        print("       'user_id': 'your_user_id'")
        print("   }")
        print("   engine = create_engine(config)")
        print("   ")
        print("   # Set context for adaptive behavior")
        print("   engine.set_context_type('presentation')")
        print("   ")
        print("   # Handle interruptions")
        print("   engine.handle_interruption('phone_call')")
        print("   recovery = engine.resume_after_interruption()")
        print("   ```")
    
    if PERSONAL_AVAILABLE:
        print("✅ VoiceFlow Personal integration available")
        print("   Example usage:")
        print("   ```python")
        print("   from voiceflow_personal import PersonalVoiceFlow")
        print("   ")
        print("   # Create instance with pause detection")
        print("   voiceflow = PersonalVoiceFlow()")
        print("   ")
        print("   # Set context for optimal pause behavior")
        print("   voiceflow.set_context_type('writing')")
        print("   ")
        print("   # Get pause statistics")
        print("   stats = voiceflow.get_pause_statistics()")
        print("   ```")
    
    if not (CORE_AVAILABLE or PERSONAL_AVAILABLE):
        print("⚠️  No VoiceFlow integration available")
        print("   Install VoiceFlow core components to enable integration")


def main():
    """Main demo entry point"""
    print("🚀 VoiceFlow Pause Detection System Demo")
    print("=" * 60)
    
    if not COMPONENTS_AVAILABLE:
        print("❌ Pause detection components not available")
        print("   Please ensure all required modules are installed:")
        print("   • pause_analyzer.py")
        print("   • context_manager.py") 
        print("   • vad_profiles.py")
        print("   • pause_ui.py")
        return 1
    
    print("Available demos:")
    print("1. 🎮 Interactive demo (choose individual features)")
    print("2. 🎯 Comprehensive demo (all features)")
    print("3. 🔗 Integration examples")
    print("4. 🧪 Run test suite")
    
    try:
        choice = input("\nChoose demo type (1-4): ").strip()
        
        if choice == '1':
            demo = PauseDetectionDemo()
            demo.run_interactive_demo()
        elif choice == '2':
            demo = PauseDetectionDemo()
            asyncio.run(demo.run_comprehensive_demo())
        elif choice == '3':
            demonstrate_voiceflow_integration()
        elif choice == '4':
            # Run test suite
            try:
                from test_pause_detection import run_comprehensive_tests
                success = run_comprehensive_tests()
                return 0 if success else 1
            except ImportError:
                print("❌ Test suite not available")
                return 1
        else:
            print("❌ Invalid choice")
            return 1
        
        return 0
    
    except KeyboardInterrupt:
        print("\n👋 Demo terminated by user")
        return 0
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())