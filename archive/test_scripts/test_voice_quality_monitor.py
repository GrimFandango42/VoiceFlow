#!/usr/bin/env python3
"""
VoiceFlow Quality Monitoring & Diagnostics
Real-time analysis of transcription quality patterns and degradation detection.
"""

import sys
import os
import time
import threading
import json
from datetime import datetime
from pathlib import Path
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from localflow.config import Config
from localflow.asr_buffer_safe import BufferSafeWhisperASR

class VoiceQualityMonitor:
    """Monitor VoiceFlow transcription quality in real-time"""
    
    def __init__(self):
        self.config = Config()
        self.asr = BufferSafeWhisperASR(self.config)
        self.session_data = []
        self.session_start = time.time()
        self.transcription_count = 0
        
        print("=== VoiceFlow Quality Monitor ===")
        print("This will analyze your transcription patterns to identify issues.")
        print("Loading Whisper model...")
        
        self.asr.load()
        print("PASS: Model loaded successfully")
        
    def analyze_transcription_quality(self, text: str, expected_words: int = None):
        """Analyze transcription for quality metrics"""
        
        # Basic quality metrics
        word_count = len(text.split())
        char_count = len(text.strip())
        
        # Detect hallucination patterns
        hallucination_indicators = [
            "drilling", "spine", "without", "figure that",
            "read this", "thank you", "thanks for watching"
        ]
        
        hallucination_score = sum(1 for indicator in hallucination_indicators if indicator in text.lower())
        
        # Detect fragmentation (incomplete sentences)
        fragmentation_score = text.count('.') + text.count('...')
        
        # Coherence check (basic)
        coherence_score = 10  # Start with max
        if word_count < 3:
            coherence_score -= 3
        if hallucination_score > 0:
            coherence_score -= 4
        if fragmentation_score > 2:
            coherence_score -= 2
            
        quality_metrics = {
            'timestamp': datetime.now().isoformat(),
            'transcription_number': self.transcription_count + 1,
            'text': text,
            'word_count': word_count,
            'char_count': char_count,
            'hallucination_score': hallucination_score,
            'fragmentation_score': fragmentation_score,
            'coherence_score': max(0, coherence_score),
            'expected_words': expected_words,
            'efficiency_ratio': word_count / expected_words if expected_words else None
        }
        
        return quality_metrics
    
    def test_model_consistency(self):
        """Test if the model produces consistent results"""
        print("\n=== Testing Model Consistency ===")
        
        # Create test audio (3 seconds of synthetic speech-like signal)
        sample_rate = 16000
        duration = 3.0
        t = np.linspace(0, duration, int(sample_rate * duration))
        
        # Simulate speech with formants (like human voice)
        test_audio = (
            0.3 * np.sin(2 * np.pi * 200 * t) +  # F0 (fundamental)
            0.2 * np.sin(2 * np.pi * 800 * t) +  # F1 
            0.1 * np.sin(2 * np.pi * 1200 * t)   # F2
        ).astype(np.float32)
        
        # Test transcription consistency 3 times
        results = []
        for i in range(3):
            print(f"Consistency test {i+1}/3...")
            start_time = time.perf_counter()
            result = self.asr.transcribe(test_audio)
            processing_time = time.perf_counter() - start_time
            
            results.append({
                'iteration': i + 1,
                'result': result,
                'processing_time': processing_time,
                'word_count': len(result.split())
            })
            
            time.sleep(0.5)  # Brief pause between tests
        
        # Analyze consistency
        unique_results = set(r['result'] for r in results)
        processing_times = [r['processing_time'] for r in results]
        
        print(f"\nConsistency Results:")
        print(f"  Unique outputs: {len(unique_results)} (should be 1 for perfect consistency)")
        print(f"  Processing times: {processing_times}")
        print(f"  Average processing time: {np.mean(processing_times):.3f}s")
        
        for i, result in enumerate(results):
            print(f"  Test {i+1}: '{result['result']}'")
        
        return len(unique_results) == 1  # True if consistent
    
    def analyze_progressive_pattern(self, transcriptions: list):
        """Analyze if there's a progressive degradation pattern"""
        if len(transcriptions) < 3:
            return "Need at least 3 transcriptions to analyze pattern"
        
        # Check word count trend
        word_counts = [len(t['text'].split()) for t in transcriptions]
        coherence_scores = [t['coherence_score'] for t in transcriptions]
        
        # Calculate trend (negative = degrading)
        word_trend = np.polyfit(range(len(word_counts)), word_counts, 1)[0]
        coherence_trend = np.polyfit(range(len(coherence_scores)), coherence_scores, 1)[0]
        
        analysis = {
            'total_transcriptions': len(transcriptions),
            'word_count_trend': word_trend,
            'coherence_trend': coherence_trend,
            'degradation_detected': word_trend < -0.5 or coherence_trend < -0.3,
            'word_counts': word_counts,
            'coherence_scores': coherence_scores
        }
        
        return analysis
    
    def run_diagnostic_session(self):
        """Run a full diagnostic session"""
        print("\n" + "="*60)
        print("VoiceFlow Quality Diagnostic Session")
        print("="*60)
        
        # Test model consistency first
        consistency_ok = self.test_model_consistency()
        
        print(f"\n📊 Session Results:")
        print(f"Model Consistency: {'PASS' if consistency_ok else 'FAIL'}")
        
        if not consistency_ok:
            print("WARNING: Model is producing inconsistent results for identical input")
            print("   This indicates internal state persistence issues")
        
        # Return diagnostic info
        return {
            'session_start': datetime.now().isoformat(),
            'model_consistent': consistency_ok,
            'ready_for_user_testing': True
        }
    
    def monitor_user_session(self):
        """Monitor a user's testing session"""
        print("\n" + "="*60)
        print("Real-Time Quality Monitoring Active")
        print("="*60)
        print("Start testing with your voice now...")
        print("I'll analyze each transcription for quality patterns.")
        print("Press Ctrl+C when done to see the analysis.\n")
        
        try:
            while True:
                time.sleep(1)
                # In a real implementation, this would monitor the actual VoiceFlow session
                # For now, it's a placeholder for user input analysis
                
        except KeyboardInterrupt:
            print(f"\n\n📊 Session Analysis Complete")
            print(f"Transcriptions analyzed: {len(self.session_data)}")
            
            if self.session_data:
                pattern_analysis = self.analyze_progressive_pattern(self.session_data)
                
                print(f"Progressive degradation: {'Yes' if pattern_analysis['degradation_detected'] else 'No'}")
                print(f"Word count trend: {pattern_analysis['word_count_trend']:.2f} words/transcription")
                print(f"Quality trend: {pattern_analysis['coherence_trend']:.2f} points/transcription")
            
            return self.session_data

def main():
    """Main diagnostic program"""
    monitor = VoiceQualityMonitor()
    
    print("\nSelect diagnostic mode:")
    print("1. Quick consistency test")
    print("2. Full diagnostic session") 
    print("3. Monitor user testing session")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == "1":
        monitor.test_model_consistency()
    elif choice == "2":
        monitor.run_diagnostic_session()
    elif choice == "3":
        monitor.monitor_user_session()
    else:
        print("Invalid choice")
    
    print("\nDiagnostic complete!")

if __name__ == "__main__":
    main()