#!/usr/bin/env python3
"""
VoiceFlow Performance Benchmark
Compare original vs optimized performance
"""

import time
import tempfile
import wave
import numpy as np
from faster_whisper import WhisperModel
import os

def create_test_audio(duration_seconds=2.0, sample_rate=16000):
    """Create test audio with speech-like characteristics"""
    # Generate audio with varying amplitude to simulate speech
    t = np.linspace(0, duration_seconds, int(duration_seconds * sample_rate))
    
    # Create speech-like signal with multiple frequencies
    signal = (
        0.3 * np.sin(2 * np.pi * 200 * t) +  # Low frequency
        0.2 * np.sin(2 * np.pi * 800 * t) +  # Mid frequency  
        0.1 * np.sin(2 * np.pi * 1500 * t)   # High frequency
    )
    
    # Add envelope to make it more speech-like
    envelope = np.exp(-t * 0.5) * (1 + 0.5 * np.sin(2 * np.pi * 3 * t))
    signal = signal * envelope
    
    # Convert to int16
    audio_data = (signal * 32767).astype(np.int16)
    
    return audio_data

def save_audio_to_file(audio_data, filename, sample_rate=16000):
    """Save audio data to WAV file"""
    with wave.open(filename, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(audio_data.tobytes())

def benchmark_model_config(config, test_audio_file, num_iterations=5):
    """Benchmark a specific model configuration"""
    print(f"\nBenchmarking: {config['model']} on {config['device']} ({config['compute_type']})")
    
    try:
        # Load model
        load_start = time.time()
        model = WhisperModel(
            config['model'],
            device=config['device'],
            compute_type=config['compute_type']
        )
        load_time = time.time() - load_start
        print(f"  Model load time: {load_time:.3f}s")
        
        # Warmup run
        print("  Warming up...")
        segments, _ = model.transcribe(test_audio_file, language="en")
        list(segments)  # Consume the generator
        
        # Benchmark runs
        times = []
        for i in range(num_iterations):
            start_time = time.time()
            
            segments, info = model.transcribe(
                test_audio_file,
                language="en",
                vad_filter=True,
                vad_parameters=dict(min_silence_duration_ms=500)
            )
            
            # Consume all segments
            text = " ".join([segment.text for segment in segments])
            
            end_time = time.time()
            processing_time = end_time - start_time
            times.append(processing_time)
            
            print(f"  Run {i+1}: {processing_time:.3f}s")
        
        # Calculate statistics
        avg_time = np.mean(times)
        min_time = np.min(times)
        max_time = np.max(times)
        std_time = np.std(times)
        
        return {
            'config': config,
            'load_time': load_time,
            'avg_time': avg_time,
            'min_time': min_time,
            'max_time': max_time,
            'std_time': std_time,
            'text_sample': text[:100] + "..." if len(text) > 100 else text
        }
        
    except Exception as e:
        print(f"  Error: {e}")
        return None

def benchmark_optimization_techniques():
    """Benchmark different optimization techniques"""
    print("\n" + "="*60)
    print("VoiceFlow Performance Benchmark")
    print("="*60)
    
    # Create test audio
    print("Creating test audio...")
    test_audio = create_test_audio(duration_seconds=3.0)
    
    with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as f:
        test_file = f.name
    
    save_audio_to_file(test_audio, test_file)
    print(f"Test audio created: {os.path.getsize(test_file)} bytes")
    
    # Define configurations to test
    configs = [
        # Speed-focused configurations
        {"model": "tiny", "device": "cpu", "compute_type": "int8"},
        {"model": "base", "device": "cpu", "compute_type": "int8"},
        {"model": "small", "device": "cpu", "compute_type": "int8"},
    ]
    
    # Add CUDA configs if available
    try:
        import torch
        if torch.cuda.is_available():
            configs.extend([
                {"model": "tiny", "device": "cuda", "compute_type": "int8"},
                {"model": "tiny", "device": "cuda", "compute_type": "float16"},
                {"model": "base", "device": "cuda", "compute_type": "int8"},
                {"model": "base", "device": "cuda", "compute_type": "float16"},
            ])
    except ImportError:
        print("PyTorch not available, skipping CUDA configs")
    
    # Run benchmarks
    results = []
    for config in configs:
        result = benchmark_model_config(config, test_file)
        if result:
            results.append(result)
    
    # Cleanup
    os.unlink(test_file)
    
    # Display results
    print("\n" + "="*60)
    print("PERFORMANCE RESULTS")
    print("="*60)
    print(f"{'Model':<8} {'Device':<6} {'Compute':<8} {'Avg Time':<10} {'Min Time':<10} {'Speedup':<8}")
    print("-" * 60)
    
    fastest_time = min(r['min_time'] for r in results) if results else 1
    
    for result in sorted(results, key=lambda x: x['avg_time']):
        config = result['config']
        speedup = fastest_time / result['min_time']
        
        print(f"{config['model']:<8} {config['device']:<6} {config['compute_type']:<8} "
              f"{result['avg_time']:.3f}s    {result['min_time']:.3f}s    {speedup:.1f}x")
    
    # Recommendations
    print("\n" + "="*60)
    print("RECOMMENDATIONS")
    print("="*60)
    
    if results:
        fastest = min(results, key=lambda x: x['min_time'])
        balanced = min([r for r in results if r['config']['model'] == 'base'], 
                      key=lambda x: x['min_time'], default=fastest)
        
        print(f"🚀 FASTEST: {fastest['config']['model']} on {fastest['config']['device']} "
              f"({fastest['min_time']:.3f}s)")
        
        if balanced != fastest:
            print(f"⚖️  BALANCED: {balanced['config']['model']} on {balanced['config']['device']} "
                  f"({balanced['min_time']:.3f}s)")
        
        # Performance targets
        print(f"\nPerformance Targets:")
        print(f"- Real-time factor: {3.0/fastest['min_time']:.1f}x (target: >10x)")
        print(f"- Latency for 3s audio: {fastest['min_time']*1000:.0f}ms (target: <500ms)")
        
        if fastest['min_time'] < 0.5:
            print("✅ EXCELLENT: Sub-500ms latency achieved!")
        elif fastest['min_time'] < 1.0:
            print("✅ GOOD: Sub-1000ms latency achieved")
        else:
            print("⚠️  NEEDS OPTIMIZATION: >1000ms latency")

def benchmark_vad_parameters():
    """Benchmark different VAD parameter configurations"""
    print("\n" + "="*60)
    print("VAD PARAMETER OPTIMIZATION")
    print("="*60)
    
    # Create test audio
    test_audio = create_test_audio(duration_seconds=2.0)
    
    with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as f:
        test_file = f.name
    
    save_audio_to_file(test_audio, test_file)
    
    # Initialize model (use fastest config)
    model = WhisperModel("tiny", device="cpu", compute_type="int8")
    
    # VAD parameter sets to test
    vad_configs = [
        {"name": "Conservative", "params": {"min_silence_duration_ms": 500, "speech_pad_ms": 400}},
        {"name": "Balanced", "params": {"min_silence_duration_ms": 300, "speech_pad_ms": 200}},
        {"name": "Aggressive", "params": {"min_silence_duration_ms": 200, "speech_pad_ms": 100}},
        {"name": "Fast", "params": {"min_silence_duration_ms": 100, "speech_pad_ms": 50}},
    ]
    
    print(f"{'Config':<12} {'Time (ms)':<10} {'Quality':<8}")
    print("-" * 32)
    
    for vad_config in vad_configs:
        start_time = time.time()
        
        segments, info = model.transcribe(
            test_file,
            language="en",
            vad_filter=True,
            vad_parameters=vad_config["params"]
        )
        
        text = " ".join([segment.text for segment in segments])
        processing_time = (time.time() - start_time) * 1000
        
        quality = "Good" if len(text) > 10 else "Poor"
        
        print(f"{vad_config['name']:<12} {processing_time:<10.0f} {quality:<8}")
    
    # Cleanup
    os.unlink(test_file)

if __name__ == "__main__":
    print("VoiceFlow Performance Benchmark Suite")
    print("This will test different model configurations for optimal speed.")
    print()
    
    choice = input("Run benchmark? (y/n): ").lower().strip()
    if choice == 'y':
        benchmark_optimization_techniques()
        benchmark_vad_parameters()
        
        print("\n" + "="*60)
        print("Benchmark complete! Use results to optimize VoiceFlow configuration.")
        print("="*60)
    else:
        print("Benchmark cancelled.")