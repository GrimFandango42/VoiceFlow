# VoiceFlow Performance Optimization Plan

## Executive Summary

This comprehensive plan identifies key performance bottlenecks in VoiceFlow and provides actionable optimizations to significantly reduce transcription latency from the current ~2-3 seconds to under 1 second for typical use cases.

## Current Performance Analysis

### Identified Bottlenecks

1. **Audio Tail Buffer (0.8s)** - Fixed delay after key release
2. **File I/O Operations** - Temporary WAV file creation/deletion
3. **Model Loading** - No preloading or warmup
4. **Whisper Parameters** - Not optimized for speed
5. **AI Enhancement** - Synchronous Ollama API calls (3s timeout)
6. **Text Injection** - Sequential fallback methods

### Current Pipeline Timeline (Estimated)
- Recording: Variable (user controlled)
- Tail buffer wait: 800ms (fixed)
- File I/O: ~50-100ms
- Transcription: ~500-1500ms (depending on length)
- AI Enhancement: ~200-1000ms
- Text Injection: ~10-50ms
**Total: 1.5-3.5 seconds post-release**

## Optimization Strategy

### Phase 1: Quick Wins (Immediate Implementation)

#### 1. Dynamic Tail Buffer
Replace fixed 0.8s buffer with intelligent Voice Activity Detection (VAD):

```python
# Instead of fixed delay:
# threading.Timer(0.8, self.stop_recording).start()

# Implement VAD-based stopping:
class SmartRecordingBuffer:
    def __init__(self, silence_threshold=0.3, min_buffer=0.2):
        self.silence_threshold = silence_threshold
        self.min_buffer = min_buffer
        self.last_speech_time = time.time()
        
    def should_stop_recording(self, audio_chunk):
        if self.is_silence(audio_chunk):
            silence_duration = time.time() - self.last_speech_time
            return silence_duration >= self.silence_threshold
        else:
            self.last_speech_time = time.time()
            return False
```

**Expected Improvement**: 300-600ms reduction

#### 2. In-Memory Audio Processing
Eliminate temp file I/O:

```python
def process_audio_in_memory(self, audio_frames):
    # Convert frames directly to numpy array
    audio_data = np.frombuffer(b''.join(audio_frames), dtype=np.int16)
    audio_float = audio_data.astype(np.float32) / 32768.0
    
    # Direct transcription from numpy array
    segments, info = self.whisper_model.transcribe(
        audio_float,
        sampling_rate=16000,
        language="en",
        vad_filter=True
    )
```

**Expected Improvement**: 50-100ms reduction

#### 3. Optimize Whisper Parameters
Speed-optimized configuration:

```python
# Speed-optimized parameters
whisper_config = {
    "model_size": "tiny",  # Fastest model
    "device": "cuda" if cuda_available else "cpu",
    "compute_type": "int8",  # Fastest compute type
    "num_workers": 4,  # Parallel processing
    "beam_size": 1,  # Fastest (greedy search)
    "best_of": 1,  # No multiple attempts
    "temperature": 0,  # Deterministic (faster)
    "compression_ratio_threshold": None,  # Skip check
    "log_prob_threshold": None,  # Skip check
    "no_speech_threshold": 0.5,  # Balanced
    "condition_on_previous_text": False,  # Faster
    "initial_prompt": None,  # No context
    "prefix": None,  # No prefix
    "suppress_blank": True,
    "suppress_tokens": [-1],  # Minimal suppression
    "without_timestamps": True,  # Skip timestamps
    "max_initial_timestamp": None,
    "word_timestamps": False  # Skip word-level
}
```

**Expected Improvement**: 200-400ms reduction

### Phase 2: Architecture Improvements

#### 4. Model Preloading and Warmup
Initialize and warm up model at startup:

```python
def init_and_warmup_model(self):
    # Load model
    self.whisper_model = WhisperModel("tiny", device="cuda", compute_type="int8")
    
    # Warmup with dummy audio (1 second of silence)
    print("[Warmup] Preparing speech processor...")
    dummy_audio = np.zeros(16000, dtype=np.float32)
    
    # Run 3 warmup iterations
    for i in range(3):
        start = time.time()
        segments, _ = self.whisper_model.transcribe(
            dummy_audio,
            sampling_rate=16000,
            language="en"
        )
        print(f"[Warmup] Iteration {i+1}: {(time.time()-start)*1000:.0f}ms")
```

**Expected Improvement**: 100-300ms on first transcription

#### 5. Asynchronous AI Enhancement
Non-blocking enhancement with fallback:

```python
async def enhance_text_async(self, text, callback):
    # Immediately return basic formatted text
    basic_text = self._basic_format(text)
    callback(basic_text)  # Inject immediately
    
    # Enhance in background if AI available
    if self.ai_available:
        try:
            enhanced = await self._ai_enhance_async(text)
            if enhanced != basic_text:
                # Optional: Update with enhanced version
                self._update_last_transcription(enhanced)
        except:
            pass  # Silent fail, already injected basic
```

**Expected Improvement**: 200-1000ms perceived reduction

#### 6. Streaming Transcription
Process audio in chunks during recording:

```python
class StreamingTranscriber:
    def __init__(self, model, chunk_duration=1.0):
        self.model = model
        self.chunk_duration = chunk_duration
        self.buffer = []
        self.transcribed_text = []
        
    def add_audio(self, audio_chunk):
        self.buffer.extend(audio_chunk)
        
        # Process if we have enough audio
        if len(self.buffer) >= 16000 * self.chunk_duration:
            self._process_chunk()
    
    def _process_chunk(self):
        # Process buffered audio
        audio_data = np.array(self.buffer[:int(16000 * self.chunk_duration)])
        segments, _ = self.model.transcribe(audio_data, ...)
        
        # Add to results
        for segment in segments:
            self.transcribed_text.append(segment.text)
        
        # Keep overlap for context
        self.buffer = self.buffer[int(16000 * 0.5):]
```

**Expected Improvement**: Start getting results before recording ends

### Phase 3: Advanced Optimizations

#### 7. GPU Memory Optimization
Keep model in GPU memory:

```python
# Pin model to GPU memory
if torch.cuda.is_available():
    torch.cuda.set_per_process_memory_fraction(0.3)  # Limit GPU memory
    
    # Pre-allocate buffers
    self.gpu_audio_buffer = torch.zeros(
        (1, 480000),  # Max 30 seconds at 16kHz
        dtype=torch.float32,
        device='cuda'
    )
```

#### 8. Batched Processing
Process multiple requests efficiently:

```python
class BatchedTranscriber:
    def __init__(self, model, batch_size=4, max_wait=0.1):
        self.model = model
        self.batch_size = batch_size
        self.max_wait = max_wait
        self.queue = asyncio.Queue()
        
    async def process_batch(self):
        batch = []
        start_wait = time.time()
        
        while len(batch) < self.batch_size:
            try:
                timeout = self.max_wait - (time.time() - start_wait)
                if timeout <= 0:
                    break
                item = await asyncio.wait_for(
                    self.queue.get(), 
                    timeout=timeout
                )
                batch.append(item)
            except asyncio.TimeoutError:
                break
        
        if batch:
            # Process all items together
            results = self.model.transcribe_batch(batch)
            return results
```

#### 9. Caching Strategy
Cache common phrases and corrections:

```python
class TranscriptionCache:
    def __init__(self, max_size=1000):
        self.cache = {}  # audio_hash -> (text, enhanced_text)
        self.max_size = max_size
        
    def get_cached(self, audio_hash):
        return self.cache.get(audio_hash)
    
    def add_to_cache(self, audio_hash, text, enhanced_text):
        if len(self.cache) >= self.max_size:
            # LRU eviction
            oldest = min(self.cache.items(), key=lambda x: x[1]['timestamp'])
            del self.cache[oldest[0]]
        
        self.cache[audio_hash] = {
            'text': text,
            'enhanced_text': enhanced_text,
            'timestamp': time.time()
        }
```

### Phase 4: Faster-Whisper Specific Optimizations

#### 10. Optimal Model Selection
Choose model based on use case:

```python
MODEL_CONFIGS = {
    "ultra_fast": {
        "model": "tiny",
        "compute_type": "int8",
        "beam_size": 1,
        "best_of": 1
    },
    "balanced": {
        "model": "base", 
        "compute_type": "int8_float16",
        "beam_size": 3,
        "best_of": 2
    },
    "accurate": {
        "model": "small",
        "compute_type": "float16",
        "beam_size": 5,
        "best_of": 3
    }
}
```

#### 11. VAD Optimization
Fine-tune Voice Activity Detection:

```python
vad_parameters = {
    "threshold": 0.5,  # Speech probability threshold
    "min_speech_duration_ms": 250,  # Minimum speech chunk
    "max_speech_duration_s": None,  # No limit
    "min_silence_duration_ms": 300,  # Faster silence detection
    "window_size_samples": 512,  # Smaller window for responsiveness
    "speech_pad_ms": 100  # Minimal padding
}
```

## Implementation Priority

### Immediate (Week 1)
1. ✅ Dynamic tail buffer with VAD
2. ✅ In-memory audio processing  
3. ✅ Optimize Whisper parameters
4. ✅ Model preloading and warmup

### Short-term (Week 2-3)
5. ⏳ Asynchronous AI enhancement
6. ⏳ Basic streaming transcription
7. ⏳ GPU memory optimization

### Medium-term (Month 1-2)
8. ⏳ Batched processing
9. ⏳ Caching system
10. ⏳ Advanced VAD tuning

## Expected Performance Gains

### Current Performance
- Total latency: 1.5-3.5 seconds
- Transcription accuracy: ~95%
- GPU utilization: ~30%

### Optimized Performance (Phase 1)
- Total latency: 0.8-1.5 seconds (50% reduction)
- Transcription accuracy: ~93% (slight trade-off)
- GPU utilization: ~60%

### Target Performance (All Phases)
- Total latency: 0.3-0.8 seconds (75% reduction)
- Transcription accuracy: ~94% (balanced)
- GPU utilization: ~80%

## Testing Methodology

### Benchmark Suite
```python
# performance_benchmark.py
test_cases = [
    {"duration": 1, "text": "Hello world"},
    {"duration": 3, "text": "This is a medium length sentence with punctuation."},
    {"duration": 10, "text": "Long paragraph with multiple sentences..."}
]

for test in test_cases:
    times = []
    for i in range(10):
        start = time.time()
        result = transcribe_audio(test["audio"])
        times.append(time.time() - start)
    
    print(f"Duration: {test['duration']}s")
    print(f"Average: {np.mean(times)*1000:.0f}ms")
    print(f"Std Dev: {np.std(times)*1000:.0f}ms")
```

### Monitoring Dashboard
- Real-time latency tracking
- Accuracy metrics
- Resource utilization
- Error rates

## Rollout Plan

### Phase 1 Release (v1.2.0)
- Implement quick wins
- A/B test with users
- Collect performance metrics

### Phase 2 Release (v1.3.0)
- Architecture improvements
- Streaming support
- Enhanced monitoring

### Phase 3 Release (v2.0.0)
- Full optimization suite
- Configurable performance profiles
- Advanced features

## Risk Mitigation

### Accuracy vs Speed Trade-off
- Provide user-configurable profiles
- Default to balanced mode
- Allow per-application settings

### Hardware Compatibility
- Automatic fallback to CPU
- Dynamic parameter adjustment
- Performance auto-tuning

### User Experience
- Progress indicators during processing
- Instant basic text with async enhancement
- Clear error messages

## Conclusion

This optimization plan can reduce VoiceFlow's transcription latency by 50-75% while maintaining high accuracy. The phased approach ensures stable releases with measurable improvements at each stage.

Priority should be given to Phase 1 optimizations which provide the most significant improvements with minimal risk. These can be implemented and tested within a week, providing immediate value to users.

The key insight is that users perceive latency from key release to text appearance, so optimizing the tail buffer and transcription speed has the most direct impact on user experience.