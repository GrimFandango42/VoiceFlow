# VoiceFlow Performance Testing Suite

Comprehensive performance testing framework for evaluating VoiceFlow transcription system performance after implementing aggressive stability improvements.

## Quick Start

### Prerequisites
```bash
# Install required dependencies
pip install psutil numpy matplotlib seaborn plotly pandas
```

### Running Tests

#### 1. Quick Performance Validation
```bash
cd tests/performance
python -c "
import sys, os
sys.path.insert(0, os.path.join(os.getcwd(), '..', '..', 'src'))
from test_transcription_performance import *
# Quick test code here
"
```

#### 2. Comprehensive Test Suite
```bash
python run_performance_tests.py
```

#### 3. Configuration Comparison
```bash
python performance_comparison.py
```

#### 4. Interactive Dashboard
```bash
python performance_dashboard.py
```

## Test Components

### Core Performance Tests
- **`test_transcription_performance.py`** - Main performance testing framework
- **`performance_comparison.py`** - Configuration comparison analysis
- **`performance_dashboard.py`** - Interactive visualization dashboard
- **`run_performance_tests.py`** - Comprehensive test orchestrator

### Test Categories

#### 1. Transcription Speed Benchmarks
- Processing time vs audio duration analysis
- Real-time factor calculations
- Speed consistency measurement
- Model reload impact assessment

#### 2. Memory Usage Monitoring
- Memory growth tracking during model reloads
- Peak memory usage analysis
- Memory leak detection
- Resource optimization evaluation

#### 3. Latency Analysis
- End-to-end response time measurement
- Hotkey-to-completion latency tracking
- Model initialization overhead
- Performance consistency validation

#### 4. Long Session Stability
- Extended usage testing (30+ transcriptions)
- Performance degradation detection
- Error rate monitoring
- System reliability validation

#### 5. Configuration Comparison
- Before/after stability improvements
- Performance regression detection
- Optimization trade-off analysis
- Alternative configuration evaluation

## Test Results Structure

```
performance_test_output/
├── test_results/           # Raw performance test data
├── comparison_results/     # Configuration comparison data
├── dashboards/            # Interactive HTML dashboards
└── reports/               # Analysis reports and summaries
```

## Key Findings Summary

### Current Stability-Focused Configuration
- **Model**: tiny.en on CPU with int8 compute
- **Reload Frequency**: Every 2 transcriptions
- **Performance**: Variable (0.16x - 21x realtime)
- **Stability**: Excellent (zero stuck transcriptions)

### Performance Characteristics
- ✅ **Real-time capable**: Average performance exceeds 1x realtime
- ✅ **Zero failures**: No stuck transcriptions or system hangs
- ✅ **Robust error handling**: Comprehensive recovery patterns
- ⚠️ **Reload overhead**: 2.5-3.5s delay every 2 transcriptions

### Trade-off Analysis
- **Reliability**: A+ (Primary goal achieved)
- **Speed**: B- (Acceptable with reload overhead)
- **Resource Usage**: B (CPU-only, reasonable memory)
- **User Experience**: B+ (Reliable with minor delays)

## Usage Examples

### Basic Performance Test
```python
from test_transcription_performance import PerformanceTester, Config

# Create test configuration
config = Config(
    model_name="tiny.en",
    device="cpu",
    compute_type="int8",
    max_transcriptions_before_reload=2
)

# Run performance test
tester = PerformanceTester(config)
asr_instance = tester.create_asr_instance()
results = tester.benchmark_transcription_speed(asr_instance)
```

### Configuration Comparison
```python
from performance_comparison import PerformanceComparator

comparator = PerformanceComparator()
results = comparator.run_profile_comparison(
    baseline_profile='stability_focused',
    comparison_profiles=['original_optimized', 'balanced']
)
```

### Dashboard Generation
```python
from performance_dashboard import PerformanceDashboard

dashboard = PerformanceDashboard()
dashboard.load_test_results('test_results/latest.json')
dashboard.create_speed_analysis_dashboard('speed_analysis.html')
```

## Performance Targets

### Acceptable Performance Thresholds
- **Speed Factor**: ≥1.0x realtime average
- **Memory Growth**: ≤100MB per session
- **Latency**: ≤2000ms end-to-end
- **Error Rate**: ≤5%
- **CPU Usage**: ≤80% peak

### Optimization Goals
- **Consistency**: Reduce reload-related performance variance
- **Efficiency**: Maintain stability with fewer reloads
- **Quality**: Preserve transcription accuracy
- **Scalability**: Support extended usage sessions

## Troubleshooting

### Common Issues
1. **Import Errors**: Ensure VoiceFlow source path is correct
2. **Missing Dependencies**: Install from requirements.txt
3. **Model Loading Failures**: Check Whisper model availability
4. **Memory Issues**: Monitor available system memory

### Performance Optimization
1. **GPU Testing**: Enable CUDA if available
2. **Model Selection**: Test different Whisper model sizes
3. **Reload Tuning**: Adjust reload frequency based on stability
4. **Resource Monitoring**: Track system resource usage

## Contributing

### Adding New Tests
1. Extend `PerformanceTester` class with new test methods
2. Update dashboard visualization for new metrics
3. Include results in comparison framework
4. Document expected performance characteristics

### Extending Dashboards
1. Add new chart types to `PerformanceDashboard`
2. Create specialized analysis functions
3. Update report generation templates
4. Include interactive features for exploration

## References

- **VoiceFlow Core Documentation**: `../../src/voiceflow/`
- **Stability Improvements**: Implementation in `asr_buffer_safe.py`
- **Configuration Options**: `config.py` parameter reference
- **Performance Analysis**: `PERFORMANCE_ANALYSIS_REPORT.md`