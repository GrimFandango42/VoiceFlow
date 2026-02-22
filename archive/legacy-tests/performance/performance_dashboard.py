"""
VoiceFlow Performance Dashboard
==============================

Interactive dashboard for visualizing and analyzing VoiceFlow performance test results.
Provides comprehensive visualization of:
- Transcription speed trends
- Memory usage patterns
- Latency distributions
- Model reload impact analysis
- Performance comparison charts
"""

import json
import logging
import statistics
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.express as px

logger = logging.getLogger(__name__)

class PerformanceDashboard:
    """Performance analysis and visualization dashboard"""

    def __init__(self):
        self.results_data = {}
        self.comparison_data = {}

        # Set up plotting style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")

        # Dashboard configuration
        self.figure_size = (12, 8)
        self.subplot_figure_size = (15, 12)

    def load_test_results(self, results_file: Path) -> bool:
        """Load performance test results from JSON file"""
        try:
            with open(results_file, 'r') as f:
                self.results_data = json.load(f)
            logger.info(f"Loaded test results from {results_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load test results: {e}")
            return False

    def load_comparison_results(self, comparison_file: Path) -> bool:
        """Load performance comparison results from JSON file"""
        try:
            with open(comparison_file, 'r') as f:
                self.comparison_data = json.load(f)
            logger.info(f"Loaded comparison results from {comparison_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load comparison results: {e}")
            return False

    def create_speed_analysis_dashboard(self, save_path: Optional[Path] = None) -> go.Figure:
        """Create comprehensive speed analysis dashboard"""

        if not self.results_data:
            logger.error("No test results loaded")
            return None

        # Extract speed data from test results
        speed_data = self._extract_speed_metrics()

        # Create subplot figure
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Speed Factor Distribution', 'Speed vs Audio Duration',
                          'Processing Time Trends', 'Real-time Factor Analysis'],
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": True}, {"secondary_y": False}]]
        )

        # 1. Speed factor distribution
        fig.add_trace(
            go.Histogram(
                x=speed_data['speed_factors'],
                nbinsx=20,
                name='Speed Distribution',
                opacity=0.7
            ),
            row=1, col=1
        )

        # 2. Speed vs Audio Duration scatter
        fig.add_trace(
            go.Scatter(
                x=speed_data['audio_durations'],
                y=speed_data['speed_factors'],
                mode='markers',
                name='Speed vs Duration',
                text=speed_data['test_names'],
                hovertemplate='Duration: %{x:.2f}s<br>Speed: %{y:.2f}x<br>Test: %{text}<extra></extra>'
            ),
            row=1, col=2
        )

        # Add ideal line (1x real-time)
        fig.add_hline(y=1.0, line_dash="dash", line_color="red",
                     annotation_text="Real-time threshold", row=1, col=2)

        # 3. Processing time trends
        fig.add_trace(
            go.Scatter(
                x=list(range(len(speed_data['processing_times']))),
                y=speed_data['processing_times'],
                mode='lines+markers',
                name='Processing Time',
                line=dict(color='blue')
            ),
            row=2, col=1
        )

        # Add secondary y-axis for memory usage
        fig.add_trace(
            go.Scatter(
                x=list(range(len(speed_data['memory_usage']))),
                y=speed_data['memory_usage'],
                mode='lines',
                name='Memory Usage',
                line=dict(color='red', dash='dot'),
                yaxis='y4'
            ),
            row=2, col=1, secondary_y=True
        )

        # 4. Real-time factor analysis
        realtime_factors = [max(0.1, sf) for sf in speed_data['speed_factors']]  # Avoid log(0)
        fig.add_trace(
            go.Box(
                y=realtime_factors,
                name='Real-time Factors',
                boxpoints='all',
                jitter=0.3,
                pointpos=-1.8
            ),
            row=2, col=2
        )

        # Update layout
        fig.update_layout(
            title='VoiceFlow Transcription Speed Analysis Dashboard',
            height=800,
            showlegend=True,
            template='plotly_white'
        )

        # Update axes labels
        fig.update_xaxes(title_text="Speed Factor (x)", row=1, col=1)
        fig.update_yaxes(title_text="Frequency", row=1, col=1)

        fig.update_xaxes(title_text="Audio Duration (s)", row=1, col=2)
        fig.update_yaxes(title_text="Speed Factor (x)", row=1, col=2)

        fig.update_xaxes(title_text="Test Number", row=2, col=1)
        fig.update_yaxes(title_text="Processing Time (s)", row=2, col=1)
        fig.update_yaxes(title_text="Memory Usage (MB)", secondary_y=True, row=2, col=1)

        fig.update_yaxes(title_text="Speed Factor (x)", row=2, col=2)

        if save_path:
            fig.write_html(save_path)
            logger.info(f"Speed analysis dashboard saved to {save_path}")

        return fig

    def create_memory_analysis_dashboard(self, save_path: Optional[Path] = None) -> go.Figure:
        """Create memory usage analysis dashboard"""

        if not self.results_data:
            logger.error("No test results loaded")
            return None

        memory_data = self._extract_memory_metrics()

        # Create subplot figure
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Memory Growth Over Time', 'Memory Usage Distribution',
                          'Memory vs Processing Time', 'Peak Memory Analysis'],
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"secondary_y": False}]]
        )

        # 1. Memory growth over time
        fig.add_trace(
            go.Scatter(
                x=list(range(len(memory_data['memory_before']))),
                y=memory_data['memory_before'],
                mode='lines+markers',
                name='Memory Before',
                line=dict(color='blue')
            ),
            row=1, col=1
        )

        fig.add_trace(
            go.Scatter(
                x=list(range(len(memory_data['memory_after']))),
                y=memory_data['memory_after'],
                mode='lines+markers',
                name='Memory After',
                line=dict(color='red')
            ),
            row=1, col=1
        )

        fig.add_trace(
            go.Scatter(
                x=list(range(len(memory_data['memory_peak']))),
                y=memory_data['memory_peak'],
                mode='lines',
                name='Peak Memory',
                line=dict(color='orange', dash='dot')
            ),
            row=1, col=1
        )

        # 2. Memory growth distribution
        memory_growth = [after - before for before, after in
                        zip(memory_data['memory_before'], memory_data['memory_after'])]

        fig.add_trace(
            go.Histogram(
                x=memory_growth,
                nbinsx=15,
                name='Memory Growth',
                opacity=0.7
            ),
            row=1, col=2
        )

        # 3. Memory vs Processing Time
        fig.add_trace(
            go.Scatter(
                x=memory_data['processing_times'],
                y=memory_growth,
                mode='markers',
                name='Memory Growth vs Time',
                text=memory_data['test_names'],
                hovertemplate='Processing: %{x:.3f}s<br>Memory Growth: %{y:.1f}MB<br>Test: %{text}<extra></extra>'
            ),
            row=2, col=1
        )

        # 4. Peak memory analysis
        fig.add_trace(
            go.Box(
                y=memory_data['memory_peak'],
                name='Peak Memory',
                boxpoints='outliers'
            ),
            row=2, col=2
        )

        # Update layout
        fig.update_layout(
            title='VoiceFlow Memory Usage Analysis Dashboard',
            height=800,
            showlegend=True,
            template='plotly_white'
        )

        # Update axes labels
        fig.update_xaxes(title_text="Test Number", row=1, col=1)
        fig.update_yaxes(title_text="Memory Usage (MB)", row=1, col=1)

        fig.update_xaxes(title_text="Memory Growth (MB)", row=1, col=2)
        fig.update_yaxes(title_text="Frequency", row=1, col=2)

        fig.update_xaxes(title_text="Processing Time (s)", row=2, col=1)
        fig.update_yaxes(title_text="Memory Growth (MB)", row=2, col=1)

        fig.update_yaxes(title_text="Peak Memory (MB)", row=2, col=2)

        if save_path:
            fig.write_html(save_path)
            logger.info(f"Memory analysis dashboard saved to {save_path}")

        return fig

    def create_performance_comparison_dashboard(self, save_path: Optional[Path] = None) -> go.Figure:
        """Create performance comparison dashboard"""

        if not self.comparison_data:
            logger.error("No comparison results loaded")
            return None

        comparison_metrics = self._extract_comparison_metrics()

        # Create subplot figure
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Speed Factor Comparison', 'Memory Usage Comparison',
                          'Latency Comparison', 'Stability Score Comparison'],
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"secondary_y": False}]]
        )

        profiles = list(comparison_metrics.keys())

        # 1. Speed factor comparison
        speed_values = [comparison_metrics[p]['speed_factor_change'] for p in profiles]
        colors = ['green' if x > 0 else 'red' for x in speed_values]

        fig.add_trace(
            go.Bar(
                x=profiles,
                y=speed_values,
                name='Speed Change',
                marker_color=colors,
                text=[f'{x:+.2f}x' for x in speed_values],
                textposition='auto'
            ),
            row=1, col=1
        )

        # Add baseline line
        fig.add_hline(y=0, line_dash="dash", line_color="black", row=1, col=1)

        # 2. Memory usage comparison
        memory_values = [comparison_metrics[p]['memory_usage_change'] for p in profiles]
        memory_colors = ['red' if x > 0 else 'green' for x in memory_values]

        fig.add_trace(
            go.Bar(
                x=profiles,
                y=memory_values,
                name='Memory Change',
                marker_color=memory_colors,
                text=[f'{x:+.1f}MB' for x in memory_values],
                textposition='auto'
            ),
            row=1, col=2
        )

        fig.add_hline(y=0, line_dash="dash", line_color="black", row=1, col=2)

        # 3. Latency comparison
        latency_values = [comparison_metrics[p]['latency_change'] for p in profiles]
        latency_colors = ['red' if x > 0 else 'green' for x in latency_values]

        fig.add_trace(
            go.Bar(
                x=profiles,
                y=latency_values,
                name='Latency Change',
                marker_color=latency_colors,
                text=[f'{x:+.0f}ms' for x in latency_values],
                textposition='auto'
            ),
            row=2, col=1
        )

        fig.add_hline(y=0, line_dash="dash", line_color="black", row=2, col=1)

        # 4. Stability score comparison
        stability_values = [comparison_metrics[p]['stability_score_change'] for p in profiles]
        stability_colors = ['green' if x > 0 else 'red' for x in stability_values]

        fig.add_trace(
            go.Bar(
                x=profiles,
                y=stability_values,
                name='Stability Change',
                marker_color=stability_colors,
                text=[f'{x:+.2f}' for x in stability_values],
                textposition='auto'
            ),
            row=2, col=2
        )

        fig.add_hline(y=0, line_dash="dash", line_color="black", row=2, col=2)

        # Update layout
        fig.update_layout(
            title='VoiceFlow Performance Comparison Dashboard',
            height=800,
            showlegend=False,
            template='plotly_white'
        )

        # Update axes labels
        fig.update_yaxes(title_text="Speed Change (x)", row=1, col=1)
        fig.update_yaxes(title_text="Memory Change (MB)", row=1, col=2)
        fig.update_yaxes(title_text="Latency Change (ms)", row=2, col=1)
        fig.update_yaxes(title_text="Stability Change", row=2, col=2)

        if save_path:
            fig.write_html(save_path)
            logger.info(f"Performance comparison dashboard saved to {save_path}")

        return fig

    def create_stability_trends_dashboard(self, save_path: Optional[Path] = None) -> go.Figure:
        """Create stability and reliability trends dashboard"""

        if not self.results_data:
            logger.error("No test results loaded")
            return None

        stability_data = self._extract_stability_metrics()

        # Create subplot figure
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Error Rate Over Time', 'Performance Consistency',
                          'Model Reload Impact', 'Session Duration Analysis'],
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"secondary_y": False}]]
        )

        # 1. Error rate over time
        test_numbers = list(range(len(stability_data['error_flags'])))
        cumulative_errors = np.cumsum(stability_data['error_flags'])
        error_rate = [err / (i + 1) for i, err in enumerate(cumulative_errors)]

        fig.add_trace(
            go.Scatter(
                x=test_numbers,
                y=error_rate,
                mode='lines+markers',
                name='Cumulative Error Rate',
                line=dict(color='red')
            ),
            row=1, col=1
        )

        # 2. Performance consistency (speed factor variance)
        window_size = 5
        speed_variance = self._calculate_rolling_variance(stability_data['speed_factors'], window_size)

        fig.add_trace(
            go.Scatter(
                x=test_numbers[window_size-1:],
                y=speed_variance,
                mode='lines',
                name='Speed Variance',
                fill='tonexty'
            ),
            row=1, col=2
        )

        # 3. Model reload impact (if available)
        if stability_data['model_reload_flags']:
            reload_indices = [i for i, flag in enumerate(stability_data['model_reload_flags']) if flag]
            if reload_indices:
                # Show processing time spikes during reloads
                fig.add_trace(
                    go.Scatter(
                        x=test_numbers,
                        y=stability_data['processing_times'],
                        mode='lines+markers',
                        name='Processing Time',
                        line=dict(color='blue')
                    ),
                    row=2, col=1
                )

                # Highlight reload points
                fig.add_trace(
                    go.Scatter(
                        x=reload_indices,
                        y=[stability_data['processing_times'][i] for i in reload_indices],
                        mode='markers',
                        name='Model Reloads',
                        marker=dict(size=10, color='red', symbol='x')
                    ),
                    row=2, col=1
                )

        # 4. Session duration analysis
        if 'session_data' in self.results_data:
            session_data = self.results_data['session_data']
            if isinstance(session_data, list):
                session_durations = [s.get('total_processing_time', 0) for s in session_data]
                session_transcriptions = [s.get('total_transcriptions', 0) for s in session_data]

                fig.add_trace(
                    go.Scatter(
                        x=session_transcriptions,
                        y=session_durations,
                        mode='markers',
                        name='Session Performance',
                        marker=dict(size=8)
                    ),
                    row=2, col=2
                )

        # Update layout
        fig.update_layout(
            title='VoiceFlow Stability and Reliability Trends',
            height=800,
            showlegend=True,
            template='plotly_white'
        )

        # Update axes labels
        fig.update_xaxes(title_text="Test Number", row=1, col=1)
        fig.update_yaxes(title_text="Error Rate", row=1, col=1)

        fig.update_xaxes(title_text="Test Number", row=1, col=2)
        fig.update_yaxes(title_text="Speed Variance", row=1, col=2)

        fig.update_xaxes(title_text="Test Number", row=2, col=1)
        fig.update_yaxes(title_text="Processing Time (s)", row=2, col=1)

        fig.update_xaxes(title_text="Transcriptions", row=2, col=2)
        fig.update_yaxes(title_text="Duration (s)", row=2, col=2)

        if save_path:
            fig.write_html(save_path)
            logger.info(f"Stability trends dashboard saved to {save_path}")

        return fig

    def generate_summary_report(self, output_path: Path) -> str:
        """Generate comprehensive text summary report"""

        if not self.results_data and not self.comparison_data:
            return "No data available for report generation"

        report_lines = []
        report_lines.append("VoiceFlow Performance Analysis Report")
        report_lines.append("=" * 50)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")

        # Test results summary
        if self.results_data:
            report_lines.append("PERFORMANCE TEST RESULTS")
            report_lines.append("-" * 30)

            if 'summary' in self.results_data:
                summary = self.results_data['summary']
                report_lines.append(f"Total Tests: {summary.get('total_tests', 'N/A')}")
                report_lines.append(f"Error Rate: {summary.get('error_rate', 0):.1%}")

                if 'speed_factor' in summary:
                    sf = summary['speed_factor']
                    report_lines.append(f"Average Speed: {sf.get('mean', 0):.2f}x realtime")
                    report_lines.append(f"Speed Range: {sf.get('min', 0):.2f}x - {sf.get('max', 0):.2f}x")

                if 'memory_usage' in summary:
                    mem = summary['memory_usage']
                    report_lines.append(f"Max Memory Growth: {mem.get('max_growth_mb', 0):.1f}MB")

                if 'latency' in summary and summary['latency']:
                    lat = summary['latency']
                    report_lines.append(f"Average Latency: {lat.get('mean_ms', 0):.0f}ms")
                    report_lines.append(f"Max Latency: {lat.get('max_ms', 0):.0f}ms")

                if 'performance_assessment' in summary:
                    assessment = summary['performance_assessment']
                    report_lines.append(f"Overall Grade: {assessment.get('overall_grade', 'N/A')}")

                    if assessment.get('issues'):
                        report_lines.append("Issues:")
                        for issue in assessment['issues']:
                            report_lines.append(f"  - {issue}")

                    if assessment.get('strengths'):
                        report_lines.append("Strengths:")
                        for strength in assessment['strengths']:
                            report_lines.append(f"  + {strength}")

            report_lines.append("")

        # Comparison results summary
        if self.comparison_data:
            report_lines.append("PERFORMANCE COMPARISON RESULTS")
            report_lines.append("-" * 35)

            if 'comparisons' in self.comparison_data:
                for profile_name, comparison in self.comparison_data['comparisons'].items():
                    report_lines.append(f"\n{profile_name.upper()}:")
                    report_lines.append(f"  Summary: {comparison.get('performance_summary', 'N/A')}")
                    report_lines.append(f"  Speed Change: {comparison.get('speed_factor_change', 0):+.2f}x")
                    report_lines.append(f"  Memory Change: {comparison.get('memory_usage_change', 0):+.1f}MB")
                    report_lines.append(f"  Latency Change: {comparison.get('latency_change', 0):+.0f}ms")

                    if comparison.get('regression_detected'):
                        report_lines.append("  ⚠️ REGRESSION DETECTED")
                    else:
                        report_lines.append("  ✅ No significant regressions")

            report_lines.append("")

        # Recommendations
        report_lines.append("RECOMMENDATIONS")
        report_lines.append("-" * 15)

        if self.results_data and 'summary' in self.results_data:
            assessment = self.results_data['summary'].get('performance_assessment', {})
            recommendations = assessment.get('recommendations', [])
            for rec in recommendations:
                report_lines.append(f"• {rec}")

        # Add stability-specific recommendations
        report_lines.append("• Monitor long-term stability over extended sessions")
        report_lines.append("• Track memory usage patterns for potential optimizations")
        report_lines.append("• Consider adjusting model reload frequency based on performance data")
        report_lines.append("• Evaluate trade-offs between stability and performance")

        report_text = "\n".join(report_lines)

        # Save report to file
        with open(output_path, 'w') as f:
            f.write(report_text)

        logger.info(f"Summary report saved to {output_path}")
        return report_text

    def _extract_speed_metrics(self) -> Dict[str, List]:
        """Extract speed-related metrics from test results"""
        speed_data = {
            'speed_factors': [],
            'audio_durations': [],
            'processing_times': [],
            'memory_usage': [],
            'test_names': []
        }

        # Extract from different test result sections
        test_sections = ['speed_benchmark', 'latency', 'model_reload', 'long_session']

        for section in test_sections:
            if section in self.results_data.get('test_results', {}):
                section_data = self.results_data['test_results'][section]

                if isinstance(section_data, list):
                    # Individual test results
                    for result in section_data:
                        if isinstance(result, dict):
                            speed_data['speed_factors'].append(result.get('speed_factor', 0))
                            speed_data['audio_durations'].append(result.get('audio_duration', 0))
                            speed_data['processing_times'].append(result.get('processing_time', 0))
                            speed_data['memory_usage'].append(result.get('memory_after_mb', 0) - result.get('memory_before_mb', 0))
                            speed_data['test_names'].append(result.get('test_name', f'{section}_test'))
                elif isinstance(section_data, dict):
                    # Session data
                    if 'individual_metrics' in section_data:
                        for result in section_data['individual_metrics']:
                            speed_data['speed_factors'].append(result.get('speed_factor', 0))
                            speed_data['audio_durations'].append(result.get('audio_duration', 0))
                            speed_data['processing_times'].append(result.get('processing_time', 0))
                            speed_data['memory_usage'].append(result.get('memory_after_mb', 0) - result.get('memory_before_mb', 0))
                            speed_data['test_names'].append(result.get('test_name', f'{section}_test'))

        return speed_data

    def _extract_memory_metrics(self) -> Dict[str, List]:
        """Extract memory-related metrics from test results"""
        memory_data = {
            'memory_before': [],
            'memory_after': [],
            'memory_peak': [],
            'processing_times': [],
            'test_names': []
        }

        # Similar extraction logic as speed metrics
        test_sections = ['speed_benchmark', 'latency', 'model_reload', 'long_session']

        for section in test_sections:
            if section in self.results_data.get('test_results', {}):
                section_data = self.results_data['test_results'][section]

                if isinstance(section_data, list):
                    for result in section_data:
                        if isinstance(result, dict):
                            memory_data['memory_before'].append(result.get('memory_before_mb', 0))
                            memory_data['memory_after'].append(result.get('memory_after_mb', 0))
                            memory_data['memory_peak'].append(result.get('memory_peak_mb', 0))
                            memory_data['processing_times'].append(result.get('processing_time', 0))
                            memory_data['test_names'].append(result.get('test_name', f'{section}_test'))
                elif isinstance(section_data, dict):
                    if 'individual_metrics' in section_data:
                        for result in section_data['individual_metrics']:
                            memory_data['memory_before'].append(result.get('memory_before_mb', 0))
                            memory_data['memory_after'].append(result.get('memory_after_mb', 0))
                            memory_data['memory_peak'].append(result.get('memory_peak_mb', 0))
                            memory_data['processing_times'].append(result.get('processing_time', 0))
                            memory_data['test_names'].append(result.get('test_name', f'{section}_test'))

        return memory_data

    def _extract_comparison_metrics(self) -> Dict[str, Dict]:
        """Extract comparison metrics from comparison results"""
        comparison_metrics = {}

        if 'comparisons' in self.comparison_data:
            for profile_name, comparison in self.comparison_data['comparisons'].items():
                comparison_metrics[profile_name] = {
                    'speed_factor_change': comparison.get('speed_factor_change', 0),
                    'memory_usage_change': comparison.get('memory_usage_change', 0),
                    'latency_change': comparison.get('latency_change', 0),
                    'cpu_usage_change': comparison.get('cpu_usage_change', 0),
                    'stability_score_change': comparison.get('stability_score_change', 0),
                    'regression_detected': comparison.get('regression_detected', False)
                }

        return comparison_metrics

    def _extract_stability_metrics(self) -> Dict[str, List]:
        """Extract stability-related metrics from test results"""
        stability_data = {
            'error_flags': [],
            'speed_factors': [],
            'processing_times': [],
            'model_reload_flags': []
        }

        # Extract from all test results
        test_sections = ['speed_benchmark', 'latency', 'model_reload', 'long_session']

        for section in test_sections:
            if section in self.results_data.get('test_results', {}):
                section_data = self.results_data['test_results'][section]

                if isinstance(section_data, list):
                    for result in section_data:
                        if isinstance(result, dict):
                            stability_data['error_flags'].append(1 if result.get('error_occurred', False) else 0)
                            stability_data['speed_factors'].append(result.get('speed_factor', 0))
                            stability_data['processing_times'].append(result.get('processing_time', 0))
                            stability_data['model_reload_flags'].append(result.get('model_reload_occurred', False))
                elif isinstance(section_data, dict):
                    if 'individual_metrics' in section_data:
                        for result in section_data['individual_metrics']:
                            stability_data['error_flags'].append(1 if result.get('error_occurred', False) else 0)
                            stability_data['speed_factors'].append(result.get('speed_factor', 0))
                            stability_data['processing_times'].append(result.get('processing_time', 0))
                            stability_data['model_reload_flags'].append(result.get('model_reload_occurred', False))

        return stability_data

    def _calculate_rolling_variance(self, data: List[float], window_size: int) -> List[float]:
        """Calculate rolling variance for consistency analysis"""
        if len(data) < window_size:
            return []

        variances = []
        for i in range(window_size - 1, len(data)):
            window = data[i - window_size + 1:i + 1]
            variance = statistics.variance(window) if len(window) > 1 else 0
            variances.append(variance)

        return variances

def main():
    """Generate performance dashboard"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    dashboard = PerformanceDashboard()

    # Look for recent test results
    results_dir = Path("test_results")
    comparison_dir = Path("comparison_results")

    # Find most recent results files
    results_files = list(results_dir.glob("performance_results_*.json")) if results_dir.exists() else []
    comparison_files = list(comparison_dir.glob("performance_comparison_*.json")) if comparison_dir.exists() else []

    if results_files:
        latest_results = max(results_files, key=lambda x: x.stat().st_mtime)
        dashboard.load_test_results(latest_results)
        logger.info(f"Loaded test results from {latest_results}")

    if comparison_files:
        latest_comparison = max(comparison_files, key=lambda x: x.stat().st_mtime)
        dashboard.load_comparison_results(latest_comparison)
        logger.info(f"Loaded comparison results from {latest_comparison}")

    # Create output directory
    output_dir = Path("dashboard_output")
    output_dir.mkdir(exist_ok=True)

    # Generate dashboards
    if dashboard.results_data:
        logger.info("Generating performance dashboards...")

        # Speed analysis
        speed_fig = dashboard.create_speed_analysis_dashboard(
            output_dir / "speed_analysis_dashboard.html"
        )

        # Memory analysis
        memory_fig = dashboard.create_memory_analysis_dashboard(
            output_dir / "memory_analysis_dashboard.html"
        )

        # Stability trends
        stability_fig = dashboard.create_stability_trends_dashboard(
            output_dir / "stability_trends_dashboard.html"
        )

    if dashboard.comparison_data:
        logger.info("Generating comparison dashboard...")

        # Performance comparison
        comparison_fig = dashboard.create_performance_comparison_dashboard(
            output_dir / "performance_comparison_dashboard.html"
        )

    # Generate summary report
    if dashboard.results_data or dashboard.comparison_data:
        logger.info("Generating summary report...")
        report = dashboard.generate_summary_report(
            output_dir / "performance_summary_report.txt"
        )
        print("\nSUMMARY REPORT:")
        print("=" * 50)
        print(report)

    print(f"\nDashboard files saved to: {output_dir.absolute()}")

if __name__ == "__main__":
    main()