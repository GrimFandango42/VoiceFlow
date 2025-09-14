#!/usr/bin/env python3
"""
VoiceFlow Test Analytics and Reporting System

This module provides comprehensive test result analytics, trend analysis,
and advanced reporting capabilities for the VoiceFlow testing framework.

Features:
- Historical test result analysis
- Performance trend tracking
- Quality metrics calculation
- Automated report generation
- Test failure pattern detection
- Resource usage analytics
- Regression detection and alerting
"""

import json
import logging
import sqlite3
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
import numpy as np
from dataclasses import dataclass
import seaborn as sns

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TestTrend:
    """Test trend analysis result."""
    metric_name: str
    trend_direction: str  # 'improving', 'degrading', 'stable'
    trend_magnitude: float
    confidence: float
    period_days: int
    data_points: int


@dataclass
class QualityMetrics:
    """Quality metrics for test results."""
    success_rate: float
    stability_score: float
    performance_score: float
    reliability_score: float
    overall_quality_score: float
    trend_direction: str


class TestResultsDatabase:
    """Database for storing and querying test results."""
    
    def __init__(self, db_path: str = "test_analytics.db"):
        self.db_path = Path(db_path)
        self._init_database()
    
    def _init_database(self):
        """Initialize the analytics database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Test runs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                total_tests INTEGER,
                passed_tests INTEGER,
                failed_tests INTEGER,
                error_tests INTEGER,
                skipped_tests INTEGER,
                total_duration REAL,
                success_rate REAL,
                commit_hash TEXT,
                branch_name TEXT,
                environment TEXT,
                metadata TEXT
            )
        ''')
        
        # Individual test results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                test_name TEXT,
                test_type TEXT,
                status TEXT,
                duration REAL,
                error_message TEXT,
                metadata TEXT,
                FOREIGN KEY (run_id) REFERENCES test_runs (id)
            )
        ''')
        
        # Performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                metric_name TEXT,
                metric_value REAL,
                metric_unit TEXT,
                benchmark_value REAL,
                passed BOOLEAN,
                metadata TEXT,
                FOREIGN KEY (run_id) REFERENCES test_runs (id)
            )
        ''')
        
        # System metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                metric_name TEXT,
                min_value REAL,
                max_value REAL,
                avg_value REAL,
                samples INTEGER,
                metadata TEXT,
                FOREIGN KEY (run_id) REFERENCES test_runs (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_test_run(self, run_data: Dict[str, Any]) -> int:
        """Store a test run and return the run ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert test run
        cursor.execute('''
            INSERT INTO test_runs 
            (timestamp, total_tests, passed_tests, failed_tests, error_tests, 
             skipped_tests, total_duration, success_rate, commit_hash, 
             branch_name, environment, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            run_data.get('timestamp', datetime.now().isoformat()),
            run_data.get('total_tests', 0),
            run_data.get('passed', 0),
            run_data.get('failed', 0),
            run_data.get('errors', 0),
            run_data.get('skipped', 0),
            run_data.get('total_duration', 0),
            run_data.get('success_rate', 0),
            run_data.get('commit_hash'),
            run_data.get('branch_name'),
            run_data.get('environment'),
            json.dumps(run_data.get('metadata', {}))
        ))
        
        run_id = cursor.lastrowid
        
        # Store individual test results
        for result in run_data.get('results', []):
            cursor.execute('''
                INSERT INTO test_results 
                (run_id, test_name, test_type, status, duration, error_message, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                run_id,
                result.get('name'),
                result.get('test_type'),
                result.get('status'),
                result.get('duration', 0),
                result.get('error_output'),
                json.dumps(result.get('metadata', {}))
            ))
        
        # Store performance metrics
        for metric in run_data.get('performance_metrics', []):
            cursor.execute('''
                INSERT INTO performance_metrics 
                (run_id, metric_name, metric_value, metric_unit, benchmark_value, passed, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                run_id,
                metric.get('name'),
                metric.get('value'),
                metric.get('unit'),
                metric.get('benchmark'),
                metric.get('passed'),
                json.dumps(metric.get('metadata', {}))
            ))
        
        # Store system metrics
        for metric in run_data.get('system_metrics', []):
            cursor.execute('''
                INSERT INTO system_metrics 
                (run_id, metric_name, min_value, max_value, avg_value, samples, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                run_id,
                metric.get('name'),
                metric.get('min'),
                metric.get('max'),
                metric.get('avg'),
                metric.get('samples'),
                json.dumps(metric.get('metadata', {}))
            ))
        
        conn.commit()
        conn.close()
        
        return run_id
    
    def get_test_runs(self, limit: int = 100, days: int = None) -> List[Dict[str, Any]]:
        """Get test runs with optional date filtering."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM test_runs"
        params = []
        
        if days:
            cutoff_date = datetime.now() - timedelta(days=days)
            query += " WHERE timestamp >= ?"
            params.append(cutoff_date.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        
        columns = [desc[0] for desc in cursor.description]
        runs = []
        
        for row in cursor.fetchall():
            run_data = dict(zip(columns, row))
            if run_data['metadata']:
                run_data['metadata'] = json.loads(run_data['metadata'])
            runs.append(run_data)
        
        conn.close()
        return runs
    
    def get_performance_trends(self, metric_name: str, days: int = 30) -> List[Tuple[datetime, float]]:
        """Get performance trend data for a specific metric."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        cursor.execute('''
            SELECT tr.timestamp, pm.metric_value
            FROM performance_metrics pm
            JOIN test_runs tr ON pm.run_id = tr.id
            WHERE pm.metric_name = ? AND tr.timestamp >= ?
            ORDER BY tr.timestamp
        ''', (metric_name, cutoff_date.isoformat()))
        
        trends = []
        for timestamp_str, value in cursor.fetchall():
            timestamp = datetime.fromisoformat(timestamp_str)
            trends.append((timestamp, value))
        
        conn.close()
        return trends
    
    def get_failure_patterns(self, days: int = 30) -> Dict[str, Any]:
        """Analyze test failure patterns."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # Get failed tests
        cursor.execute('''
            SELECT tr.test_name, tr.test_type, tr.error_message, trun.timestamp
            FROM test_results tr
            JOIN test_runs trun ON tr.run_id = trun.id
            WHERE tr.status IN ('failed', 'error') AND trun.timestamp >= ?
            ORDER BY trun.timestamp DESC
        ''', (cutoff_date.isoformat(),))
        
        failures = cursor.fetchall()
        
        # Analyze patterns
        failure_counts = Counter(failure[0] for failure in failures)  # By test name
        failure_types = Counter(failure[1] for failure in failures)   # By test type
        
        # Common error patterns
        error_patterns = Counter()
        for failure in failures:
            error_msg = failure[2] or ""
            # Extract common error patterns
            if "timeout" in error_msg.lower():
                error_patterns["timeout"] += 1
            elif "memory" in error_msg.lower():
                error_patterns["memory"] += 1
            elif "network" in error_msg.lower():
                error_patterns["network"] += 1
            elif "assertion" in error_msg.lower():
                error_patterns["assertion"] += 1
            else:
                error_patterns["other"] += 1
        
        conn.close()
        
        return {
            'total_failures': len(failures),
            'most_failing_tests': failure_counts.most_common(10),
            'failure_by_type': dict(failure_types),
            'error_patterns': dict(error_patterns),
            'analysis_period_days': days
        }


class TestTrendAnalyzer:
    """Analyze test result trends over time."""
    
    def __init__(self, db: TestResultsDatabase):
        self.db = db
    
    def analyze_success_rate_trend(self, days: int = 30) -> TestTrend:
        """Analyze success rate trend."""
        runs = self.db.get_test_runs(days=days)
        
        if len(runs) < 2:
            return TestTrend("success_rate", "stable", 0.0, 0.0, days, len(runs))
        
        # Extract success rates and timestamps
        success_rates = [run['success_rate'] for run in runs]
        timestamps = [datetime.fromisoformat(run['timestamp']) for run in runs]
        
        # Calculate trend using linear regression
        trend_magnitude = self._calculate_linear_trend(success_rates)
        confidence = self._calculate_trend_confidence(success_rates)
        
        # Determine trend direction
        if abs(trend_magnitude) < 0.01:  # Less than 1% change
            direction = "stable"
        elif trend_magnitude > 0:
            direction = "improving"
        else:
            direction = "degrading"
        
        return TestTrend(
            metric_name="success_rate",
            trend_direction=direction,
            trend_magnitude=trend_magnitude,
            confidence=confidence,
            period_days=days,
            data_points=len(runs)
        )
    
    def analyze_performance_trends(self, days: int = 30) -> List[TestTrend]:
        """Analyze performance metric trends."""
        # Get common performance metrics
        common_metrics = [
            "audio_transcription_latency",
            "ai_enhancement_latency",
            "memory_usage",
            "cpu_usage"
        ]
        
        trends = []
        
        for metric in common_metrics:
            trend_data = self.db.get_performance_trends(metric, days)
            
            if len(trend_data) < 2:
                continue
            
            values = [point[1] for point in trend_data]
            trend_magnitude = self._calculate_linear_trend(values)
            confidence = self._calculate_trend_confidence(values)
            
            # For performance metrics, lower is usually better
            if abs(trend_magnitude) < 0.05:  # Less than 5% change
                direction = "stable"
            elif trend_magnitude > 0:
                direction = "degrading"  # Performance getting worse
            else:
                direction = "improving"  # Performance getting better
            
            trends.append(TestTrend(
                metric_name=metric,
                trend_direction=direction,
                trend_magnitude=trend_magnitude,
                confidence=confidence,
                period_days=days,
                data_points=len(trend_data)
            ))
        
        return trends
    
    def _calculate_linear_trend(self, values: List[float]) -> float:
        """Calculate linear trend using least squares."""
        if len(values) < 2:
            return 0.0
        
        n = len(values)
        x = list(range(n))
        
        # Calculate slope using least squares
        sum_x = sum(x)
        sum_y = sum(values)
        sum_xy = sum(x[i] * values[i] for i in range(n))
        sum_x2 = sum(x[i] ** 2 for i in range(n))
        
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x ** 2)
        
        # Normalize by the mean to get percentage change per data point
        mean_value = sum_y / n
        if mean_value != 0:
            return slope / mean_value
        return 0.0
    
    def _calculate_trend_confidence(self, values: List[float]) -> float:
        """Calculate confidence in trend analysis."""
        if len(values) < 3:
            return 0.0
        
        # Calculate R-squared
        n = len(values)
        x = list(range(n))
        
        # Linear regression
        slope = self._calculate_linear_trend(values) * statistics.mean(values)
        intercept = statistics.mean(values) - slope * statistics.mean(x)
        
        # Predicted values
        predicted = [slope * x[i] + intercept for i in range(n)]
        
        # R-squared calculation
        ss_res = sum((values[i] - predicted[i]) ** 2 for i in range(n))
        ss_tot = sum((values[i] - statistics.mean(values)) ** 2 for i in range(n))
        
        r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0
        
        return max(0, min(1, r_squared))  # Clamp between 0 and 1


class QualityAnalyzer:
    """Analyze overall test quality metrics."""
    
    def __init__(self, db: TestResultsDatabase):
        self.db = db
    
    def calculate_quality_metrics(self, days: int = 30) -> QualityMetrics:
        """Calculate comprehensive quality metrics."""
        runs = self.db.get_test_runs(days=days)
        
        if not runs:
            return QualityMetrics(0, 0, 0, 0, 0, "unknown")
        
        # Success rate
        success_rates = [run['success_rate'] for run in runs]
        avg_success_rate = statistics.mean(success_rates)
        
        # Stability score (consistency of success rates)
        stability_score = 1.0 - (statistics.stdev(success_rates) / 100) if len(success_rates) > 1 else 1.0
        stability_score = max(0, min(1, stability_score))
        
        # Performance score (based on duration trends)
        durations = [run['total_duration'] for run in runs if run['total_duration']]
        if durations:
            # Lower and more consistent durations are better
            avg_duration = statistics.mean(durations)
            duration_stability = 1.0 - (statistics.stdev(durations) / avg_duration) if len(durations) > 1 else 1.0
            # Normalize performance score (assume 300s is baseline good duration)
            performance_score = max(0, min(1, (600 - avg_duration) / 600)) * duration_stability
        else:
            performance_score = 0.5
        
        # Reliability score (frequency of successful runs)
        recent_runs = runs[:10]  # Last 10 runs
        recent_success_rate = statistics.mean([run['success_rate'] for run in recent_runs]) if recent_runs else 0
        reliability_score = recent_success_rate / 100
        
        # Overall quality score (weighted average)
        weights = {'success': 0.4, 'stability': 0.2, 'performance': 0.2, 'reliability': 0.2}
        overall_score = (
            weights['success'] * avg_success_rate / 100 +
            weights['stability'] * stability_score +
            weights['performance'] * performance_score +
            weights['reliability'] * reliability_score
        )
        
        # Trend direction
        if len(success_rates) >= 3:
            recent_avg = statistics.mean(success_rates[:3])
            older_avg = statistics.mean(success_rates[-3:])
            if recent_avg > older_avg + 5:
                trend_direction = "improving"
            elif recent_avg < older_avg - 5:
                trend_direction = "degrading"
            else:
                trend_direction = "stable"
        else:
            trend_direction = "stable"
        
        return QualityMetrics(
            success_rate=avg_success_rate,
            stability_score=stability_score * 100,
            performance_score=performance_score * 100,
            reliability_score=reliability_score * 100,
            overall_quality_score=overall_score * 100,
            trend_direction=trend_direction
        )


class TestReportGenerator:
    """Generate comprehensive test reports."""
    
    def __init__(self, db: TestResultsDatabase):
        self.db = db
        self.trend_analyzer = TestTrendAnalyzer(db)
        self.quality_analyzer = QualityAnalyzer(db)
    
    def generate_comprehensive_report(self, days: int = 30) -> Dict[str, Any]:
        """Generate a comprehensive test analytics report."""
        # Get basic data
        runs = self.db.get_test_runs(days=days)
        failure_patterns = self.db.get_failure_patterns(days=days)
        
        # Analyze trends
        success_trend = self.trend_analyzer.analyze_success_rate_trend(days)
        performance_trends = self.trend_analyzer.analyze_performance_trends(days)
        
        # Calculate quality metrics
        quality_metrics = self.quality_analyzer.calculate_quality_metrics(days)
        
        # Generate summary statistics
        if runs:
            total_tests = sum(run['total_tests'] for run in runs)
            total_passed = sum(run['passed_tests'] for run in runs)
            total_failed = sum(run['failed_tests'] for run in runs)
            avg_duration = statistics.mean([run['total_duration'] for run in runs if run['total_duration']])
        else:
            total_tests = total_passed = total_failed = avg_duration = 0
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'analysis_period_days': days,
            'summary': {
                'total_runs': len(runs),
                'total_tests': total_tests,
                'total_passed': total_passed,
                'total_failed': total_failed,
                'overall_success_rate': (total_passed / total_tests * 100) if total_tests > 0 else 0,
                'average_run_duration': avg_duration
            },
            'quality_metrics': {
                'success_rate': quality_metrics.success_rate,
                'stability_score': quality_metrics.stability_score,
                'performance_score': quality_metrics.performance_score,
                'reliability_score': quality_metrics.reliability_score,
                'overall_quality_score': quality_metrics.overall_quality_score,
                'trend_direction': quality_metrics.trend_direction
            },
            'trends': {
                'success_rate': {
                    'direction': success_trend.trend_direction,
                    'magnitude': success_trend.trend_magnitude,
                    'confidence': success_trend.confidence
                },
                'performance_metrics': [
                    {
                        'metric': trend.metric_name,
                        'direction': trend.trend_direction,
                        'magnitude': trend.trend_magnitude,
                        'confidence': trend.confidence
                    }
                    for trend in performance_trends
                ]
            },
            'failure_analysis': failure_patterns,
            'recommendations': self._generate_recommendations(quality_metrics, success_trend, performance_trends, failure_patterns)
        }
        
        return report
    
    def _generate_recommendations(self, quality_metrics: QualityMetrics, 
                                success_trend: TestTrend, 
                                performance_trends: List[TestTrend],
                                failure_patterns: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        # Success rate recommendations
        if quality_metrics.success_rate < 90:
            recommendations.append("🔴 Critical: Success rate is below 90%. Investigate failing tests immediately.")
        elif quality_metrics.success_rate < 95:
            recommendations.append("🟡 Warning: Success rate is below 95%. Review and fix unstable tests.")
        
        # Stability recommendations
        if quality_metrics.stability_score < 80:
            recommendations.append("⚠️  Test results are inconsistent. Focus on improving test reliability.")
        
        # Performance recommendations
        if quality_metrics.performance_score < 70:
            recommendations.append("🐌 Performance: Test execution is slow. Optimize test suite for faster feedback.")
        
        # Trend-based recommendations
        if success_trend.trend_direction == "degrading":
            recommendations.append("📉 Success rate is declining. Review recent changes and fix regressions.")
        
        for trend in performance_trends:
            if trend.trend_direction == "degrading" and trend.confidence > 0.7:
                recommendations.append(f"⏱️  {trend.metric_name} performance is degrading. Investigate performance regressions.")
        
        # Failure pattern recommendations
        if failure_patterns['total_failures'] > 0:
            top_error = max(failure_patterns['error_patterns'].items(), key=lambda x: x[1])
            recommendations.append(f"🔧 Most common error type: {top_error[0]}. Focus on fixing {top_error[0]} issues.")
        
        # General recommendations
        if not recommendations:
            recommendations.append("✅ Test quality is good. Continue monitoring trends.")
        
        return recommendations
    
    def generate_html_report(self, report_data: Dict[str, Any], output_path: str = None):
        """Generate HTML report with visualizations."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"test_analytics_report_{timestamp}.html"
        
        html_content = self._create_html_report(report_data)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
        return output_path
    
    def _create_html_report(self, data: Dict[str, Any]) -> str:
        """Create HTML report content."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VoiceFlow Test Analytics Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .metric-card {{ background: #ecf0f1; padding: 15px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
        .metric-label {{ color: #7f8c8d; font-size: 14px; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .recommendation {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 4px solid #ffc107; }}
        .trend-up {{ color: #27ae60; }}
        .trend-down {{ color: #e74c3c; }}
        .trend-stable {{ color: #7f8c8d; }}
        .quality-excellent {{ color: #27ae60; }}
        .quality-good {{ color: #f39c12; }}
        .quality-poor {{ color: #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #34495e; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>VoiceFlow Test Analytics Report</h1>
            <p>Generated: {data['generated_at']}</p>
            <p>Analysis Period: {data['analysis_period_days']} days</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">{data['summary']['total_runs']}</div>
                    <div class="metric-label">Test Runs</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{data['summary']['overall_success_rate']:.1f}%</div>
                    <div class="metric-label">Success Rate</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{data['quality_metrics']['overall_quality_score']:.1f}%</div>
                    <div class="metric-label">Quality Score</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{data['summary']['average_run_duration']:.1f}s</div>
                    <div class="metric-label">Avg Duration</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Quality Metrics</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">{data['quality_metrics']['stability_score']:.1f}%</div>
                    <div class="metric-label">Stability</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{data['quality_metrics']['performance_score']:.1f}%</div>
                    <div class="metric-label">Performance</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{data['quality_metrics']['reliability_score']:.1f}%</div>
                    <div class="metric-label">Reliability</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value trend-{data['quality_metrics']['trend_direction'].replace('degrading', 'down').replace('improving', 'up')}">{data['quality_metrics']['trend_direction'].title()}</div>
                    <div class="metric-label">Trend</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Failure Analysis</h2>
            <p><strong>Total Failures:</strong> {data['failure_analysis']['total_failures']}</p>
            
            <h3>Most Failing Tests</h3>
            <table>
                <tr><th>Test Name</th><th>Failure Count</th></tr>
"""
        
        for test, count in data['failure_analysis']['most_failing_tests'][:5]:
            html += f"<tr><td>{test}</td><td>{count}</td></tr>"
        
        html += """
            </table>
            
            <h3>Error Patterns</h3>
            <table>
                <tr><th>Error Type</th><th>Count</th></tr>
"""
        
        for error_type, count in data['failure_analysis']['error_patterns'].items():
            html += f"<tr><td>{error_type}</td><td>{count}</td></tr>"
        
        html += """
            </table>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
"""
        
        for recommendation in data['recommendations']:
            html += f'<div class="recommendation">{recommendation}</div>'
        
        html += """
        </div>
        
        <div class="section">
            <h2>Trend Analysis</h2>
            <h3>Success Rate Trend</h3>
            <p><strong>Direction:</strong> <span class="trend-{}">{}</span></p>
            <p><strong>Confidence:</strong> {:.2f}</p>
            
            <h3>Performance Trends</h3>
            <table>
                <tr><th>Metric</th><th>Direction</th><th>Magnitude</th><th>Confidence</th></tr>
""".format(
            data['trends']['success_rate']['direction'].replace('degrading', 'down').replace('improving', 'up'),
            data['trends']['success_rate']['direction'].title(),
            data['trends']['success_rate']['confidence']
        )
        
        for trend in data['trends']['performance_metrics']:
            html += f"""
                <tr>
                    <td>{trend['metric']}</td>
                    <td class="trend-{trend['direction'].replace('degrading', 'down').replace('improving', 'up')}">{trend['direction'].title()}</td>
                    <td>{trend['magnitude']:.4f}</td>
                    <td>{trend['confidence']:.2f}</td>
                </tr>
"""
        
        html += """
            </table>
        </div>
    </div>
</body>
</html>
"""
        
        return html


class TestAnalyticsRunner:
    """Main runner for test analytics."""
    
    def __init__(self, db_path: str = "test_analytics.db"):
        self.db = TestResultsDatabase(db_path)
        self.report_generator = TestReportGenerator(self.db)
    
    def import_test_results(self, results_file: str):
        """Import test results from JSON file."""
        try:
            with open(results_file, 'r') as f:
                data = json.load(f)
            
            run_id = self.db.store_test_run(data)
            logger.info(f"Imported test results to run ID: {run_id}")
            return run_id
            
        except Exception as e:
            logger.error(f"Failed to import test results: {e}")
            return None
    
    def generate_analytics_report(self, days: int = 30, output_format: str = "html"):
        """Generate comprehensive analytics report."""
        report_data = self.report_generator.generate_comprehensive_report(days)
        
        # Save JSON report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"test_analytics_report_{timestamp}.json"
        
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON report saved: {json_path}")
        
        # Generate HTML report if requested
        if output_format.lower() == "html":
            html_path = self.report_generator.generate_html_report(report_data)
            return html_path, json_path
        
        return json_path
    
    def run_continuous_monitoring(self, check_interval_hours: int = 24):
        """Run continuous monitoring and alerting."""
        logger.info(f"Starting continuous monitoring (check every {check_interval_hours} hours)")
        
        while True:
            try:
                # Generate report
                report_data = self.report_generator.generate_comprehensive_report(days=7)
                
                # Check for alerts
                alerts = self._check_alerts(report_data)
                
                if alerts:
                    logger.warning(f"Test quality alerts: {alerts}")
                    # Here you could send notifications, emails, etc.
                
                # Wait for next check
                import time
                time.sleep(check_interval_hours * 3600)
                
            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}")
                import time
                time.sleep(300)  # Wait 5 minutes before retrying
    
    def _check_alerts(self, report_data: Dict[str, Any]) -> List[str]:
        """Check for quality alerts."""
        alerts = []
        
        quality = report_data['quality_metrics']
        
        # Critical alerts
        if quality['success_rate'] < 85:
            alerts.append(f"CRITICAL: Success rate dropped to {quality['success_rate']:.1f}%")
        
        if quality['overall_quality_score'] < 70:
            alerts.append(f"CRITICAL: Overall quality score is {quality['overall_quality_score']:.1f}%")
        
        # Warning alerts
        if quality['stability_score'] < 80:
            alerts.append(f"WARNING: Test stability is low ({quality['stability_score']:.1f}%)")
        
        if quality['trend_direction'] == 'degrading':
            alerts.append("WARNING: Quality trend is degrading")
        
        return alerts


if __name__ == "__main__":
    # Example usage
    analytics = TestAnalyticsRunner()
    
    # Generate report
    report_path = analytics.generate_analytics_report(days=30, output_format="html")
    print(f"Analytics report generated: {report_path}")