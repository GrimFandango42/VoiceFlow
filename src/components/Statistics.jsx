import React from 'react';

const Statistics = ({ statistics }) => {
  if (!statistics) {
    return (
      <div className="statistics-container">
        <div className="statistics-header">
          <h2>Statistics</h2>
        </div>
        <p>Loading statistics...</p>
      </div>
    );
  }
  
  const formatNumber = (num) => {
    return new Intl.NumberFormat().format(num || 0);
  };
  
  return (
    <div className="statistics-container">
      <div className="statistics-header">
        <h2>Statistics</h2>
        <p>Track your voice transcription usage and performance</p>
      </div>
      
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Today's Words</div>
          <div className="stat-value">{formatNumber(statistics.today.words)}</div>
          <div className="stat-unit">words</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-label">Today's Sessions</div>
          <div className="stat-value">{formatNumber(statistics.today.transcriptions)}</div>
          <div className="stat-unit">transcriptions</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-label">Avg Processing Time</div>
          <div className="stat-value">{Math.round(statistics.today.avg_processing_ms || 0)}</div>
          <div className="stat-unit">ms</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-label">Session Uptime</div>
          <div className="stat-value">{statistics.session.uptime_minutes}</div>
          <div className="stat-unit">minutes</div>
        </div>
      </div>
      
      <div className="stats-section">
        <h3>All Time Statistics</h3>
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-label">Total Words</div>
            <div className="stat-value">{formatNumber(statistics.all_time.words)}</div>
            <div className="stat-unit">words</div>
          </div>
          
          <div className="stat-card">
            <div className="stat-label">Total Sessions</div>
            <div className="stat-value">{formatNumber(statistics.all_time.transcriptions)}</div>
            <div className="stat-unit">transcriptions</div>
          </div>
          
          <div className="stat-card">
            <div className="stat-label">Avg Processing</div>
            <div className="stat-value">{Math.round(statistics.all_time.avg_processing_ms || 0)}</div>
            <div className="stat-unit">ms</div>
          </div>
        </div>
      </div>
      
      <div className="performance-info">
        <h3>Performance Metrics</h3>
        <p>
          Your RTX 4080 is processing at approximately {' '}
          <strong>{Math.round(3000 / (statistics.all_time.avg_processing_ms || 100))}x</strong>
          {' '} real-time speed with Whisper Large v3.
        </p>
      </div>
    </div>
  );
};

export default Statistics;