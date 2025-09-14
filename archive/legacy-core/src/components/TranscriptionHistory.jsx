import React from 'react';
import { writeText } from '@tauri-apps/api/clipboard';

const TranscriptionHistory = ({ history }) => {
  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)} minutes ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
    
    return date.toLocaleDateString();
  };
  
  const formatDuration = (ms) => {
    const seconds = Math.floor(ms / 1000);
    return `${seconds}s`;
  };
  
  const handleCopy = async (text) => {
    await writeText(text);
    // Could show a toast notification here
  };
  
  return (
    <div className="history-container">
      <div className="history-header">
        <h2>Transcription History</h2>
      </div>
      
      <div className="history-list">
        {history.length === 0 ? (
          <div className="empty-state">
            <p>No transcriptions yet. Press Ctrl+Alt+Space to start recording!</p>
          </div>
        ) : (
          history.map((item) => (
            <div key={item.id} className="history-item">
              <div className="history-item-header">
                <span className="history-timestamp">
                  {formatTimestamp(item.timestamp)}
                </span>
                <div className="history-meta">
                  <span>{item.wordCount} words</span>
                  <span>{formatDuration(item.duration)}</span>
                </div>
              </div>
              
              <p className="history-text">{item.text}</p>
              
              <div className="history-actions">
                <button 
                  className="history-action"
                  onClick={() => handleCopy(item.text)}
                >
                  Copy
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default TranscriptionHistory;