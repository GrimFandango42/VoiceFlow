import React from 'react';

const RecordingIndicator = ({ isRecording, onToggle }) => {
  return (
    <div className="recording-indicator">
      <button 
        className={`recording-button ${isRecording ? 'recording' : ''}`}
        onClick={onToggle}
      >
        <span className="recording-icon">
          {isRecording ? '⏹️' : '🎙️'}
        </span>
      </button>
      <div className="recording-status">
        {isRecording ? 'Recording...' : 'Click to record'}
      </div>
    </div>
  );
};

export default RecordingIndicator;