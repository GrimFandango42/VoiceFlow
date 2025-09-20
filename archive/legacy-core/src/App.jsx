import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { writeText } from '@tauri-apps/api/clipboard';
import './App.css';

// Components
import RecordingIndicator from './components/RecordingIndicator';
import TranscriptionHistory from './components/TranscriptionHistory';
import Statistics from './components/Statistics';
import Settings from './components/Settings';

function App() {
  const [activeTab, setActiveTab] = useState('live');
  const [isRecording, setIsRecording] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [currentTranscription, setCurrentTranscription] = useState('');
  const [realtimePreview, setRealtimePreview] = useState('');
  const [history, setHistory] = useState([]);
  const [statistics, setStatistics] = useState(null);
  
  const ws = useRef(null);
  const reconnectTimeout = useRef(null);

  // WebSocket connection
  useEffect(() => {
    const connectWebSocket = () => {
      ws.current = new WebSocket('ws://localhost:8765');
      
      ws.current.onopen = () => {
        console.log('Connected to STT server');
        setIsConnected(true);
        // Get initial data
        ws.current.send(JSON.stringify({ type: 'get_history', limit: 20 }));
        ws.current.send(JSON.stringify({ type: 'get_statistics' }));
      };
      
      ws.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
      };
      
      ws.current.onclose = () => {
        console.log('Disconnected from STT server');
        setIsConnected(false);
        // Reconnect after 3 seconds
        reconnectTimeout.current = setTimeout(connectWebSocket, 3000);
      };
      
      ws.current.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
    };
    
    connectWebSocket();
    
    return () => {
      if (ws.current) {
        ws.current.close();
      }
      if (reconnectTimeout.current) {
        clearTimeout(reconnectTimeout.current);
      }
    };
  }, []);

  // Tauri event listeners
  useEffect(() => {
    const setupListeners = async () => {
      // Listen for hotkey press
      const unlistenHotkey = await listen('hotkey-pressed', async () => {
        const recording = await invoke('get_recording_state');
        await invoke('toggle_recording');
      });
      
      // Listen for recording state changes
      const unlistenRecording = await listen('recording-state', (event) => {
        setIsRecording(event.payload);
      });
      
      return () => {
        unlistenHotkey();
        unlistenRecording();
      };
    };
    
    setupListeners();
  }, []);

  const handleWebSocketMessage = (data) => {
    switch (data.type) {
      case 'recording_started':
        setIsRecording(true);
        setRealtimePreview('');
        setCurrentTranscription('');
        break;
        
      case 'recording_stopped':
        setIsRecording(false);
        break;
        
      case 'realtime_preview':
        setRealtimePreview(data.text);
        break;
        
      case 'transcription_complete':
        setCurrentTranscription(data.enhanced_text);
        // Auto-copy to clipboard
        writeText(data.enhanced_text);
        // Simulate text injection (in real app, would use Windows API)
        simulateTextInjection(data.enhanced_text);
        // Add to history
        setHistory(prev => [{
          id: Date.now(),
          timestamp: data.timestamp,
          text: data.enhanced_text,
          wordCount: data.word_count,
          duration: data.duration_ms
        }, ...prev.slice(0, 49)]);
        break;
        
      case 'history':
        setHistory(data.data);
        break;
        
      case 'statistics':
        setStatistics(data.data);
        break;
    }
  };

  const simulateTextInjection = (text) => {
    // In production, this would use Windows SendInput API
    // For now, we just copy to clipboard
    console.log('Text copied to clipboard:', text);
  };

  const handleManualToggle = async () => {
    await invoke('toggle_recording');
  };

  return (
    <div className="app">
      <div className="titlebar" data-tauri-drag-region>
        <div className="titlebar-title">VoiceFlow</div>
        <div className="titlebar-status">
          <span className={`status-dot ${isConnected ? 'connected' : 'disconnected'}`}></span>
          {isConnected ? 'Connected' : 'Disconnected'}
        </div>
      </div>

      <div className="tabs">
        <button 
          className={`tab ${activeTab === 'live' ? 'active' : ''}`}
          onClick={() => setActiveTab('live')}
        >
          Live
        </button>
        <button 
          className={`tab ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          History
        </button>
        <button 
          className={`tab ${activeTab === 'statistics' ? 'active' : ''}`}
          onClick={() => setActiveTab('statistics')}
        >
          Statistics
        </button>
        <button 
          className={`tab ${activeTab === 'settings' ? 'active' : ''}`}
          onClick={() => setActiveTab('settings')}
        >
          Settings
        </button>
      </div>

      <div className="content">
        {activeTab === 'live' && (
          <div className="live-view">
            <RecordingIndicator 
              isRecording={isRecording}
              onToggle={handleManualToggle}
            />
            
            {realtimePreview && (
              <div className="preview-container">
                <h3>Preview</h3>
                <p className="preview-text">{realtimePreview}</p>
              </div>
            )}
            
            {currentTranscription && (
              <div className="transcription-container">
                <h3>Last Transcription</h3>
                <p className="transcription-text">{currentTranscription}</p>
              </div>
            )}
            
            <div className="hotkey-hint">
              Press <kbd>Ctrl</kbd> + <kbd>Alt</kbd> + <kbd>Space</kbd> to toggle recording
            </div>
          </div>
        )}
        
        {activeTab === 'history' && (
          <TranscriptionHistory history={history} />
        )}
        
        {activeTab === 'statistics' && (
          <Statistics statistics={statistics} />
        )}
        
        {activeTab === 'settings' && (
          <Settings />
        )}
      </div>
      
      {/* Floating widget indicator - always visible */}
      <div className="floating-widget" onClick={handleManualToggle}>
        <div className={`widget-indicator ${isRecording ? 'recording' : ''}`}>
          {isRecording ? '🔴' : '🎙️'}
        </div>
      </div>
    </div>
  );
}

export default App;