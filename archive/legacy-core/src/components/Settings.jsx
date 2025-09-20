import React, { useState } from 'react';

const Settings = () => {
  const [settings, setSettings] = useState({
    autoStart: true,
    minimizeToTray: true,
    copyToClipboard: true,
    autoInject: true,
    model: 'large-v3',
    language: 'en',
    enhanceWithAI: true,
    hotkey: 'Ctrl+Alt+Space'
  });
  
  const handleToggle = (key) => {
    setSettings(prev => ({
      ...prev,
      [key]: !prev[key]
    }));
  };
  
  return (
    <div className="settings-container">
      <div className="settings-section">
        <h3>General Settings</h3>
        
        <div className="setting-item">
          <div className="setting-label">
            <span>Start with Windows</span>
            <small>Launch VoiceFlow when Windows starts</small>
          </div>
          <label className="toggle">
            <input 
              type="checkbox" 
              checked={settings.autoStart}
              onChange={() => handleToggle('autoStart')}
            />
            <span className="toggle-slider"></span>
          </label>
        </div>
        
        <div className="setting-item">
          <div className="setting-label">
            <span>Minimize to System Tray</span>
            <small>Hide in system tray when closed</small>
          </div>
          <label className="toggle">
            <input 
              type="checkbox" 
              checked={settings.minimizeToTray}
              onChange={() => handleToggle('minimizeToTray')}
            />
            <span className="toggle-slider"></span>
          </label>
        </div>
      </div>
      
      <div className="settings-section">
        <h3>Transcription Settings</h3>
        
        <div className="setting-item">
          <div className="setting-label">
            <span>Auto Copy to Clipboard</span>
            <small>Automatically copy transcribed text</small>
          </div>
          <label className="toggle">
            <input 
              type="checkbox" 
              checked={settings.copyToClipboard}
              onChange={() => handleToggle('copyToClipboard')}
            />
            <span className="toggle-slider"></span>
          </label>
        </div>
        
        <div className="setting-item">
          <div className="setting-label">
            <span>Auto Text Injection</span>
            <small>Automatically type transcribed text</small>
          </div>
          <label className="toggle">
            <input 
              type="checkbox" 
              checked={settings.autoInject}
              onChange={() => handleToggle('autoInject')}
            />
            <span className="toggle-slider"></span>
          </label>
        </div>
        
        <div className="setting-item">
          <div className="setting-label">
            <span>AI Enhancement</span>
            <small>Use DeepSeek for formatting and corrections</small>
          </div>
          <label className="toggle">
            <input 
              type="checkbox" 
              checked={settings.enhanceWithAI}
              onChange={() => handleToggle('enhanceWithAI')}
            />
            <span className="toggle-slider"></span>
          </label>
        </div>
      </div>
      
      <div className="settings-section">
        <h3>Model Settings</h3>
        
        <div className="setting-item">
          <div className="setting-label">
            <span>Whisper Model</span>
            <small>Larger models are more accurate but slower</small>
          </div>
          <select 
            value={settings.model}
            onChange={(e) => setSettings({...settings, model: e.target.value})}
            className="setting-select"
          >
            <option value="tiny">Tiny (39M)</option>
            <option value="base">Base (74M)</option>
            <option value="small">Small (244M)</option>
            <option value="medium">Medium (769M)</option>
            <option value="large-v3">Large v3 (1550M)</option>
          </select>
        </div>
        
        <div className="setting-item">
          <div className="setting-label">
            <span>Language</span>
            <small>Primary language for transcription</small>
          </div>
          <select 
            value={settings.language}
            onChange={(e) => setSettings({...settings, language: e.target.value})}
            className="setting-select"
          >
            <option value="en">English</option>
            <option value="es">Spanish</option>
            <option value="fr">French</option>
            <option value="de">German</option>
            <option value="it">Italian</option>
            <option value="pt">Portuguese</option>
            <option value="ru">Russian</option>
            <option value="zh">Chinese</option>
            <option value="ja">Japanese</option>
            <option value="ko">Korean</option>
          </select>
        </div>
      </div>
      
      <div className="settings-section">
        <h3>Hotkey Configuration</h3>
        
        <div className="setting-item">
          <div className="setting-label">
            <span>Recording Hotkey</span>
            <small>Global shortcut to toggle recording</small>
          </div>
          <div className="hotkey-display">
            <kbd>Ctrl</kbd> + <kbd>Alt</kbd> + <kbd>Space</kbd>
          </div>
        </div>
      </div>
      
      <div className="settings-info">
        <h3>System Information</h3>
        <div className="info-grid">
          <div className="info-item">
            <span className="info-label">GPU:</span>
            <span className="info-value">NVIDIA RTX 4080 (16GB)</span>
          </div>
          <div className="info-item">
            <span className="info-label">CPU:</span>
            <span className="info-value">AMD Ryzen 7 5800X3D</span>
          </div>
          <div className="info-item">
            <span className="info-label">Whisper Backend:</span>
            <span className="info-value">CUDA (GPU Accelerated)</span>
          </div>
          <div className="info-item">
            <span className="info-label">DeepSeek Model:</span>
            <span className="info-value">deepseek-r1:14b via Ollama</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;