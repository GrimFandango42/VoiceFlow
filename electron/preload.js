const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Expose only safe, controlled APIs to the renderer process
  onMenuItemClick: (callback) => ipcRenderer.on('menu-click', callback),
  
  // Voice transcription controls
  startRecording: () => ipcRenderer.invoke('start-recording'),
  stopRecording: () => ipcRenderer.invoke('stop-recording'),
  getTranscription: () => ipcRenderer.invoke('get-transcription'),
  
  // Settings
  updateSettings: (settings) => ipcRenderer.invoke('update-settings', settings),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  
  // Statistics
  getStatistics: () => ipcRenderer.invoke('get-statistics'),
  
  // Security: No direct file system or process access exposed
});