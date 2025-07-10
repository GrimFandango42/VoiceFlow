const { app, BrowserWindow, Tray, Menu, globalShortcut } = require('electron');
const path = require('path');
const url = require('url');

let mainWindow;
let tray;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 400,
    height: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: true,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  // Load the app
  const appPath = path.join(__dirname, 'app', 'index.html');
  mainWindow.loadFile(appPath);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform == 'darwin') {
    app.quit();
  }
});
