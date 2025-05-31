@echo off
setlocal

echo ================================================
echo Creating Electron-based VoiceFlow App
echo ================================================
echo.

cd /d C:\AI_Projects\VoiceFlow

:: Create electron directory
if not exist "electron" mkdir electron

:: Create package.json for Electron
echo Creating Electron configuration...
(
echo {
echo   "name": "voiceflow-electron",
echo   "version": "1.0.0",
echo   "main": "main.js",
echo   "scripts": {
echo     "start": "electron .",
echo     "build": "electron-builder",
echo     "dist": "electron-builder --win"
echo   },
echo   "devDependencies": {
echo     "electron": "^28.0.0",
echo     "electron-builder": "^24.9.1"
echo   },
echo   "build": {
echo     "appId": "com.voiceflow.app",
echo     "productName": "VoiceFlow",
echo     "directories": {
echo       "output": "dist"
echo     },
echo     "win": {
echo       "target": "portable",
echo       "icon": "../src-tauri/icons/icon.ico"
echo     }
echo   }
echo }
) > electron\package.json

:: Create main.js for Electron
echo Creating Electron main process...
(
echo const { app, BrowserWindow, Tray, Menu, globalShortcut } = require('electron'^);
echo const path = require('path'^);
echo.
echo let mainWindow;
echo let tray;
echo.
echo function createWindow(^) {
echo   mainWindow = new BrowserWindow({
echo     width: 400,
echo     height: 600,
echo     webPreferences: {
echo       nodeIntegration: true,
echo       contextIsolation: false
echo     },
echo     icon: path.join(__dirname, '..', 'src-tauri', 'icons', 'icon.ico'^)
echo   }^);
echo.
echo   mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'^)^);
echo.
echo   mainWindow.on('close', (event^) =^> {
echo     event.preventDefault(^);
echo     mainWindow.hide(^);
echo   }^);
echo }
echo.
echo function createTray(^) {
echo   tray = new Tray(path.join(__dirname, '..', 'src-tauri', 'icons', 'icon.ico'^)^);
echo   
echo   const contextMenu = Menu.buildFromTemplate([
echo     { label: 'Show', click: (^) =^> mainWindow.show(^) },
echo     { label: 'Hide', click: (^) =^> mainWindow.hide(^) },
echo     { type: 'separator' },
echo     { label: 'Toggle Recording', click: (^) =^> console.log('Toggle'^) },
echo     { type: 'separator' },
echo     { label: 'Quit', click: (^) =^> app.quit(^) }
echo   ]^);
echo   
echo   tray.setContextMenu(contextMenu^);
echo   tray.on('click', (^) =^> {
echo     mainWindow.isVisible(^) ? mainWindow.hide(^) : mainWindow.show(^);
echo   }^);
echo }
echo.
echo app.whenReady(^).then((^) =^> {
echo   createWindow(^);
echo   createTray(^);
echo   
echo   globalShortcut.register('CommandOrControl+Alt+Space', (^) =^> {
echo     mainWindow.webContents.send('hotkey-pressed'^);
echo   }^);
echo   
echo   mainWindow.hide(^);
echo }^);
echo.
echo app.on('window-all-closed', (^) =^> {
echo   if (process.platform !== 'darwin'^) {
echo     app.quit(^);
echo   }
echo }^);
) > electron\main.js

:: Install Electron dependencies
echo.
echo Installing Electron dependencies...
cd electron
call npm install electron@latest --save-dev

:: Create start script
echo.
echo Creating start script...
(
echo @echo off
echo cd /d C:\AI_Projects\VoiceFlow\electron
echo npm start
) > ..\START_ELECTRON.bat

:: Create portable exe
echo.
echo Building portable executable...
call npm run dist

cd ..

echo.
echo ================================================
echo Electron App Created!
echo ================================================
echo.
echo To run the app:
echo   START_ELECTRON.bat
echo.
echo Portable executable will be in:
echo   electron\dist\
echo.
pause