@echo off
echo ================================================
echo VoiceFlow Build Diagnostics
echo ================================================
echo.

cd /d C:\AI_Projects\VoiceFlow

echo [1] Checking Node.js...
node --version
npm --version
echo.

echo [2] Checking Rust (with explicit path)...
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
rustc --version
cargo --version
echo.

echo [3] Checking npm packages...
npm list @tauri-apps/cli
echo.

echo [4] Checking frontend build output...
if exist "dist\index.html" (
    echo ✓ Frontend built successfully
    dir dist
) else (
    echo ✗ Frontend not built. Running npm run build...
    npm run build
)
echo.

echo [5] Checking Tauri configuration...
if exist "src-tauri\tauri.conf.json" (
    echo ✓ Tauri config found
    type src-tauri\tauri.conf.json | findstr /C:"productName" /C:"identifier"
) else (
    echo ✗ Tauri config missing!
)
echo.

echo [6] Attempting minimal Rust build test...
cd src-tauri
echo Testing Cargo build...
cargo check
echo.

echo [7] Checking for build errors...
if exist "target\debug\build" (
    echo Build artifacts found. Looking for error logs...
    dir target\debug\build\*.txt 2>nul
)

cd ..
echo.
echo ================================================
echo Diagnostics complete. Review output above.
echo ================================================
pause