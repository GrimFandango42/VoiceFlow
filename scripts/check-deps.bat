@echo off
echo ============================================
echo VoiceFlow Build Prerequisites Check
echo ============================================
echo.

set missing_deps=0

:: Check Rust
echo Checking Rust...
rustc --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ ] Rust - NOT INSTALLED
    echo     Download from: https://rustup.rs/
    set missing_deps=1
) else (
    echo [✓] Rust - INSTALLED
    rustc --version
)

echo.

:: Check Node.js
echo Checking Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ ] Node.js - NOT INSTALLED
    echo     Download from: https://nodejs.org/
    set missing_deps=1
) else (
    echo [✓] Node.js - INSTALLED
    node --version
)

echo.

:: Check npm
echo Checking npm...
npm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ ] npm - NOT INSTALLED
    set missing_deps=1
) else (
    echo [✓] npm - INSTALLED
    npm --version
)

echo.

:: Check for Microsoft C++ Build Tools
echo Checking C++ Build Tools...
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo [?] Microsoft C++ Build Tools - POSSIBLY MISSING
    echo     If build fails, download from:
    echo     https://visualstudio.microsoft.com/visual-cpp-build-tools/
) else (
    echo [✓] C++ Build Tools - FOUND
)

echo.

:: Check WebView2
echo Checking WebView2...
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" >nul 2>&1
if %errorlevel% neq 0 (
    echo [?] WebView2 - POSSIBLY MISSING
    echo     Usually installed with Windows updates
    echo     Manual download: https://developer.microsoft.com/microsoft-edge/webview2/
) else (
    echo [✓] WebView2 - INSTALLED
)

echo.
echo ============================================

if %missing_deps% equ 1 (
    echo.
    echo Some dependencies are missing!
    echo Please install them before building.
    echo.
) else (
    echo.
    echo All core dependencies found!
    echo You can run COMPLETE_BUILD.bat to build the app.
    echo.
)

pause