@echo off
setlocal

cd /d C:\AI_Projects\VoiceFlow

echo ================================================
echo VoiceFlow Build Script - Fixed Version
echo ================================================
echo.

:: Set up Rust path explicitly
set PATH=%USERPROFILE%\.cargo\bin;%PATH%

:: Verify Rust is available
echo Checking Rust installation...
rustc --version
if %errorlevel% neq 0 (
    echo ERROR: Rust not found!
    echo Please ensure Rust is installed from https://rustup.rs/
    pause
    exit /b 1
)
cargo --version
echo.

:: Check for Tauri CLI
echo Checking for Tauri CLI...
cargo tauri --version 2>nul
if %errorlevel% neq 0 (
    echo Tauri CLI not found. Installing...
    cargo install tauri-cli
)
echo.

:: Build frontend first
echo [1/2] Building frontend...
call npm run build
if %errorlevel% neq 0 (
    echo ERROR: Frontend build failed!
    echo Make sure you have run 'npm install' first.
    pause
    exit /b 1
)

echo.
echo [2/2] Building Tauri application...
echo This may take 5-15 minutes on first build...
echo.

:: Build with cargo directly since npx might have issues
cd src-tauri
cargo build --release
if %errorlevel% neq 0 (
    echo.
    echo Build failed! Trying with more verbose output...
    cargo build --release --verbose
    pause
    exit /b 1
)
cd ..

echo.
echo ================================================
echo Checking for executable...
echo ================================================

if exist "src-tauri\target\release\voiceflow.exe" (
    echo SUCCESS! Executable found at:
    echo   %CD%\src-tauri\target\release\voiceflow.exe
    echo.
    dir "src-tauri\target\release\*.exe"
) else (
    echo WARNING: Expected executable not found.
    echo Checking for any .exe files...
    dir "src-tauri\target\release\*.exe" 2>nul
    if %errorlevel% neq 0 (
        echo No executables found in release directory.
        echo.
        echo Checking debug directory...
        dir "src-tauri\target\debug\*.exe" 2>nul
    )
)

echo.
pause