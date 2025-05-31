@echo off
setlocal enabledelayedexpansion

echo ================================================
echo VoiceFlow Step-by-Step Build
echo ================================================
echo.

cd /d C:\AI_Projects\VoiceFlow

:: Set paths
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
set RUST_BACKTRACE=1

:: Step 1: Verify Rust
echo [STEP 1] Verifying Rust installation...
cargo --version >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: Cargo not found. Please install Rust from https://rustup.rs/
    echo Opening Rust installer page...
    start https://rustup.rs/
    pause
    exit /b 1
)
cargo --version
echo.

:: Step 2: Install Tauri CLI globally via Cargo
echo [STEP 2] Ensuring Tauri CLI is installed...
cargo install tauri-cli --version ^1.6.3 2>nul
echo.

:: Step 3: Check frontend dependencies
echo [STEP 3] Checking Node.js dependencies...
if not exist "node_modules" (
    echo Installing npm dependencies...
    npm install
) else (
    echo Dependencies already installed.
)
echo.

:: Step 4: Build frontend
echo [STEP 4] Building frontend...
if exist "dist" rmdir /s /q dist
npm run build
if not exist "dist\index.html" (
    echo ERROR: Frontend build failed!
    pause
    exit /b 1
)
echo Frontend built successfully.
echo.

:: Step 5: Build Tauri app using cargo directly
echo [STEP 5] Building Tauri application...
echo This may take several minutes on first build...
echo.

cargo tauri build

:: Step 6: Check results
echo.
echo [STEP 6] Checking build results...
echo.

set found=0
if exist "src-tauri\target\release\VoiceFlow.exe" (
    echo ✓ SUCCESS! Found executable:
    echo   %CD%\src-tauri\target\release\VoiceFlow.exe
    dir "src-tauri\target\release\VoiceFlow.exe"
    set found=1
)

if exist "src-tauri\target\release\voiceflow.exe" (
    echo ✓ SUCCESS! Found executable:
    echo   %CD%\src-tauri\target\release\voiceflow.exe
    dir "src-tauri\target\release\voiceflow.exe"
    set found=1
)

if !found! equ 0 (
    echo ✗ No release executable found.
    echo.
    echo Checking for debug build...
    if exist "src-tauri\target\debug\VoiceFlow.exe" (
        echo Found debug build: src-tauri\target\debug\VoiceFlow.exe
        set found=1
    )
    if exist "src-tauri\target\debug\voiceflow.exe" (
        echo Found debug build: src-tauri\target\debug\voiceflow.exe
        set found=1
    )
)

if !found! equ 0 (
    echo.
    echo Build appears to have failed. Checking for error details...
    echo.
    echo Contents of src-tauri\target\release:
    dir "src-tauri\target\release" 2>nul
    echo.
    echo Would you like to try a debug build instead? (Y/N)
    set /p debug_choice=
    if /i "!debug_choice!"=="Y" (
        echo.
        echo Building debug version...
        cargo tauri build --debug
    )
)

echo.
echo ================================================
echo Build process complete.
echo ================================================
pause