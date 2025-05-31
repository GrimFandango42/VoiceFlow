@echo off
setlocal

echo ================================================
echo VoiceFlow - Installing Missing Dependencies
echo ================================================
echo.

cd /d C:\AI_Projects\VoiceFlow

echo The build is failing because Microsoft C++ Build Tools are not installed.
echo This is required for building Rust applications on Windows.
echo.
echo You have two options:
echo.
echo 1. Install Visual Studio Build Tools (Recommended)
echo    - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
echo    - During installation, select "Desktop development with C++"
echo    - This will install the necessary C++ compiler and linker
echo.
echo 2. Use the pre-built executable (if available)
echo    - Check the GitHub releases page
echo.
echo Would you like to open the download page? (Y/N)
set /p choice=
if /i "%choice%"=="Y" (
    start https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo.
    echo After installing Visual Studio Build Tools:
    echo 1. Restart your computer
    echo 2. Run BUILD_STEP_BY_STEP.bat again
)

echo.
echo ================================================
echo Alternative: Try building with npm/npx
echo ================================================
echo.
echo Let me try using the Node.js version of Tauri CLI...
echo.

:: Ensure npm packages are installed
npm install

:: Try using npx to run tauri
echo.
echo Attempting build with npx...
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
npx tauri build

echo.
echo If this also fails, you'll need to install Visual Studio Build Tools.
echo.
pause