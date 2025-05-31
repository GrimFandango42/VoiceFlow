@echo off
echo Cleaning up redundant files...

:: Remove old batch files
if exist "build.bat" del "build.bat"
if exist "build.ps1" del "build.ps1"
if exist "build_app.bat" del "build_app.bat"
if exist "BUILD_RELEASE.bat" del "BUILD_RELEASE.bat"
if exist "BUILD_NOW.bat" del "BUILD_NOW.bat"
if exist "COMPLETE_BUILD.bat" del "COMPLETE_BUILD.bat"
if exist "complete_setup.ps1" del "complete_setup.ps1"
if exist "dev.ps1" del "dev.ps1"
if exist "fix_dependencies.bat" del "fix_dependencies.bat"
if exist "launch.bat" del "launch.bat"
if exist "run.bat" del "run.bat"
if exist "setup.ps1" del "setup.ps1"
if exist "SETUP_CHECK.bat" del "SETUP_CHECK.bat"
if exist "setup_ollama_wsl.sh" del "setup_ollama_wsl.sh"

:: Remove temporary files
if exist "create-icon.js" del "create-icon.js"
if exist "build_output.txt" del "build_output.txt"

:: Remove rust installer if build is complete
if exist "src-tauri\target\release\voiceflow.exe" (
    if exist "rustup-init.exe" del "rustup-init.exe"
)

echo Cleanup complete!
echo.
echo Remaining structure:
echo - BUILD.bat         (Build the app)
echo - RUN.bat          (Run the app)
echo - dev.bat          (Development mode)
echo - setup.bat        (Initial setup)
echo - scripts\         (All utility scripts)
echo - docs\            (All documentation)