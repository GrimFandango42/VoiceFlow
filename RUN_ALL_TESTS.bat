@echo off
setlocal

echo ================================================
echo VoiceFlow Comprehensive Test Suite
echo ================================================
echo.

cd /d C:\AI_Projects\VoiceFlow

:: Test 1: Backend Tests
echo [1/4] Running backend tests...
if exist "python\venv\Scripts\python.exe" (
    python\venv\Scripts\python.exe test_backend.py
    if %ERRORLEVEL% EQU 0 (
        echo [PASS] Backend tests
    ) else (
        echo [FAIL] Backend tests
    )
) else (
    echo [SKIP] Python environment not found
)

echo.

:: Test 2: Frontend Tests
echo [2/4] Running frontend tests...
node test_frontend.cjs
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Frontend tests
) else (
    echo [FAIL] Frontend tests
)

echo.

:: Test 3: Integration Tests
echo [3/4] Running integration tests...
if exist "python\venv\Scripts\python.exe" (
    python\venv\Scripts\python.exe test_integration.py
    if %ERRORLEVEL% EQU 0 (
        echo [PASS] Integration tests
    ) else (
        echo [FAIL] Integration tests  
    )
) else (
    echo [SKIP] Python environment not found
)

echo.

:: Test 4: Build Verification
echo [4/4] Verifying build outputs...
set BUILD_PASS=0

if exist "dist\index.html" (
    echo [OK] Frontend build found
    set /a BUILD_PASS+=1
) else (
    echo [MISSING] Frontend build
)

if exist "electron\dist\*.exe" (
    echo [OK] Electron build found
    set /a BUILD_PASS+=1
) else (
    echo [MISSING] Electron build
)

if exist "VoiceFlow-Launcher.bat" (
    echo [OK] Launcher script found
    set /a BUILD_PASS+=1
) else (
    echo [MISSING] Launcher script
)

echo.
echo ================================================
echo TEST SUMMARY
echo ================================================
echo.

:: Count test result files
set TEST_FILES=0
if exist "test_results.json" set /a TEST_FILES+=1
if exist "frontend_test_results.json" set /a TEST_FILES+=1
if exist "integration_test_results.json" set /a TEST_FILES+=1

echo Test Results: %TEST_FILES% test suites completed
echo Build Outputs: %BUILD_PASS% components ready

echo.
echo For detailed results, check:
echo - test_results.json (backend)
echo - frontend_test_results.json (frontend)
echo - integration_test_results.json (integration)
echo.

pause