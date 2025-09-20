@echo off
:: Windows-specific test runner for VoiceFlow
:: This script runs Windows integration tests with proper environment setup

setlocal EnableDelayedExpansion

:: Configuration
set "PROJECT_ROOT=%~dp0"
set "PYTHON=python"
set "TEST_REPORT_DIR=tests\reports"
set "TEST_TEMP_DIR=tests\temp_audio"
set "LOG_FILE=%TEST_REPORT_DIR%\test_run_%DATE:~-4,4%%DATE:~-10,2%%DATE:~-7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.log"

:: Initialize logging
if not exist "%TEST_REPORT_DIR%" mkdir "%TEST_REPORT_DIR%"
if not exist "%TEST_TEMP_DIR%" mkdir "%TEST_TEMP_DIR%"

:: Function to log messages
:log
    echo [%TIME%] %*
    echo [%TIME%] %* >> "%LOG_FILE%"
    exit /b 0

:: Check Python version
for /f "tokens=2 del==" %%v in ('%PYTHON% --version 2^>^&1') do set PYTHON_VERSION=%%v
if "!PYTHON_VERSION!"=="" (
    call :log [ERROR] Python is not installed or not in PATH
    exit /b 1
)
call :log [INFO] Using Python version: !PYTHON_VERSION!

:: ---------------------------------------------------------------------------
:: Smoke-test Windows installer (non-interactive)
:: ---------------------------------------------------------------------------
call :log [INFO] Running installer smoke test (non-interactive)...
call "%PROJECT_ROOT%setup_windows.bat" < nul
if %ERRORLEVEL% NEQ 0 (
    call :log [ERROR] Installer smoke test failed with exit code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)
call :log [INFO] Installer smoke test completed successfully.

:: Set up environment
set "PYTHONPATH=%PROJECT_ROOT%;%PYTHONPATH%"
set "VOICEFLOW_ENV=test"
set "TEST_OUTPUT_DIR=%PROJECT_ROOT%\test_output"

:: Install test dependencies
call :log [INFO] Installing test dependencies...
%PYTHON% -m pip install -q -r requirements_testing.txt
if %ERRORLEVEL% NEQ 0 (
    call :log [ERROR] Failed to install test dependencies
    exit /b 1
)

:: Run tests
call :log [INFO] Starting Windows integration tests...
set "TEST_ARGS=-v --log-cli-level=INFO --junitxml=%TEST_REPORT_DIR%\windows_tests.xml"
set "TEST_ARGS=!TEST_ARGS! --html=%TEST_REPORT_DIR%\test_report.html --self-contained-html"
set "TEST_ARGS=!TEST_ARGS! --cov=voiceflow --cov-report=xml:%TEST_REPORT_DIR%\coverage.xml"
set "TEST_ARGS=!TEST_ARGS! --cov-report=html:%TEST_REPORT_DIR%\coverage_html"

%PYTHON% -m pytest tests !TEST_ARGS! 2>&1 | tee -a "%LOG_FILE%"
set TEST_RESULT=!ERRORLEVEL!

:: Generate test report
if %TEST_RESULT% EQU 0 (
    call :log [SUCCESS] All Windows integration tests passed!
) else (
    call :log [ERROR] Some Windows integration tests failed. Check the logs at: %LOG_FILE%
    call :log [INFO] Test report available at: %TEST_REPORT_DIR%\test_report.html
    call :log [INFO] Coverage report available at: %TEST_REPORT_DIR%\coverage_html\index.html
    exit /b !TEST_RESULT!
)

call :log [INFO] Test execution completed successfully.
call :log [INFO] Test report: %TEST_REPORT_DIR%\test_report.html
call :log [INFO] Coverage report: %TEST_REPORT_DIR%\coverage_html\index.html
exit /b 0
