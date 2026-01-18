@echo off
setlocal

REM ============================================================================
REM This batch file is for LOCAL DEVELOPMENT on Windows ONLY.
REM Running a production server on Windows is a critical operational risk.
REM Ensure your production environment (Linux) is your primary testing target.
REM ============================================================================

echo Starting VPN Auth Server for Development...

REM --- Check for virtual environment ---
IF NOT EXIST ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found at '.\.venv'.
    echo Please create it first: python -m venv .venv
    exit /b 1
)

REM --- Activate virtual environment ---
echo Activating virtual environment...
call .venv\Scripts\activate


REM --- Set Flask application entry point ---
set FLASK_APP=app.py

echo Launching with Waitress on port 5000...
echo Visit http://127.0.0.1:5000 in your browser.

REM --- Run the WSGI server ---
REM Waitress is an acceptable pure-Python server for Windows development.
waitress-serve --host=127.0.0.1 --port=5000 app:app

endlocal