@echo off
echo ==========================================
echo   ShubhaGuard - Phishing URL Detector
echo ==========================================
echo.
if not exist venv (
  echo Creating virtual environment...
  python -m venv venv
)
call venv\Scripts\activate.bat
echo Installing requirements...
python -m pip install -r requirements.txt
echo.
echo Starting server...
echo Open http://127.0.0.1:5000 in your browser.
echo Press Ctrl+C to stop.
python app.py
pause
