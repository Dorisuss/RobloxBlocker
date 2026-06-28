@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -c "import pystray, PIL" 2>nul
if errorlevel 1 (
    echo Installing dependencies...
    python -m pip install -r requirements.txt -q
)
for /f "delims=" %%P in ('python -c "import sys,os; print(os.path.join(os.path.dirname(sys.executable),'pythonw.exe'))"') do set PYTHONW=%%P
if not exist "%PYTHONW%" set PYTHONW=python
start "" "%PYTHONW%" "%~dp0app.py"
