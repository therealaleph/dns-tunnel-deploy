@echo off
echo Building DNSTT Manager for Windows...
echo.

python -m pip install --upgrade pip
pip install paramiko pyinstaller

echo.
echo Building executable...
pyinstaller --onefile --windowed --name "DNSTT-Manager-Windows" --clean dnstt_manager.py

echo.
echo Build complete! Executable is in the dist folder.
echo.
pause
