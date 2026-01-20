#!/bin/bash
echo "Building DNSTT Manager for Linux..."
echo

python3 -m pip install --upgrade pip
pip3 install paramiko pyinstaller

echo
echo "Building executable..."
pyinstaller --onefile --name "DNSTT-Manager-Linux" --clean dnstt_manager.py

echo
echo "Build complete! Executable is in the dist folder."
echo
