@echo off
chcp 65001 >nul
title Активатор PC-версий Angry Birds
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo [!] Python не найден.
  echo     Установите Python 3 с https://www.python.org/downloads/
  echo     При установке отметьте галочку "Add Python to PATH".
  echo.
  pause
  exit /b 1
)

python ablua.py wizard
pause
