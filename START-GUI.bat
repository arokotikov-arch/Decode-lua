@echo off
chcp 65001 >nul
title Активатор Angry Birds — интерфейс в браузере
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

echo Запускаю локальный интерфейс... Браузер откроется автоматически.
echo Чтобы остановить — закройте это окно или нажмите Ctrl+C.
echo.
python ablua.py gui --root "%CD%"
pause
