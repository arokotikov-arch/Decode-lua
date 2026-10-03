@echo off
rem Запуск с правами администратора: нужен, если игра стоит в Program Files.
chcp 65001 >nul
title Активатор PC-версий Angry Birds (администратор)
cd /d "%~dp0"

net session >nul 2>nul
if errorlevel 1 (
  echo Запрашиваю права администратора...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>nul
  if errorlevel 1 (
    echo.
    echo [!] Не удалось получить права администратора.
    echo     Запустите файл правым кликом -^> "Запуск от имени администратора".
    echo.
    pause
  )
  exit /b
)

where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo [!] Python не найден. Установите Python 3 с https://www.python.org/downloads/
  echo.
  pause
  exit /b 1
)

python ablua.py wizard
pause
