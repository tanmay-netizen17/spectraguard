@echo off
title SpectraGuard
echo Starting SpectraGuard...

start "SpectraGuard Backend" /min cmd /c "cd backend && uvicorn main:app --port 8000 --reload"
timeout /t 2 /nobreak >nul

start "SpectraGuard Local Service" /min cmd /c "cd backend && python local_service.py"
timeout /t 1 /nobreak >nul

start "" "http://localhost:5173"
echo SpectraGuard is running. Check system tray.
pause
