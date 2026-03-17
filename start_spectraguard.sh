#!/bin/bash
echo "Starting SpectraGuard..."
cd backend
uvicorn main:app --port 8000 --reload &
sleep 2
python local_service.py &
echo "SpectraGuard running. Open http://localhost:5173"
