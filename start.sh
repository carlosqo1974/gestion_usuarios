#!/bin/bash
# Script de arranque para pm2 — activa el venv y lanza Flask
cd "$(dirname "$0")"
source venv/bin/activate
exec python app.py
