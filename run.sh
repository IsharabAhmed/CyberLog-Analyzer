#!/bin/bash
echo "[*] Initializing CyberLog Platform..."

echo "[1/4] Syncing dependencies..."
uv sync

echo "[2/4] Running database migrations..."
uv run python manage.py makemigrations
uv run python manage.py migrate

echo "[3/4] Loading sample data..."
uv run python manage.py load_sample_data

echo "[4/4] Starting development server..."
echo "Open http://localhost:8000 in your browser."
echo "Demo Credentials - Username: demo | Password: demo1234"
echo "---------------------------------------------------------"
uv run python manage.py runserver
