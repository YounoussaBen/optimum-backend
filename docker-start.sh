#!/bin/bash

# Debug environment
echo "=== DEBUG: Environment variables ==="
echo "PORT environment variable: '$PORT'"
env | grep PORT
echo "===================================="

# Ensure PORT environment variable is set
if [ -z "$PORT" ]; then
    echo "WARNING: PORT not set, defaulting to 8000"
    export PORT=8000
fi

echo "Starting Django app on port: $PORT"

# Run migrations
echo "Running migrations..."
python manage.py migrate --noinput

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Start gunicorn server
echo "Starting gunicorn on host 0.0.0.0 port $PORT"
exec gunicorn core.wsgi:application --bind 0.0.0.0:${PORT} --workers 2
