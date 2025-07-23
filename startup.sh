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

# Create necessary directories
mkdir -p /app/static
mkdir -p /app/staticfiles

# Run migrations
echo "Running migrations..."
python manage.py migrate --noinput

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Creating superuser if needed..."
# Use the custom management command instead of shell
python manage.py create_superuser

python manage.py createcachetable

# Start gunicorn server
echo "Starting gunicorn on host 0.0.0.0 port $PORT"
exec gunicorn core.wsgi:application --bind 0.0.0.0:${PORT} --workers 2
