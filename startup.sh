#!/bin/bash
# render_deploy.sh - Complete deployment script for Render

set -e  # Exit on any error

echo "Starting Django application on Render..."

# Create necessary directories
mkdir -p /app/static
mkdir -p /app/staticfiles

echo "Running migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Creating superuser if needed..."
# Use the custom management command instead of shell
python manage.py create_superuser

python manage.py createcachetable

# Start the application
echo "Starting server..."
exec gunicorn --bind 0.0.0.0:$PORT core.wsgi:application --workers 2
