#!/bin/bash

# Exit on any error
set -e

echo "Starting Django application on Render..."

# Run database migrations
echo "Running migrations..."
python manage.py migrate --noinput

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Create superuser if it doesn't exist
echo "Creating superuser..."
python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'test@admin.com', '1234')
    print('Superuser created')
else:
    print('Superuser already exists')
"

# Start the application
echo "Starting server..."
exec gunicorn --bind 0.0.0.0:$PORT core.wsgi:application --workers 2
