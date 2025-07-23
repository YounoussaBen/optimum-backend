#!/bin/bash

# Ensure PORT environment variable is set
if [ -z "$PORT" ]; then
    export PORT=8000
fi

echo "Starting Django app on port $PORT"

# Run migrations
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

# Start uvicorn server
exec uvicorn core.asgi:application --host 0.0.0.0 --port $PORT
