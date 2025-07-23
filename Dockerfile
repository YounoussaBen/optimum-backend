# syntax=docker/dockerfile:1.4

##########################################
# Stage 1: Builder
##########################################
FROM python:3.10-slim AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Set workdir
WORKDIR /app

# Copy project metadata
COPY pyproject.toml uv.lock ./

# Install dependencies to system Python (alternative approach)
RUN uv pip install --system -r pyproject.toml

# Copy only necessary code for building packages
COPY core core
COPY apps apps

##########################################
# Stage 2: Production
##########################################
FROM python:3.10-slim AS production

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN groupadd -r django && useradd -r -g django django

# Set workdir
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy rest of the code
COPY . .

# Make startup script executable
RUN chmod +x /app/startup.sh

# Set correct permissions
RUN mkdir -p /app/staticfiles /app/media /app/logs && \
    chown -R django:django /app

# Final user
USER django

# Set Django settings for production
ENV DJANGO_SETTINGS_MODULE=core.settings.prod \
    DEBUG=False \
    PYTHONPATH=/app

# Default command
CMD ["/app/startup.sh"]
