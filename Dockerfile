# =============================================================================
# Multi-stage Dockerfile for Cybersecurity Log Analysis Platform
# =============================================================================

# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /app

# Install uv for fast dependency management
RUN pip install --no-cache-dir uv

# Copy dependency file and install
COPY pyproject.toml .
RUN uv sync --no-dev --frozen

# Stage 2: Production image
FROM python:3.12-slim AS production

WORKDIR /app

# Create non-root user for security
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Copy installed packages from builder
COPY --from=builder /app/.venv /app/.venv

# Ensure virtualenv is on PATH
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy project files
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput --settings=config.settings.production || true

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Run gunicorn
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120"]
