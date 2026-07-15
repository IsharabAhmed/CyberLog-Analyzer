# Cybersecurity Log Analyzer

A Django-based web platform with ML capabilities that analyzes server and network logs for suspicious activity.

## Features

- **Log Analysis**: Automatically parses Apache, Nginx, Linux Auth, Firewall (UFW/iptables), and SSH logs.
- **Machine Learning Detection**: Uses Isolation Forest for anomaly detection and sliding windows for brute-force attacks.
- **Threat Scoring**: Assigns risk scores based on anomalies, failed auths, known attack signatures (SQLi, XSS, etc.), and time context.
- **Dashboard & Visualization**: Beautiful dark-mode dashboard with Tailwind CSS, Chart.js, and Plotly.js for threat timelines and geo maps.
- **Reporting**: Generate comprehensive CSV and PDF reports.

## Setup Instructions

### Prerequisites
- Python 3.12+
- `uv` package manager

### Manual Setup

If you prefer to run things step-by-step:

1. **Clone and enter the directory**:
   ```bash
   git clone <repo-url>
   cd "Cybersecurity Log Analyzer"
   ```

2. **Sync dependencies using uv**:
   ```bash
   uv sync
   ```

3. **Run database migrations**:
   ```bash
   uv run python manage.py makemigrations
   uv run python manage.py migrate
   ```

4. **Load sample data**:
   This command creates a demo user (`demo` / `demo1234`) and loads realistic sample logs:
   ```bash
   uv run python manage.py load_sample_data
   ```

5. **Run the development server**:
   ```bash
   uv run python manage.py runserver
   ```

6. **Access the application**:
   Open `http://localhost:8000` in your browser.

## Architecture

- **Django Backend**: Handling ORM, routing, and API endpoints.
- **ML Engine**: Custom pipeline with `scikit-learn` and `pandas`.
- **Frontend**: Tailwind CSS (v4 via CDN), Chart.js, Plotly.js.

## Deployment

A `Dockerfile` is provided for containerized deployment. It uses a multi-stage build to package the application with `gunicorn`.

```bash
docker build -t cyberlog .
docker run -p 8000:8000 cyberlog
```
