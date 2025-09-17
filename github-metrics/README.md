# GitHub Metrics Collection API (FastAPI Version)

This is a FastAPI-based implementation of the GitHub metrics collection system with asynchronous capabilities using HTTPX.

## Features

- **Asynchronous Processing**: Uses `httpx` for async HTTP requests
- **RESTful API**: Exposes endpoints for scanning and collecting metrics
- **FastAPI Framework**: Built with FastAPI for automatic API documentation
- **Real-time Metrics**: Collects metrics in real-time
- **Health Check**: Built-in health check endpoint
- **Cron Automation**: Ready for automated execution with cron jobs

## Endpoints

1. **GET `/scan`** - Scan all organization repositories and identify active ones
2. **GET `/metrics`** - Collect detailed metrics for active repositories  
3. **GET `/health`** - Health check endpoint

## Setup Instructions

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Configure environment variables in `.env`:
   ```
   GITHUB_TOKEN=your_github_token_here
   GITHUB_ORGANIZATION=your_organization_name
   ```

3. Run the server:
   ```
   python main.py
   ```

4. Access the API documentation:
   - Open browser to `http://localhost:8000/docs`
   - Or `http://localhost:8000/redoc`

## Automation with Cron Jobs

This system can be automated using cron jobs for regular execution:

### Running the Automation Script

```bash
# Test the automation script manually
python automate_metrics.py
```

This will:
1. Call the `/scan` endpoint to identify active repositories
2. Save the results to `active_repos.json`
3. Call the `/metrics` endpoint to collect detailed metrics
4. Save the results to `metrics_report.json`

### Setting Up Cron Jobs

See `CRON_SETUP.md` for detailed instructions on setting up cron jobs for automated execution.

## Architecture

This implementation follows the same two-script architecture but as a REST API service:

1. **Activity Scanner**: Scans repositories and identifies active ones
2. **Metrics Collector**: Collects detailed metrics from active repositories

The system is designed to be scalable and can handle concurrent requests efficiently thanks to the async nature of FastAPI and HTTPX.

## Error Handling

The API includes proper error handling with meaningful HTTP status codes and error messages.

## Future Enhancements

- Add caching layer for improved performance
- Implement rate limiting
- Add authentication for API endpoints
- Support for database persistence
- Add more sophisticated metrics collection

## Automation Scripts

The following automation scripts are included:

1. `automate_metrics.py` - Main automation script for running the complete cycle
2. `start_server.py` - Script to start the FastAPI server
3. `CRON_SETUP.md` - Detailed instructions for setting up cron jobs

## Usage Examples

### Manual API Calls
```bash
# Scan repositories
curl http://localhost:8000/scan

# Collect metrics
curl http://localhost:8000/metrics

# Health check
curl http://localhost:8000/health
```

### Using the Automation Script
```bash
# Run the complete automation cycle
python automate_metrics.py
```

### Running with Docker
```bash
# Build and run with Docker
docker-compose up --build
```