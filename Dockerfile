# Use Python slim image for smaller size
FROM python:3.10-slim-buster

# Create non-root user for security
RUN useradd -m -r appuser

# Install system dependencies and clean up in one layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory and change ownership
WORKDIR /app
RUN chown appuser:appuser /app

# Switch to non-root user
USER appuser

# Install Python dependencies
COPY --chown=appuser:appuser requirements.txt /app/
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser app.py /app/
COPY --chown=appuser:appuser coverage_analyzer/ /app/coverage_analyzer/

# Set environment variables
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_HEADLESS=true \
    PATH="/home/appuser/.local/bin:${PATH}"

# Expose port
EXPOSE 8501

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

# Run app
ENTRYPOINT ["streamlit", "run", "app.py"]
