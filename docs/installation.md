# Installation Documentation

## Installation Methods

<!-- ### 1. Pre-built Executables (Recommended)

The fastest and easiest way to get started is by downloading our pre-built executables from the [GitHub Releases page](https://github.com/stellarcyber/detection_coverage_app/releases).

#### macOS
1. Download the `.pkg` installer package
2. Double-click the installer to run it
3. Follow the installation wizard
4. The `coverage-analyzer` command will be automatically available in your terminal

#### Windows (amd64)
1. Download the Windows executable and library directory
2. Move both the executable and library directory to your desired location (e.g., `C:\Program Files\CoverageAnalyzer`)
3. Add the location to your system PATH:
   - Open System Properties > Advanced > Environment Variables
   - Under System Variables, find and select "Path"
   - Click Edit > New
   - Add the path to your executable's directory
   - Click OK to save

#### Linux (amd64)
1. Download the Linux executable and library directory
2. Move both to your desired location (e.g., `/opt/coverage-analyzer/`)
3. Add to your PATH:
   ```bash
   echo 'export PATH="/opt/coverage-analyzer:$PATH"' >> ~/.bashrc
   source ~/.bashrc
   ``` -->

### 1. Manual Installation

For development or customization purposes, you can install from source:

#### Prerequisites
- Python 3.10 or higher (but less than 3.14)
- pip or uv package manager
- Git

#### Installation Steps

=== "Using uv (Recommended)"
    #### Clone repository

    ```bash
    git clone https://github.com/stellarcyber/detection_coverage_app.git
    cd detection_coverage_app
    ```

    #### Install dependencies with uv
    ```bash
    uv sync
    ```

    #### Run with uv
    ```bash
    uv run run.py
    ```

    #### OR
    ```bash
    uv run streamlit run app.py
    ```

=== "Using Pip"
    #### Clone repository
    ```bash
    git clone https://github.com/stellarcyber/detection_coverage_app.git
    cd detection_coverage_app
    ```

    #### Create and activate virtual environment
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # Unix/macOS
    ```

    #### or
    ```bash
    .venv\Scripts\activate     # Windows
    ```

    #### Install dependencies
    ```bash
    pip install -r requirements.txt
    ```

    #### Run using streamlit
    ```bash
    streamlit run app.py
    ```

    #### OR
    ```bash
    python run.py
    ```

### 2. Docker Installation (arm64/amd64)

Our Docker image supports both arm64 and amd64 architectures.

=== "Using Pre-built Image"
    ```bash
    # Pull the image
    docker pull ghcr.io/stellarcyber/detection_coverage_app/coverage_analyzer:latest

    # Run the container
    docker run -p 8501:8501 ghcr.io/stellarcyber/detection_coverage_app/coverage_analyzer:latest
    ```

=== "Building Locally"
    ```bash
    # Build the image
    docker build -t coverage_analyzer .
    
    # Run the container
    docker run -p 8501:8501 coverage_analyzer
    ```



## Running the Application

### GUI Mode (Default)
```bash
# Using installed command
coverage-analyzer

# Using streamlit directly
streamlit run app.py

# Using Python script
python run.py
```
The application will attempt to automatically open your default web browser.

### Headless Mode
For environments without a GUI (e.g., servers):
```bash
coverage-analyzer --headless
```

## System Requirements

Component | Minimum | Recommended
---|---|---
RAM | 4GB | 8GB+
CPU | 2 cores | 4+ cores
Disk Space | 500MB | 1GB+
Internet | Required | Required
Browser | Modern (Chrome recommended) | Latest Chrome


## Verification

After installation:

1. Run the application using any of these methods:
   ```bash
   # Using installed command
   coverage-analyzer

   # Using streamlit
   streamlit run app.py

   # Using Python script
   python run.py
   ```

2. Verify access:
   - GUI mode: Browser should open automatically
   - Headless mode: Navigate to `http://localhost:8501`


## Troubleshooting

### Common Issues

1. **Browser Launch Fails**
   - Use headless mode: `coverage-analyzer --headless`
   - Access via URL: `http://localhost:8501`

2. **Port Conflicts**
   ```bash
   # Check port usage
   lsof -i :8501      # Unix/macOS
   netstat -ano | findstr :8501  # Windows
   
   # Use different port
   export STREAMLIT_SERVER_PORT=8502
   ```

<!-- 3. **Permission Issues**
   - macOS: Verify installer completed successfully
   - Windows/Linux: Check PATH configuration
   - Docker: Ensure proper permissions for port binding

4. **Missing Dependencies**
   - Pre-built executables: Verify library directory is with executable
   - Python install: Check Python version compatibility -->

### Environment Setup

For development installations:

1. Verify Python version:
   ```bash
   python --version  # Should be 3.10+
   ```

2. Check virtual environment:
   ```bash
   # Should show .venv/bin/python
   which python  # Unix/macOS
   where python  # Windows
   ```

<!-- ## Updating

### Pre-built Executables
1. Download latest release
2. Replace existing installation
3. Verify PATH configuration

### Docker
```bash
docker pull ghcr.io/stellarcyber/detection_coverage_app/coverage_analyzer:latest
``` -->


<!-- ## Notes

- Pre-built executables are the recommended installation method
- Docker supports both arm64 and amd64 architectures
- Manual installation is primarily for development
- Keep your installation up to date for latest features and security updates -->
