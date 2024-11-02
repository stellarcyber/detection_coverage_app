# Coverage Analyzer v0.2.0

## Release Information
- **Version:** 0.2.0
- **Release Date:** 2024-11-02
- **Python Compatibility:** ^3.10,<3.14

## Installation

### Pre-built Executables (Recommended)

Download the pre-built executable for your platform from our [GitHub Releases page](https://github.com/stellarcyber/detection_coverage_app/releases):

#### macOS
- Download the `.pkg` installer
- Run the installer package
- The `coverage-analyzer` command will be automatically available in your terminal

#### Windows and Linux (amd64)
- Download the executable and library directory for your platform
- Move both the executable and library directory to your desired location
- Add the location to your system PATH

### Docker (Alternative)

```bash
docker pull ghcr.io/stellarcyber/detection_coverage_app/coverage_analyzer:latest
docker run -p 8501:8501 ghcr.io/stellarcyber/detection_coverage_app/coverage_analyzer:latest
```

Supports both arm64 and amd64 architectures.

### Manual Installation (Development)

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

## Key Features

### New in 0.2.0
- Performance optimizations for data processing
- Enhanced error handling and recovery mechanisms
- Improved type safety throughout codebase
- Comprehensive documentation suite
- Memory optimization for large datasets
- Connection pooling for API requests
- Caching improvements
- Security enhancements

### Core Features
- Coverage analysis dashboard
- MITRE ATT&CK framework integration
- Stellar Cyber API client
- Advanced visualization components
- Robust data processing
- Efficient caching system
- Comprehensive error handling

## Breaking Changes

### API Changes
```python
# Old way
analyzer.get_data()

# New way
analyzer.get_data(validate=True)
```

### Configuration Changes
```python
# Old configuration
{
    "cache": true
}

# New configuration
{
    "cache": {
        "enabled": true,
        "ttl": "1h"
    }
}
```

## Dependencies

### Core Dependencies
- streamlit ^1.39.0
- pandas ^2.2.3
- polars ^1.9.0
- plotly ^5.24.1
- mitreattack-python ^3.0.6
- pydantic ^2.0.0

### Optional Dependencies
- kaleido 0.2.1 (for static image export)
- PyPDF2 ^3.0.1 (for PDF processing)

## Usage

1. Launch the application using any of these methods:
```bash
# Using installed command
coverage-analyzer

# Using streamlit directly
streamlit run app.py

# Using Python script
python run.py
```

For headless environments (e.g., servers):
```bash
coverage-analyzer --headless
```

## Documentation

Comprehensive documentation is available at:
https://stellarcyber.github.io/detection_coverage_app

## Security

This release includes several security enhancements:
- Enhanced input validation
- Improved error handling
- Better token management
- Secure logging implementation
- SSL verification improvements

## Support

- GitHub Issues: Report bugs and feature requests
- Documentation: Comprehensive guides and API reference
- Migration Guide: Available in CHANGELOG.md

## License

Released under MIT License. See LICENSE.md for details.
