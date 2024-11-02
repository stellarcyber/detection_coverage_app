> [!IMPORTANT]  
> 11/2/2024: **Important Update**
> Major changes to the application have been made. Please review the updated documentation for the latest information. 


# Coverage Analyzer

A Python Streamlit application for analyzing security coverage using the Stellar Cyber API and MITRE ATT&CK framework. This tool provides comprehensive analysis of current and simulated detection coverage, enabling informed decisions about security posture.

## Quick Start

### Pre-built Executables (Recommended)

Download from our [GitHub Releases page](https://github.com/stellarcyber/detection_coverage_app/releases) and follow the platform-specific installation instructions.

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

### Docker Usage

#### Pull and run container
```bash
docker pull ghcr.io/stellarcyber/detection_coverage_app/coverage_analyzer:latest
docker run -p 8501:8501 coverage_analyzer
```

## Documentation

- [Quickstart Guide](docs/index.md) - Getting started and troubleshooting
- [API Reference](docs/api.md) - Comprehensive API documentation
- [Development Guide](docs/development.md) - Development workflow and testing

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and quality checks
5. Submit a pull request

## License

This project is licensed under the MIT License - see [LICENSE.md](LICENSE.md) for details.

## Acknowledgments

- MITRE ATT&CK® framework
- Stellar Cyber platform
- Open source community
- Streamlit framework
- Python ecosystem

## Support

- Documentation: [docs/](docs/)
- Issues: GitHub Issues
- Community: Discussions
- Professional: Contact maintainers

## Project Status

- Version: 0.2.0
- Status: Active Development
- Python: 3.10+
- Platform: Cross-platform

## Related Projects

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Stellar Cyber](https://stellarcyber.ai/)
- [Streamlit](https://streamlit.io/)
