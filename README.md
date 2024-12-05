> [!IMPORTANT]  
> 11/2/2024: **Important Update**
> Major changes to the application have been made. Please review the updated documentation for the latest information.

# Coverage Analyzer

A Python Streamlit application for analyzing security coverage using the Stellar Cyber API and MITRE ATT&CK framework. This tool provides comprehensive analysis of current and simulated detection coverage, enabling informed decisions about security posture.

## Quick Start

### Python Installation

---

#### Using uv (Highly Recommended)

---

##### Install uv

If you don't already have `uv` installed, you can follow instructions [here](https://docs.astral.sh/uv/getting-started/installation/)

---

##### Download and Run or Install

1. Clone repository

   ```bash
   git clone https://github.com/stellarcyber/detection_coverage_app.git
   ```

2. Change directory to the project directory

   ```bash
   cd detection_coverage_app
   ```

3. To just run the app:

   ```bash
   uv run coverage-analyzer
   ```

   OR

   ```bash
   uv run run.py
   ```

   OR

   ```bash
   uv run streamlit run app.py
   ```

4. To install the app globally as a CLI tool (make sure to run within the project directory):
   ```bash
   uv tool install --editable ./
   ```
   When completed, you can run the app from anywhere in your terminal (not just within the project directory):
   ```bash
   coverage-analyzer
   ```
   OR
   ```bash
   coverage-analyzer --headless
   ```

---

##### Additional Info

- If for any reason after using the `uv tool install` command you want to uninstall the app, you can do so by running:

  ```bash
  uv tool uninstall coverage-analyzer
  ```

- If you run into an issue after installing globally where the command is not found, you can run the following to ensure the uv tools dir is in your PATH:
  ```bash
  uv tool update-shell
  ```

#### Using Pip

---

1. Clone repository

   ```bash
   git clone https://github.com/stellarcyber/detection_coverage_app.git
   cd detection_coverage_app
   ```

2. Create and activate virtual environment

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

   or for Windows

   ```bash
   .venv\Scripts\activate
   ```

3. Install dependencies

   ```bash
   pip install -r requirements.txt
   ```

4. Run using streamlit
   ```bash
   streamlit run app.py
   ```
   OR
   ```bash
   python run.py
   ```

### Docker Usage

---

#### Build and run container

```bash
docker build -t coverage_analyzer .
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
