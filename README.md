# Stellar Cyber Coverage Dashboard Streamlit App

This is a Python Streamlit app as a prototype/proof of concept using the Stellar Cyber Public API and the data from https://detections.stellarcyber.ai to calculate coverage and provide data source recommendations as well as simulate the coverage of those recommendations.

## Getting Started

### With Python

1. Clone the repository: `git clone https://github.com/stellarcyber/detection_coverage_app.git`
2. Go to the cloned directory: `cd detection_coverage_app`
3. Install the dependencies: `pip install -r requirements.txt`  or `pip3 install -r requirements.txt`
4. Run the app: `streamlit run app.py`  
   It should open a tab in your browser. (Tested in Chrome)
5. To stop the app: `CTRL-C`

> [!NOTE]
> To make sure you can run `streamlit`, make sure your python bin directory is added to your `PATH`. Alternatively you can use the absolute path to `streamlit` to run it.
> Tested with Python 3.10+

### With Docker

> [!NOTE]
> To simply launch premade image
1. Launch the Docker container: `docker run -p 8501:8501 ghcr.io/stellarcyber/detection_coverage_app/streamlit_coverage_analyzer:latest`
   
> [!NOTE]
> To build image locally

1. Build the Docker image: `docker build -t streamlit_coverage_analyzer .`
2. Launch the Docker container: `docker run -p 8501:8501 streamlit_coverage_analyzer`

## Project Structure

- `app.py`: This file is the entry point of the Streamlit application. It sets up the user interface and the functionality of the app.
- `requirements.txt`: This file lists the dependencies required for the project. It is used by pip to install the dependencies.
- `README.md`: This file contains the documentation for the project. It provides information on how to set up and run the Streamlit app.

## Usage

### Directly with python

1. Run the app: `streamlit run app.py`
2. Follow the instructions on the app to use it.
3. To stop the app: `CTRL-C`

### With Docker
1. Launch the Docker container: `docker run -p 8501:8501 streamlit_coverage_analyzer` or `docker run -p 8501:8501 ghcr.io/stellarcyber/detection_coverage_app/streamlit_coverage_analyzer:latest`
2. To stop the app: `CTRL-C`
