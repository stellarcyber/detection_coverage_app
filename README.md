# Stellar Cyber Coverage Dashboard Streamlit App

This is a Python Streamlit app as a prototype/proof of concept using the Stellar Cyber Public API and the data from https://detections.stellarcyber.ai to calculate coverage and provide data source recommendations as well as simulate the coverage of those recommendations.

## Getting Started

1. Clone the repository: `git clone https://github.com/stellarcyber/detection_coverage_app.git`
2. Go to the cloned directory: `cd detection_coverage_app`
1. Install the dependencies: `pip install -r requirements.txt`  or `pip3 install -r requirements` 
   [!NOTE]
   To make sure you can run `streamlit`, make sure your python bin directory is added to your `PATH`. Alternatively you can use the absolute path to `streamlit` to run it.
   Tested with Python 3.10+
2. Run the app: `streamlit run app.py`  
   It should open a tab in your browser. (Tested in Chrome)
3. To stop the app: `CTRL-C`

## Project Structure

- `app.py`: This file is the entry point of the Streamlit application. It sets up the user interface and the functionality of the app.
- `requirements.txt`: This file lists the dependencies required for the project. It is used by pip to install the dependencies.
- `README.md`: This file contains the documentation for the project. It provides information on how to set up and run the Streamlit app.

## Usage

1. Run the app: `streamlit run app.py`
2. Follow the instructions on the app to use it.
3. To stop the app: `CTRL-C`
