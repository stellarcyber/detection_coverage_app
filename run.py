"""
This script launches the Stellar Cyber Coverage Analyzer Streamlit app.
It supports running the app in headless mode and provides CLI sub-commands for advanced usage.
"""

__version__ = "0.0.1"

import argparse
import sys
from pathlib import Path

from rich import print as rich_print
from streamlit.web import cli as stcli


def launch_streamlit_app(headless: bool | None = None) -> None:
    """
    Launch the Streamlit app with the specified arguments.

    Args:
            headless (Optional[bool]): Whether to run the Streamlit app in headless mode.
                    If None, the default behavior is to open a browser window.
    """
    if headless:
        rich_print("\nLaunching Streamlit app in headless mode...")
    else:
        rich_print(
            "\nLaunching Streamlit app... Attempting to open a browser window..."
        )
    app_path = f"{Path(__file__).parent}/app.py"
    sys.argv = [
        "streamlit",
        "run",
        app_path,
        "--global.developmentMode=false",
        f"--server.headless={'true' if headless else 'false'}",
        "--server.port=8501",
        "--browser.gatherUsageStats=false",
        "--logger.level=info",
    ]
    try:
        sys.exit(stcli.main())
    except Exception as e:
        rich_print(f"An error of type {type(e).__name__} occurred: {e}")
        sys.exit(1)


def main() -> None:
    """
    Main function to parse command line arguments and launch the Streamlit app.
    """
    parser = argparse.ArgumentParser(
        prog="coverage-analyzer",
        description="Launch the Stellar Cyber Coverage Analyzer Streamlit app.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help=(
            "Launch the Streamlit app in headless mode"
            "(Don't automatically open a browser window)."
            "Used for server deployments."
        ),
    )
    subparsers = parser.add_subparsers(
        help="CLI sub-commands for advanced usage.", dest="subcommand"
    )
    config_parser = subparsers.add_parser(  # noqa: F841
        "config", help="Create and manage configuration files for coverage-analyzer"
    )
    cli_parser = subparsers.add_parser(  # noqa: F841
        "cli", help="Execute the coverage-analyzer as a CLI tool"
    )
    # Arguments and subcommands will be added here to enable cli functionality

    args = parser.parse_args()
    if args.subcommand is None:
        # Create and start a new process for the Streamlit app
        launch_streamlit_app(headless=args.headless)
    else:
        rich_print(
            f"\nSub-command '{args.subcommand}' not implemented yet. Coming soon..."
        )
        # This is where we will route to the appropriate functions to add cli functionality


if __name__ == "__main__":
    main()
