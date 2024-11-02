"""Tests for the run script functionality."""

import sys
from pathlib import Path
from unittest.mock import patch
from run import launch_streamlit_app, main


def test_launch_streamlit_app_normal():
    """Test normal launch of Streamlit app."""
    with (
        patch("streamlit.web.cli.main") as mock_stcli,
        patch("rich.print"),
        patch("sys.exit") as mock_exit,
    ):
        # Configure mock to avoid SystemExit
        mock_stcli.return_value = 0

        launch_streamlit_app(headless=False)

        # Verify streamlit CLI arguments
        assert sys.argv[0] == "streamlit"
        assert sys.argv[1] == "run"
        assert Path(sys.argv[2]).name == "app.py"
        assert "--server.headless=false" in sys.argv

        # Verify streamlit CLI and sys.exit were called
        mock_stcli.assert_called_once()
        mock_exit.assert_called_once_with(0)


def test_launch_streamlit_app_headless():
    """Test headless launch of Streamlit app."""
    with (
        patch("streamlit.web.cli.main") as mock_stcli,
        patch("rich.print"),
        patch("sys.exit") as mock_exit,
    ):
        # Configure mock to avoid SystemExit
        mock_stcli.return_value = 0

        launch_streamlit_app(headless=True)

        # Verify streamlit CLI arguments
        assert sys.argv[0] == "streamlit"
        assert sys.argv[1] == "run"
        assert Path(sys.argv[2]).name == "app.py"
        assert "--server.headless=true" in sys.argv

        # Verify streamlit CLI and sys.exit were called
        mock_stcli.assert_called_once()
        mock_exit.assert_called_once_with(0)


def test_launch_streamlit_app_error():
    """Test error handling during app launch."""
    with (
        patch("streamlit.web.cli.main", side_effect=Exception("Test error")),
        patch("rich.print"),
        patch("sys.exit") as mock_exit,
    ):
        launch_streamlit_app()
        mock_exit.assert_called_once_with(1)


def test_main_default():
    """Test default main function behavior."""
    with (
        patch("sys.argv", ["run.py"]),
        patch("run.launch_streamlit_app") as mock_launch,
    ):
        main()
        mock_launch.assert_called_with(headless=False)


def test_main_headless():
    """Test headless mode in main function."""
    with (
        patch("sys.argv", ["run.py", "--headless"]),
        patch("run.launch_streamlit_app") as mock_launch,
    ):
        main()
        mock_launch.assert_called_with(headless=True)
