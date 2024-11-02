"""Tests for the main Streamlit application."""

import json
from unittest.mock import MagicMock, patch

import pytest
from streamlit.testing.v1 import AppTest


@pytest.fixture
def app_test():
    """Create an AppTest instance for testing."""
    at = AppTest.from_file("app.py").run()
    at.session_state.config = "test_host"
    at.session_state.configs = {
        "test_host": {
            "host": "test_host",
            "user": "test_user",
            "api_key": "test_key",
            "version": "1.0",
            "verify_ssl": True,
        }
    }
    return at


@pytest.fixture
def mock_coverage_analyzer():
    """Create a mock coverage analyzer for testing."""
    mock = MagicMock()
    mock.get_tenants.return_value = ["Tenant1", "Tenant2"]
    mock.get_detections_datasources.return_value = ["source1", "source2"]
    mock.get_alert_type_hits.return_value = {"Alert1": 5, "Alert2": 3}
    mock.get_tactics_and_techniques.return_value = [
        {
            "name": "Initial Access",
            "techniques": [{"name": "Drive-by Compromise", "external_id": "T1189"}],
        }
    ]
    return mock


def test_init_state(mock_cookie_manager, app_test):
    """Test initialization of application state."""
    mock_configs = {
        "test_host": {
            "host": "test_host",
            "user": "test_user",
            "api_key": "test_key",
            "version": "1.0",
            "verify_ssl": True,
        }
    }
    mock_cookie_manager.get.return_value = json.dumps(mock_configs)

    with (
        patch("app.get_cookie_manager", return_value=mock_cookie_manager),
        patch("app.read_hosts_config", return_value=mock_configs),
    ):
        app_test.run()
        assert "configs" in app_test.session_state
        assert isinstance(app_test.session_state["configs"], dict)
        assert app_test.session_state["configs"] == mock_configs


def test_save_state(mock_cookie_manager, app_test):
    """Test saving application state."""
    new_config = {
        "host": "new_host",
        "user": "new_user",
        "api_key": "new_key",
        "version": "2.0",
        "verify_ssl": True,
    }

    with patch("app.get_cookie_manager", return_value=mock_cookie_manager):
        app_test.session_state["configs"] = {}
        app_test.run()

        # Call save_state with new config
        with patch("coverage_analyzer.callbacks.save_state") as mock_save:
            mock_save(new_config)
            mock_save.assert_called_once_with(new_config)
