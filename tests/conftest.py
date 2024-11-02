"""Pytest configuration and fixtures."""

from datetime import date, datetime, timezone
from typing import Any
from unittest.mock import patch

import pytest


@pytest.fixture
def mock_tactics() -> list[dict[str, str]]:
    """Return mock MITRE tactics data."""
    return [
        {
            "name": "Initial Access",
            "shortname": "initial-access",
            "external_id": "TA0001",
        },
        {"name": "Execution", "shortname": "execution", "external_id": "TA0002"},
    ]


@pytest.fixture
def mock_techniques() -> list[dict[str, Any]]:
    """Return mock MITRE techniques data."""
    return [
        {
            "name": "Drive-by Compromise",
            "description": "Adversaries may gain access...",
            "external_id": "T1189",
        },
        {
            "name": "Valid Accounts",
            "description": "Adversaries may steal...",
            "external_id": "T1078",
        },
    ]


@pytest.fixture
def mock_alert_type_hits() -> dict[str, int]:
    """Return mock alert type hits data."""
    return {"Alert Type 1": 5, "Alert Type 2": 3, "Alert Type 3": 1}


@pytest.fixture
def mock_date_range() -> dict[str, date]:
    """Return mock date range."""
    return {
        "start_date": datetime.now(tz=timezone.utc).date(),
        "end_date": datetime.now(tz=timezone.utc).date(),
    }


@pytest.fixture
def mock_data_sources() -> list[str]:
    """Return mock data sources."""
    return ["linux_sensor", "windows_sensor", "network_sensor"]


@pytest.fixture
def mock_detections() -> list[dict[str, Any]]:
    """Return mock detections data."""
    return [
        {
            "XDR Display Name": "Alert Type 1",
            "XDR Tactic": "Initial Access",
            "XDR Technique": "Drive-by Compromise",
            "data_sources_combined": ["linux_sensor", "windows_sensor"],
        },
        {
            "XDR Display Name": "Alert Type 2",
            "XDR Tactic": "Execution",
            "XDR Technique": "Valid Accounts",
            "data_sources_combined": ["network_sensor"],
        },
    ]


@pytest.fixture
def mock_cookie_manager():
    """Create a mock cookie manager for testing."""
    with patch("coverage_analyzer.vars.EncryptedCookieManager") as mock_cm:
        instance = mock_cm.return_value
        instance._cookie_manager._cookies = {}
        instance.ready.return_value = True
        # instance.get.return_value = "{}"
        yield instance


@pytest.fixture(autouse=True)
def mock_streamlit():
    """Mock Streamlit session state and components."""
    with patch("streamlit.session_state", {}) as mock_state:
        yield mock_state
