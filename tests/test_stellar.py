"""Tests for the Stellar Cyber API integration."""

import pytest
from coverage_analyzer.stellar import StellarCyberAPI
from unittest.mock import patch
from datetime import datetime, timedelta, timezone


@pytest.fixture
def mock_date_range():
    """Create a mock date range for testing."""
    return {
        "start_date": datetime.now(timezone.utc).date() - timedelta(days=1),
        "end_date": datetime.now(timezone.utc).date(),
    }


@pytest.fixture
def stellar_api():
    """Create a StellarCyberAPI instance for testing."""
    return StellarCyberAPI(
        host="test.stellarcyber.ai",
        username="test@example.com",
        api_key="test-key",
        version="5.2.x",
        verify_ssl=True,
    )


def test_init(stellar_api):
    """Test StellarCyberAPI initialization."""
    assert stellar_api.api_base_url == "https://test.stellarcyber.ai/connect/api/"
    assert stellar_api.username == "test@example.com"
    assert stellar_api.api_key == "test-key"
    assert stellar_api.version.value == "5.2.x"
    assert stellar_api.verify_ssl is True


def test_get_token(stellar_api):
    """Test token retrieval and refresh."""
    mock_token = {"access_token": "test-token", "exp": 9999999999}

    with patch.object(stellar_api, "_refresh_token", return_value=mock_token):
        token = stellar_api._get_token()
        assert token == "test-token"


def test_get_tenants(stellar_api):
    """Test getting tenants."""
    mock_tenants = {"data": [{"cust_name": "Tenant 1"}, {"cust_name": "Tenant 2"}]}

    with patch.object(stellar_api, "_get_data") as mock_get:
        mock_get.return_value = mock_tenants

        # Test with as_options=True
        result = stellar_api.get_tenants(as_options=True)
        assert isinstance(result, list)
        assert "Tenant 1" in result
        assert "Tenant 2" in result

        # Test with as_options=False
        result = stellar_api.get_tenants(as_options=False)
        assert isinstance(result, list)
        assert result == mock_tenants["data"]


def test_es_search(stellar_api):
    """Test Elasticsearch search functionality."""
    mock_query = {"query": {"match_all": {}}}
    mock_response = {"hits": {"hits": []}}

    with patch.object(stellar_api, "_get_data") as mock_get:
        mock_get.return_value = mock_response
        result = stellar_api.es_search("test-index", mock_query)

        assert result == mock_response
        mock_get.assert_called_once_with("data/test-index/_search", data=mock_query)


def test_get_detections(stellar_api):
    """Test getting detections."""
    mock_detections = {"data": [{"built_in": True}, {"built_in": False}]}

    with patch.object(stellar_api, "_get_data") as mock_get:
        mock_get.return_value = mock_detections

        # Test getting all detections
        result = stellar_api.get_detections()
        assert len(result) == 2

        # Test getting only built-in detections
        result = stellar_api.get_detections(only_builtin=True)
        assert len(result) == 1
        assert result[0]["built_in"] is True

        # Test getting only custom detections
        result = stellar_api.get_detections(only_custom=True)
        assert len(result) == 1
        assert result[0]["built_in"] is False


def test_get_connector_log_data_sources(stellar_api, mock_date_range):
    """Test getting connector log data sources."""
    mock_response = {
        "aggregations": {
            "log": {"buckets": [{"key": "source1"}, {"key": "source2"}]},
            "connector": {"buckets": [{"key": "source3"}]},
        }
    }

    with patch.object(stellar_api, "es_search") as mock_search:
        mock_search.return_value = mock_response

        result = stellar_api.get_connector_log_data_sources(
            start_date=mock_date_range["start_date"],
            end_date=mock_date_range["end_date"],
        )

        assert isinstance(result, list)
        assert len(result) == 3
        assert "source1" in result
        assert "source2" in result
        assert "source3" in result
