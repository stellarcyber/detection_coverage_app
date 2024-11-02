"""Tests for the Streamlit app functionality."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from coverage_analyzer.streamlit import StreamlitCoverageAnalyzerClient


@pytest.fixture
def streamlit_analyzer():
    """Create a StreamlitCoverageAnalyzer instance for testing."""
    return StreamlitCoverageAnalyzerClient(
        name="test",
        host="test.stellarcyber.ai",
        username="test@example.com",
        api_key="test-key",
        version="5.2.x",
        cache_ttl="1m",
    )


@pytest.fixture
def mock_date_range():
    """Create a mock date range for testing."""
    return {
        "start_date": (datetime.now(timezone.utc) - timedelta(days=1)).date(),
        "end_date": datetime.now(timezone.utc).date(),
    }


def test_get_tactics(streamlit_analyzer):
    """Test getting tactics."""
    mock_tactics = [
        {"name": "Test Tactic", "shortname": "test-tactic", "external_id": "TA0001"}
    ]
    with patch.object(
        streamlit_analyzer._mitre, "get_tactics", return_value=mock_tactics
    ):
        result = streamlit_analyzer.get_tactics()
        assert result == mock_tactics
        assert len(result) == 1
        assert result[0]["name"] == "Test Tactic"


def test_get_alert_type_hits(streamlit_analyzer, mock_date_range):
    """Test getting alert type hits."""
    mock_hits = {"Alert1": 5, "Alert2": 3}
    with patch.object(
        streamlit_analyzer._stellar,
        "alert_stats",
        return_value={"alert_type_hits": mock_hits},
    ):
        result = streamlit_analyzer.get_alert_type_hits(
            start_date=mock_date_range["start_date"],
            end_date=mock_date_range["end_date"],
        )
        assert result == mock_hits
        assert len(result) == 2
        assert result["Alert1"] == 5


def test_get_matching_alert_types_count_from_hits(streamlit_analyzer):
    """Test getting matching alert types count from hits."""
    mock_hits = {"Alert1": 5, "Alert2": 3}
    mock_detections = [
        {
            "XDR Display Name": "Alert1",
            "XDR Tactic": "Initial Access",
            "XDR Technique": "T1189",
        }
    ]

    with patch.object(
        streamlit_analyzer, "get_detections", return_value=mock_detections
    ):
        result = streamlit_analyzer.get_matching_alert_types_count_from_hits(
            mock_hits, "Initial Access", "T1189"
        )
        assert result == 1  # Should match Alert1's hit count


def test_get_matching_alert_types_count_from_ds(streamlit_analyzer):
    """Test getting matching alert types count from data sources."""
    mock_sources = ["source1", "source2"]
    mock_detections = [
        {
            "XDR Display Name": "Alert1",
            "XDR Tactic": "Initial Access",
            "XDR Technique": "T1189",
            "data_sources_combined": ["source1"],
        }
    ]

    with patch.object(
        streamlit_analyzer, "get_detections", return_value=mock_detections
    ):
        result = streamlit_analyzer.get_matching_alert_types_count_from_ds(
            mock_sources, "Initial Access", "T1189"
        )
        assert result == 1


def test_get_used_datasources(streamlit_analyzer, mock_date_range):
    """Test getting used data sources."""
    mock_sources = {"connector": ["source1"], "sensor": ["source2"]}
    mock_data_sources = [
        {"_id": "source1", "name": "Source 1"},
        {"_id": "source2", "name": "Source 2"},
    ]

    with (
        patch.object(
            streamlit_analyzer._mitre,
            "get_detections_datasources",
            return_value=mock_data_sources,
        ),
        patch.object(
            streamlit_analyzer._stellar,
            "get_connector_log_data_sources",
            return_value=mock_sources["connector"],
        ),
        patch.object(
            streamlit_analyzer._stellar,
            "get_sensor_sources",
            return_value=mock_sources["sensor"],
        ),
    ):
        result = streamlit_analyzer.get_used_datasources(
            start_date=mock_date_range["start_date"],
            end_date=mock_date_range["end_date"],
        )
        assert isinstance(result, list)
        assert len(result) == 2
        assert "source1" in result
        assert "source2" in result


def test_get_detections(streamlit_analyzer):
    """Test getting detections."""
    mock_detections = [
        {
            "XDR Display Name": "Alert1",
            "XDR Tactic": "Initial Access",
            "XDR Technique": "T1189",
            "data_sources_combined": ["source1"],
        }
    ]

    with patch.object(
        streamlit_analyzer._mitre, "get_detections", return_value=mock_detections
    ):
        result = streamlit_analyzer.get_detections()
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["XDR Display Name"] == "Alert1"


def test_error_handling(streamlit_analyzer, mock_date_range):
    """Test error handling in the analyzer."""
    with patch.object(
        streamlit_analyzer, "get_tactics", side_effect=Exception("Test error")
    ):
        with pytest.raises(Exception) as exc_info:
            streamlit_analyzer.get_tactics()
        assert str(exc_info.value) == "Test error"
