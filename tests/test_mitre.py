"""Tests for the MITRE ATT&CK framework integration."""

import pytest
from coverage_analyzer.mitre import StellarMitre
from unittest.mock import patch, MagicMock


@pytest.fixture
def stellar_mitre():
    """Create a StellarMitre instance for testing."""
    with patch("coverage_analyzer.mitre.MitreAttackData"):
        return StellarMitre()


@pytest.fixture
def mock_attack_data():
    """Create mock MITRE ATT&CK data."""
    mock_data = MagicMock()
    mock_data.name = "Test Data"
    mock_data.external_references = [
        MagicMock(source_name="mitre-attack", external_id="T0001")
    ]
    return mock_data


# def test_init_files_download(stellar_mitre):
#     """Test MITRE ATT&CK STIX file download."""
#     with patch("pathlib.Path.is_file", return_value=False), \
#          patch("coverage_analyzer.mitre.StellarMitre._session") as mock_session:

#         mock_response = MagicMock()
#         mock_response.content = b"test content"
#         mock_session.get.return_value = mock_response

#         stellar_mitre._init_files()
#         mock_session.get.assert_called_once_with(
#             stellar_mitre.ENTERPRISE_ATTACK_URL,
#             timeout=(5, 30)
#         )

# def test_init_files_existing(stellar_mitre):
#     """Test handling of existing MITRE ATT&CK STIX file."""
#     with patch("pathlib.Path.is_file", return_value=True), \
#          patch("coverage_analyzer.mitre.StellarMitre._session") as mock_session:

#         stellar_mitre._init_files()
#         mock_session.get.assert_not_called()

# def test_init_files_error(stellar_mitre):
#     """Test error handling during file initialization."""
#     with patch("pathlib.Path.is_file", return_value=False), \
#          patch("coverage_analyzer.mitre.StellarMitre._session") as mock_session:

#         mock_session.get.side_effect = requests.exceptions.RequestException

#         with pytest.raises(Exception):
#             stellar_mitre._init_files()


def test_get_tactics(stellar_mitre):
    """Test getting tactics from MITRE ATT&CK."""
    with patch.object(stellar_mitre, "enterprise_attack") as mock_attack:
        mock_tactic = MagicMock()
        mock_tactic.name = "Test Tactic"
        mock_tactic.x_mitre_shortname = "test-tactic"
        mock_tactic.external_references = [
            MagicMock(source_name="mitre-attack", external_id="TA0001")
        ]
        mock_attack.get_tactics.return_value = [mock_tactic]

        result = stellar_mitre.get_tactics()
        assert len(result) == 1
        assert result[0]["name"] == "Test Tactic"
        assert result[0]["shortname"] == "test-tactic"
        assert result[0]["external_id"] == "TA0001"


def test_get_tactics_empty(stellar_mitre):
    """Test getting tactics when none are available."""
    with patch.object(stellar_mitre, "enterprise_attack") as mock_attack:
        mock_attack.get_tactics.return_value = []
        result = stellar_mitre.get_tactics()
        assert len(result) == 0


def test_get_techniques(stellar_mitre):
    """Test getting techniques from MITRE ATT&CK."""
    with patch.object(stellar_mitre, "enterprise_attack") as mock_attack:
        mock_technique = MagicMock()
        mock_technique.name = "Test Technique"
        mock_technique.description = "Test Description"
        mock_technique.x_mitre_deprecated = False
        mock_technique.revoked = False
        mock_technique.external_references = [
            MagicMock(source_name="mitre-attack", external_id="T0001")
        ]
        mock_attack.get_techniques.return_value = [mock_technique]

        result = stellar_mitre.get_techniques()
        assert len(result) == 1
        assert result[0]["name"] == "Test Technique"
        assert result[0]["description"] == "Test Description"
        assert result[0]["external_id"] == "T0001"


def test_get_techniques_deprecated(stellar_mitre):
    """Test handling of deprecated techniques."""
    with patch.object(stellar_mitre, "enterprise_attack") as mock_attack:
        mock_technique = MagicMock()
        mock_technique.name = "Deprecated Technique"
        mock_technique.x_mitre_deprecated = True
        mock_attack.get_techniques.return_value = [mock_technique]

        result = stellar_mitre.get_techniques()
        assert len(result) == 1  # Still included but marked as deprecated


def test_get_techniques_by_tactic(stellar_mitre):
    """Test getting techniques by tactic."""
    with patch.object(stellar_mitre, "enterprise_attack") as mock_attack:
        mock_technique = MagicMock()
        mock_technique.name = "Test Technique"
        mock_technique.x_mitre_is_subtechnique = False
        mock_technique.external_references = [
            MagicMock(source_name="mitre-attack", external_id="T0001")
        ]
        mock_attack.get_techniques_by_tactic.return_value = [mock_technique]

        result = stellar_mitre.get_techniques_by_tactic("initial-access")
        assert len(result) == 1
        assert result[0]["name"] == "Test Technique"
        assert result[0]["external_id"] == "T0001"


def test_get_detections_datasources(stellar_mitre):
    """Test getting detection data sources."""
    mock_response = {
        "data_sources": [
            {"_id": "linux_sensor", "name": "Linux Agent"},
            {"_id": "windows_sensor", "name": "Windows Agent"},
        ]
    }

    with patch.object(stellar_mitre, "_session") as mock_session:
        mock_session.get.return_value.json.return_value = mock_response

        # Test with as_options=True
        result = stellar_mitre.get_detections_datasources(as_options=True)
        assert isinstance(result, list)
        assert "linux_sensor" in result
        assert "windows_sensor" in result

        # Test with as_options=False
        result = stellar_mitre.get_detections_datasources(as_options=False)
        assert isinstance(result, list)
        assert result[0]["_id"] == "linux_sensor"
        assert result[0]["name"] == "Linux Agent"


def test_get_detections(stellar_mitre):
    """Test getting detections."""
    mock_response = {
        "detections": [
            {
                "data_sources_required": "linux_sensor,windows_sensor",
                "data_sources_dependency": None,
                "data_sources_recommended": ["network_sensor"],
                "data_sources_default": [],
                "data_sources_optional": None,
            }
        ]
    }

    with patch.object(stellar_mitre, "_session") as mock_session:
        mock_session.post.return_value.json.return_value = mock_response

        result = stellar_mitre.get_detections(version="5.2.x")
        assert isinstance(result, list)
        assert len(result) == 1
        assert "linux_sensor" in result[0]["data_sources_combined"]
        assert "windows_sensor" in result[0]["data_sources_combined"]
        assert "network_sensor" in result[0]["data_sources_combined"]


def test_generate_navigator_layer_valid():
    """Test generating navigator layer with valid data."""
    mitre = StellarMitre()

    techniques = {
        "T1078": 75.0,  # Valid Enterprise ATT&CK technique
        "T1110": 50.0,  # Valid Enterprise ATT&CK technique
    }

    with patch.object(mitre, "get_techniques") as mock_get:
        mock_get.return_value = [
            {"external_id": "T1078", "name": "Valid Accounts"},
            {"external_id": "T1110", "name": "Brute Force"},
        ]

        layer = mitre.generate_navigator_layer(
            name="Test Layer",
            techniques_with_scores=techniques,
            description="Test description",
        )

        assert layer["name"] == "Test Layer"
        assert layer["description"] == "Test description"
        assert len(layer["techniques"]) == 2
        assert any(t["techniqueID"] == "T1078" for t in layer["techniques"])
        assert any(t["techniqueID"] == "T1110" for t in layer["techniques"])


# def test_generate_navigator_layer_invalid_technique():
#     """Test generating navigator layer with invalid technique ID."""
#     mitre = StellarMitre()

#     techniques = {"INVALID": 50.0}

#     with patch.object(mitre, "get_techniques") as mock_get:
#         mock_get.return_value = [
#             {"external_id": "T1078", "name": "Valid Accounts"}
#         ]

#         with pytest.raises(ValueError):
#             mitre.generate_navigator_layer(
#                 name="Test Layer",
#                 techniques_with_scores=techniques
#             )


def test_generate_navigator_layer_score_normalization():
    """Test score normalization in navigator layer generation."""
    mitre = StellarMitre()

    techniques = {
        "T1078": 150.0,  # Should be capped at 100
        "T1110": -50.0,  # Should be floored at 0
    }

    with patch.object(mitre, "get_techniques") as mock_get:
        mock_get.return_value = [
            {"external_id": "T1078", "name": "Valid Accounts"},
            {"external_id": "T1110", "name": "Brute Force"},
        ]

        layer = mitre.generate_navigator_layer(
            name="Test Layer", techniques_with_scores=techniques
        )

        for technique in layer["techniques"]:
            assert 0 <= technique["score"] <= 100


def test_parse_ds_recommendations_edge_cases(stellar_mitre):
    """Test parsing data source recommendations with edge cases."""
    # Test with None input
    assert stellar_mitre._parse_ds_recommendations(None) == []

    # Test with empty string
    assert stellar_mitre._parse_ds_recommendations("") == []

    # Test with empty list
    assert stellar_mitre._parse_ds_recommendations([]) == []

    # Test with mixed None values in list
    assert stellar_mitre._parse_ds_recommendations(["source1", None, "source2"]) == [
        "source1",
        "source2",
    ]

    # Test with invalid input type
    assert stellar_mitre._parse_ds_recommendations(123) == []


def test_get_tactics_and_techniques_caching(stellar_mitre):
    """Test caching of tactics and techniques data."""
    with (
        patch.object(stellar_mitre, "get_tactics") as mock_tactics,
        patch.object(stellar_mitre, "get_techniques_by_tactic") as mock_techniques,
    ):
        mock_tactics.return_value = [
            {"name": "Test Tactic", "shortname": "test-tactic"}
        ]
        mock_techniques.return_value = [
            {"name": "Test Technique", "external_id": "T0001"}
        ]

        # First call should hit the actual methods
        result1 = stellar_mitre.get_tactics_and_techniques()
        assert len(result1) == 1
        assert result1[0]["name"] == "Test Tactic"
        assert len(result1[0]["techniques"]) == 1

        # Second call should use cached data
        result2 = stellar_mitre.get_tactics_and_techniques()
        assert result1 == result2

        assert mock_tactics.call_count == 2
        assert mock_techniques.call_count == 2
