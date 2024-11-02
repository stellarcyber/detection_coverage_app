"""Tests for the plotting functionality."""

from typing import Any
import pytest
import polars as pl
import plotly.graph_objects as go
from coverage_analyzer.plots import (
    prepare_coverage_data,
    get_coverage_color,
    create_plotly_matrix,
)


@pytest.fixture
def sample_alert_types_table() -> dict[str, Any]:
    """Create a sample DataFrame for testing."""
    data = {
        "tactic": ["Initial Access", "Execution", "Initial Access"],
        "technique": ["Drive-by Compromise", "Valid Accounts", "Valid Accounts"],
        "alert_type": ["Alert Type 1", "Alert Type 2", "Alert Type 3"],
        "covered": [True, False, True],
        "triggered": [True, False, False],
        "recommended_data_sources": [
            ["linux_sensor"],
            ["windows_sensor"],
            ["network_sensor"],
        ],
    }
    return data


@pytest.fixture
def sample_alert_types_df(sample_alert_types_table) -> pl.DataFrame:
    """Create a sample Polars DataFrame for testing."""
    return pl.DataFrame(sample_alert_types_table)


def test_prepare_coverage_data(sample_alert_types_table: dict[str, Any]) -> None:
    """Test coverage data preparation."""
    result1, result2 = prepare_coverage_data(sample_alert_types_table)

    assert isinstance(result1, pl.DataFrame)
    assert isinstance(result2, pl.DataFrame)
    assert "tactic_coverage_ratio" in result1.columns
    assert "coverage_ratio" in result2.columns

    # Check calculations
    assert result2.shape[0] == 3
    first_row = result2.filter(pl.col("tactic") == "Initial Access").to_dict(
        as_series=False
    )
    assert first_row["coverage_ratio"][0] == 1.0  # Both Initial Access rows are covered


def test_prepare_coverage_data_empty() -> None:
    """Test coverage data preparation with empty input."""
    empty_data = {
        "tactic": [],
        "technique": [],
        "alert_type": [],
        "covered": [],
        "triggered": [],
        "recommended_data_sources": [],
    }

    result1, result2 = prepare_coverage_data(empty_data)
    assert isinstance(result1, pl.DataFrame)
    assert result1.shape[0] == 0
    assert isinstance(result2, pl.DataFrame)
    assert result2.shape[0] == 0


def test_prepare_coverage_data_single_tactic() -> None:
    """Test coverage data preparation with a single tactic."""
    single_tactic_data = {
        "tactic": ["Initial Access"],
        "technique": ["Drive-by Compromise"],
        "alert_type": ["Alert Type 1"],
        "covered": [True],
        "triggered": [True],
        "recommended_data_sources": [["linux_sensor"]],
    }

    result1, result2 = prepare_coverage_data(single_tactic_data)
    assert isinstance(result1, pl.DataFrame)
    assert result1.shape[0] == 1
    assert result1.filter(pl.col("tactic") == "Initial Access").shape[0] == 1


def test_get_coverage_color():
    """Test coverage color generation."""
    # Test low coverage
    low_color = get_coverage_color(0.1)
    assert isinstance(low_color, str)
    assert low_color.startswith("#")

    # Test medium coverage
    med_color = get_coverage_color(0.5)
    assert isinstance(med_color, str)
    assert med_color.startswith("#")

    # Test high coverage
    high_color = get_coverage_color(0.9)
    assert isinstance(high_color, str)
    assert high_color.startswith("#")

    # Test boundary values
    assert get_coverage_color(0) != get_coverage_color(1)
    assert get_coverage_color(0.5) != get_coverage_color(0)
    assert get_coverage_color(0.5) != get_coverage_color(1)


def test_create_plotly_matrix(sample_alert_types_table):
    """Test Plotly matrix creation."""
    tactic_coverage, technique_coverage = prepare_coverage_data(
        sample_alert_types_table
    )

    # Create matrix
    fig = create_plotly_matrix(tactic_coverage, technique_coverage)

    assert isinstance(fig, go.Figure)


def test_create_plotly_matrix_single_item():
    """Test Plotly matrix creation with single item."""
    single_data = {
        "tactic": ["Initial Access"],
        "technique": ["Drive-by Compromise"],
        "alert_type": ["Alert Type 1"],
        "covered": [True],
        "triggered": [True],
        "recommended_data_sources": [["linux_sensor"]],
    }

    tactic_coverage, technique_coverage = prepare_coverage_data(single_data)
    fig = create_plotly_matrix(tactic_coverage, technique_coverage)
    assert isinstance(fig, go.Figure)


def test_prepare_coverage_data_all_uncovered():
    """Test coverage data preparation with all uncovered items."""
    uncovered_data = {
        "tactic": ["Initial Access", "Execution"],
        "technique": ["Drive-by Compromise", "Valid Accounts"],
        "alert_type": ["Alert Type 1", "Alert Type 2"],
        "covered": [False, False],
        "triggered": [False, False],
        "recommended_data_sources": [["linux_sensor"], ["windows_sensor"]],
    }

    tactic_coverage, technique_coverage = prepare_coverage_data(uncovered_data)

    # Verify all coverage ratios are 0
    assert all(ratio == 0 for ratio in tactic_coverage["tactic_coverage_ratio"])
    assert all(ratio == 0 for ratio in technique_coverage["coverage_ratio"])


def test_prepare_coverage_data_all_covered():
    """Test coverage data preparation with all covered items."""
    covered_data = {
        "tactic": ["Initial Access", "Execution"],
        "technique": ["Drive-by Compromise", "Valid Accounts"],
        "alert_type": ["Alert Type 1", "Alert Type 2"],
        "covered": [True, True],
        "triggered": [True, True],
        "recommended_data_sources": [["linux_sensor"], ["windows_sensor"]],
    }

    tactic_coverage, technique_coverage = prepare_coverage_data(covered_data)

    # Verify all coverage ratios are 1
    assert all(ratio == 1 for ratio in tactic_coverage["tactic_coverage_ratio"])
    assert all(ratio == 1 for ratio in technique_coverage["coverage_ratio"])


def test_prepare_coverage_data_mixed_coverage():
    """Test coverage data preparation with mixed coverage."""
    mixed_data = {
        "tactic": ["Initial Access", "Initial Access", "Execution"],
        "technique": ["Drive-by Compromise", "Drive-by Compromise", "Valid Accounts"],
        "alert_type": ["Alert Type 1", "Alert Type 2", "Alert Type 3"],
        "covered": [True, False, True],
        "triggered": [True, False, False],
        "recommended_data_sources": [
            ["linux_sensor"],
            ["windows_sensor"],
            ["network_sensor"],
        ],
    }

    tactic_coverage, technique_coverage = prepare_coverage_data(mixed_data)

    # Verify Initial Access has 0.5 coverage (1/2 alerts covered)
    ia_coverage = tactic_coverage.filter(pl.col("tactic") == "Initial Access")[
        "tactic_coverage_ratio"
    ][0]
    assert ia_coverage == 0.5

    # Verify Execution has 1.0 coverage (1/1 alerts covered)
    exec_coverage = tactic_coverage.filter(pl.col("tactic") == "Execution")[
        "tactic_coverage_ratio"
    ][0]
    assert exec_coverage == 1.0
