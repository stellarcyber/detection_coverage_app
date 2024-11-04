from typing import Any

import matplotlib.colors as mcolors
import plotly.graph_objects as go
import polars as pl
import streamlit as st

from coverage_analyzer.vars import logger


def get_coverage_color(ratio):
    # Define light coral (low coverage) to light green (high coverage) gradient
    coral = mcolors.to_rgb("#F88379")
    green = mcolors.to_rgb("#90EE90")
    color = [(1 - ratio) * coral[i] + ratio * green[i] for i in range(3)]
    return mcolors.to_hex(tuple(color))


@st.cache_data(ttl="1h")
def prepare_coverage_data(
    alert_types_table: dict[str, Any],
) -> tuple[pl.DataFrame, pl.DataFrame]:
    """
    Prepares and caches the coverage data for visualization.
    """
    try:
        att_df = pl.DataFrame(alert_types_table)

        # Calculate coverage rate for each technique
        technique_coverage = (
            att_df.group_by(["tactic", "technique"])
            .agg(
                [
                    pl.count("alert_type").alias("total_alerts"),
                    pl.col("covered").sum().alias("covered_alerts"),
                ]
            )
            .with_columns(
                [
                    (pl.col("covered_alerts") / pl.col("total_alerts")).alias(
                        "coverage_ratio"
                    )
                ]
            )
        )

        # Calculate coverage rate for each tactic
        tactic_coverage = (
            technique_coverage.group_by("tactic")
            .agg(
                [
                    pl.col("total_alerts").sum().alias("total_tactic_alerts"),
                    pl.col("covered_alerts").sum().alias("covered_tactic_alerts"),
                ]
            )
            .with_columns(
                [
                    (
                        pl.col("covered_tactic_alerts") / pl.col("total_tactic_alerts")
                    ).alias("tactic_coverage_ratio")
                ]
            )
        )
        return (tactic_coverage, technique_coverage)
    except Exception as e:
        logger.error(f"Error preparing coverage data: {str(e)}")
        raise


def create_plotly_matrix(
    tactic_coverage: pl.DataFrame, technique_coverage: pl.DataFrame
) -> go.Figure:
    """
    Create a Plotly matrix visualization with gradient-based heatmap.

    Args:
            agg_df: Aggregated DataFrame containing coverage data

    Returns:
            Plotly Figure object
    """
    matrix = []

    for tactic in tactic_coverage["tactic"].to_list():
        tactic_row = {"tactic": tactic}
        tactic_techniques = []

        for technique_row in technique_coverage.filter(
            pl.col("tactic") == tactic
        ).to_dicts():
            technique_name = technique_row["technique"]
            coverage_ratio = technique_row["coverage_ratio"]

            # Set technique color based on coverage ratio
            technique_color = get_coverage_color(coverage_ratio)
            tactic_techniques.append(
                {"technique": technique_name, "color": technique_color}
            )

        # Set tactic color based on overall coverage ratio for the tactic
        tactic_row["techniques"] = tactic_techniques
        tactic_row["color"] = get_coverage_color(
            tactic_coverage.filter(pl.col("tactic") == tactic)["tactic_coverage_ratio"][
                0
            ]
        )

        matrix.append(tactic_row)

    # Plotly figure creation
    fig = go.Figure()

    for i, row in enumerate(matrix):
        for j, technique_info in enumerate(row["techniques"]):
            fig.add_trace(
                go.Scatter(
                    x=[i],
                    y=[j],
                    mode="markers+text",
                    marker={
                        "size": 20,
                        "color": technique_info["color"],
                        "line": {"width": 1, "color": "black"},
                    },
                    text=technique_info["technique"],
                    textposition="top center",
                )
            )

    # Add tactic background color as a rectangle
    for i, row in enumerate(matrix):
        fig.add_shape(
            type="rect",
            x0=i - 0.5,
            y0=-0.5,
            x1=i + 0.5,
            y1=len(row["techniques"]) - 0.5,
            fillcolor=row["color"],
            opacity=0.2,
            line={"width": 0},
        )

    # Update the layout for Plotly visualization
    fig.update_layout(
        title="MITRE ATT&CK Framework Matrix",
        xaxis={
            "title": "Tactics",
            "tickmode": "array",
            "tickvals": list(range(len(matrix))),
            "ticktext": [row["tactic"] for row in matrix],
        },
        showlegend=False,
        height=800,
        width=1200,
    )

    return fig


@st.fragment
def create_coverage_matrix(alert_types_table: dict[str, Any]):
    """
    Create and display a coverage matrix visualization using Graphviz.
    """
    try:
        if len(alert_types_table) == 0:
            st.warning("No data available to display in the coverage matrix.", icon="⚠️")
            return

        with st.spinner("Preparing coverage matrix..."):
            # Process data efficiently using Polars
            (tactic_coverage, technique_coverage) = prepare_coverage_data(
                alert_types_table
            )

            if tactic_coverage.is_empty():
                st.warning("No aggregated data available to display.", icon="⚠️")
                return

            # Create graphviz visualization
            fig = create_plotly_matrix(tactic_coverage, technique_coverage)
            try:
                # Render the graph
                plotly_state = st.plotly_chart(
                    fig, use_container_width=True, on_select="rerun"
                )
            except Exception as e:
                logger.error(f"Error displaying matrix: {str(e)}")
                st.error(
                    "Error displaying coverage matrix. Please try refreshing the page.",
                    icon="🚨",
                )
        return plotly_state

    except Exception as e:
        logger.error(f"Error in create_coverage_matrix: {str(e)}")
        st.error(
            "An error occurred while creating the coverage matrix. Please check the logs for details.",
            icon="🚨",
        )