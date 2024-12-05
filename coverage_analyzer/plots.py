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


# @st.cache_data(ttl="1h")
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
            tactic_coverage: DataFrame containing tactic coverage data
            technique_coverage: DataFrame containing technique coverage data

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
            # Set technique color based on coverage ratio
            technique_color = get_coverage_color(technique_row["coverage_ratio"])
            technique_row["color"] = technique_color
            tactic_techniques.append(technique_row)

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
                        "symbol": "square",
                        "line": {"width": 1, "color": "black"},
                    },
                    # text=technique_info.get("technique", "").replace(" ", "<br>"),
                    # textposition="top center",
                    # textfont={"size": 10},
                    hovertemplate=f"{technique_info['technique']}<br>Covered: {technique_info['covered_alerts']}<br>Available: {technique_info['total_alerts']}<extra></extra>",
                )
            )

    fig.update_layout(
        # title="MITRE ATT&CK Framework Matrix",
        autosize=True,
        uniformtext_minsize=12,
        uniformtext_mode="show",
        xaxis={
            "title": "Tactics",
            "tickmode": "array",
            "tickvals": list(range(len(matrix))),
            "ticktext": [row["tactic"] for row in matrix],
            "side": "top",
        },
        yaxis={
            "autorange": "reversed",
            "visible": False,
        },
        showlegend=False,
        height=600,
        width=1200,
    )

    return fig


# def create_plotly_matrix(
#     tactic_coverage: pl.DataFrame, technique_coverage: pl.DataFrame
# ) -> go.Figure:
#     """
#     Create a Plotly heatmap visualization with gradient-based coloring.

#     Args:
#             tactic_coverage: DataFrame containing tactic coverage data
#             technique_coverage: DataFrame containing technique coverage data

#     Returns:
#             Plotly Figure object
#     """
#     matrix = []

#     for tactic in tactic_coverage["tactic"].to_list():
#         tactic_row = {"tactic": tactic}
#         tactic_techniques = []
#         for technique_row in technique_coverage.filter(
#             pl.col("tactic") == tactic
#         ).to_dicts():
#             # Set technique color based on coverage ratio
#             technique_color = get_coverage_color(technique_row["coverage_ratio"])
#             technique_row["color"] = technique_color
#             tactic_techniques.append(technique_row)

#         # Set tactic color based on overall coverage ratio for the tactic
#         tactic_row["techniques"] = tactic_techniques
#         tactic_row["color"] = get_coverage_color(
#             tactic_coverage.filter(pl.col("tactic") == tactic)["tactic_coverage_ratio"][
#                 0
#             ]
#         )

#         matrix.append(tactic_row)

#     # Compute the maximum number of techniques per tactic
#     max_techniques = max(len(row["techniques"]) for row in matrix)

#     # Create data structures for the heatmap
#     z = []  # 2D array of coverage ratios
#     text = []  # 2D array of hover texts

#     for row in matrix:
#         coverage_ratios = [tech["coverage_ratio"] for tech in row["techniques"]]
#         technique_names = [tech["technique"] for tech in row["techniques"]]
#         covered_alerts = [tech["covered_alerts"] for tech in row["techniques"]]
#         total_alerts = [tech["total_alerts"] for tech in row["techniques"]]

#         # Pad lists to the maximum length with None or empty strings
#         pad_length = max_techniques - len(coverage_ratios)
#         coverage_ratios += [None] * pad_length
#         technique_names += [""] * pad_length
#         covered_alerts += [""] * pad_length
#         total_alerts += [""] * pad_length

#         z.append(coverage_ratios)
#         text.append(
#             [
#                 f"{technique_names[i]}<br>Covered: {covered_alerts[i]}<br>Available: {total_alerts[i]}"
#                 if technique_names[i]
#                 else ""
#                 for i in range(max_techniques)
#             ]
#         )

#     # Transpose z and text to match the heatmap's expected format
#     import numpy as np

#     z = np.array(z).T.tolist()
#     text = np.array(text).T.tolist()

#     # Define custom colorscale based on coverage ratios
#     colorscale = [
#         [0.0, "red"],
#         [0.25, "orange"],
#         [0.5, "yellow"],
#         # [0.75, "green"],
#         [1.0, "green"],
#     ]

#     # Create the heatmap
#     fig = go.Figure(
#         data=go.Heatmap(
#             z=z,
#             x=[row["tactic"] for row in matrix],
#             y=list(range(max_techniques)),
#             text=text,
#             texttemplate="%{text}",
#             hoverinfo="text",
#             colorscale=colorscale,
#             zmin=0,
#             zmax=1,
#             colorbar={"title": "Coverage Ratio"},
#             xgap=0.8,
#             ygap=0.8,
#             showscale=False,
#         )
#     )

#     fig.update_layout(
#         xaxis={
#             "title": "Tactics",
#             "side": "top",
#         },
#         yaxis={"visible": False, "autorange": "reversed"},
#         showlegend=False,
#         height=600,
#         width=1200,
#         autosize=True,
#         uniformtext_minsize=10,

#     )

#     return fig


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

            fig = create_plotly_matrix(tactic_coverage, technique_coverage)
            try:
                # Render the graph
                plotly_state = st.plotly_chart(
                    fig, use_container_width=False, on_select="rerun"
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
