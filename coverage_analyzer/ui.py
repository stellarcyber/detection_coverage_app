from typing import Any
from collections.abc import Callable
import json
from datetime import datetime, timedelta, timezone
import streamlit as st
import streamlit.components.v1 as components
import polars as pl
from coverage_analyzer import __version__
from coverage_analyzer.vars import logger, OVERVIEW_MARKDOWN, COOKIES
from coverage_analyzer.plots import create_coverage_matrix
from coverage_analyzer.callbacks import save_state, refresh_state


def header():
    """Display the application header with version and overview information."""
    st.title("Coverage Analyzer")
    st.caption(f"Version: {__version__}")
    st.subheader("Overview", divider=True)

    # Improved accessibility with semantic HTML and ARIA labels
    with st.expander(
        "",
        expanded=not st.session_state.get("selected_tenant", False)
        or not st.session_state.get("selected_timeframe", False),
        icon=":material/help:",
    ):
        st.markdown(
            OVERVIEW_MARKDOWN,
            unsafe_allow_html=True,
        )


def sidebar():
    global COOKIES
    st.sidebar.selectbox(
        "Select Configuration",
        options=st.session_state.get("configs", {}).keys(),
        key="config",
        help="Select a saved configuration to load",
        on_change=refresh_state,
    )
    left, middle, right = st.sidebar.columns(3)
    if left.button(label="", icon=":material/add:", use_container_width=True):
        config_dialog(callback=save_state, edit=False)

    if middle.button(
        label="",
        icon=":material/edit:",
        disabled=not st.session_state.config,
        use_container_width=True,
    ):
        config_dialog(callback=save_state, edit=True)

    if right.button(
        label="",
        icon=":material/delete:",
        disabled=not st.session_state.config,
        use_container_width=True,
    ):
        if st.session_state.config:
            configs = st.session_state.configs
            del configs[st.session_state.config]
            st.session_state.configs = configs
            COOKIES["configs"] = json.dumps(configs)  # type: ignore
            COOKIES.save()  # type: ignore
            st.session_state.config = None

    if st.session_state.config:
        refresh_state()
        tenant_options: list[str] = st.session_state.stca.get_tenants()
        tenant_options.insert(0, "All Tenants")
        st.sidebar.divider()
        st.sidebar.selectbox(
            label="Select Tenant",
            options=tenant_options,
            key="selected_tenant",
            index=None,
        )
        st.sidebar.date_input(
            "Time Range",
            value=[
                datetime.now(tz=timezone.utc).date() - timedelta(days=7),
                datetime.now(tz=timezone.utc).date(),
            ],
            help="Select the time range to run the dashboard for.",
            key="selected_timeframe",
        )
        st.sidebar.divider()
        if not st.session_state.get(
            "selected_tenant", False
        ) or not st.session_state.get("selected_timeframe", False):
            st.stop()

        analyze_coverage()
        # recommended_data_sources()

    else:
        st.sidebar.warning(
            "No saved configurations found in cookies. Please add one to connect to Stellar Cyber API and use dashboard."
        )


def recommended_data_sources():
    """Display recommended data sources to add to improve coverage."""
    if st.session_state.get("recommended_data_sources", False):
        st.sidebar.dataframe(st.session_state.recommended_data_sources, hide_index=True)


@st.dialog("Add New Configuration")
def config_dialog(callback: Callable, edit: bool | None = None) -> None:
    """
    Display configuration dialog with improved validation and user feedback.

    Args:
            callback: Function to call with new configuration
            edit: Whether this is an edit of existing config
    """
    if edit:
        config = st.session_state.configs[st.session_state.config]
    else:
        config = {
            "host": "",
            "user": "",
            "api_key": "",
            "version": "5.2.x",
            "verify_ssl": True,
        }

    with st.form("config_form"):
        stellar_cyber_host = st.text_input(
            "Stellar Cyber Host",
            help="Your Stellar Cyber Host, Ex. example.stellarcyber.cloud",
            autocomplete="host",
            placeholder="example.stellarcyber.ai",
            value=config["host"],
        )

        stellar_cyber_user = st.text_input(
            "Stellar Cyber User",
            help="The Stellar Cyber API User Email",
            autocomplete="email",
            placeholder="example.user@stellarcyber.ai",
            value=config["user"],
        )

        stellar_api_key = st.text_input(
            "Stellar Cyber API Key",
            type="password",
            help="The Stellar Cyber API Key for the User",
            placeholder="API Key",
            value=config["api_key"],
        )

        stellar_detections_version = st.selectbox(
            "Stellar Cyber Platform Version",
            help="The version of the Stellar Cyber Platform we are connecting to.",
            options=["4.3.0", "4.3.1", "4.3.7", "5.1.x", "5.2.x", "5.3.x"],
            index=4,
        )

        stellar_verify_ssl = st.checkbox(
            "Verify SSL",
            help="Check to verify the SSL of the Stellar Cyber Host",
            value=config["verify_ssl"],
        )

        submitted = st.form_submit_button("Submit")

        if submitted:
            # Validate inputs
            if not stellar_cyber_host:
                st.error("Host is required")
                return
            if not stellar_cyber_user:
                st.error("User is required")
                return
            if not stellar_api_key:
                st.error("API Key is required")
                return

            config = {
                "host": stellar_cyber_host,
                "user": stellar_cyber_user,
                "api_key": stellar_api_key,
                "version": stellar_detections_version,
                "verify_ssl": stellar_verify_ssl,
            }

            try:
                callback(config)
                st.success("Configuration saved successfully!")
                st.rerun()
            except Exception as e:
                logger.exception(f"Error saving configuration: {str(e)}")
                st.error(f"Error saving configuration: {str(e)}")


# @st.fragment
def analyze_coverage():
    """Display and manage the coverage analysis interface with improved UX."""
    try:
        data_source_options = st.session_state.stca.get_detections_datasources(
            as_options=True
        )
        timeframe = st.session_state.selected_timeframe
        tenant = (
            st.session_state.selected_tenant
            if st.session_state.selected_tenant != "All Tenants"
            else None
        )

        # Initialize data sources if needed
        if not st.session_state.get("selected_data_sources"):
            with st.spinner("Loading data sources..."):
                used_datasources = st.session_state.stca.get_used_datasources(
                    timeframe[0], timeframe[1], tenant
                )
                st.session_state.selected_data_sources = used_datasources

        # Data Sources Section
        st.subheader("Data Sources", divider=True)
        st.caption(
            "Data sources used for coverage analysis. Auto populated from configured data sources in the defined tenant/timeframe. Any additional data sources can be selected to model additional coverage."
        )
        selected_data_sources = st.multiselect(
            label="Configured Data Sources",
            options=data_source_options,
            key="selected_data_sources",
            help="Select data sources to analyze coverage",
        )

        with st.spinner("Calculating metrics..."):
            compiled_stats: dict[str, dict[str, Any]] = (
                st.session_state.stca.compile_stats(
                    selected_data_sources,
                    timeframe[0],
                    timeframe[1],
                    tenant,
                )
            )

        # Metrics Section
        display_metrics(compiled_stats)

        # Coverage Tables Section
        display_coverage_tables(compiled_stats)

        # Recommendations Section
        display_recommendations(
            data_source_options, st.session_state.selected_data_sources
        )

        # Coverage Matrix Section
        display_coverage_matrix(compiled_stats)
        display_raw_json(compiled_stats)

    except Exception as e:
        logger.exception(f"Error in analyze_coverage: {str(e)}")
        st.error(
            "An error occurred while analyzing coverage. Please check the logs for details."
        )


@st.cache_data(ttl=600)
def display_raw_json(compiled_stats: dict[str, dict[str, Any]]):
    st.expander(
        "Raw Coverage JSON Data", expanded=False, icon=":material/code:"
    ).markdown(f"""
               ```json
               {json.dumps(compiled_stats.get("alert_types", {}).get("alert_type_stats", {}).get("alert_type_details", []), indent=2)}
               ```
               """)


@st.cache_data
def display_metrics(compiled_stats: dict[str, dict[str, Any]]):
    st.subheader("Metrics", divider=True)
    st.caption(
        "Summary of coverage metrics based on selected data sources and time period."
    )

    # Display metrics in columns
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            label="Tactics Covered",
            value=f"{compiled_stats.get('tactics', {}).get('tactics_covered_per', 0):.0%}",
            help="Percentage of tactics covered by selected data sources",
        )
        st.divider()
        with st.container():
            st.markdown("#### Tactics")
            st.markdown(
                f"Number of Tactics in XDR Kill Chain: **:orange[{compiled_stats.get('tactics', {}).get('tactics_available', 0)}]**"
            )
            st.markdown(
                f"Number of Tactics covered with data sources: **:orange[{compiled_stats.get('tactics', {}).get('tactics_covered', 0)}]**"
            )
            st.markdown(
                f"Number of Tactics triggered in time period: **:orange[{compiled_stats.get('tactics', {}).get('tactics_triggered', 0)}]**"
            )

    with col2:
        st.metric(
            label="Techniques Covered",
            value=f"{compiled_stats.get('techniques', {}).get('techniques_covered_per', 0):.0%}",
            help="Percentage of techniques covered by selected data sources",
        )
        st.divider()
        with st.container():
            st.markdown("#### Techniques")
            st.markdown(
                f"Number of Techniques in XDR Kill Chain: **:orange[{compiled_stats.get('techniques', {}).get('techniques_available', 0)}]**"
            )
            st.markdown(
                f"Number of Techniques covered with data sources: **:orange[{compiled_stats.get('techniques', {}).get('techniques_covered', 0)}]**"
            )
            st.markdown(
                f"Number of Techniques triggered in time period: **:orange[{compiled_stats.get('techniques', {}).get('techniques_triggered', 0)}]**"
            )

    with col3:
        st.metric(
            label="Alert Types Covered",
            value=f"{compiled_stats.get('alert_types', {}).get('alert_types_covered_per', 0):.0%}",
            help="Percentage of alert types covered by selected data sources",
        )
        st.divider()
        with st.container():
            st.markdown("#### Alert Types")
            st.markdown(
                f"Number of Alert Types in XDR Kill Chain: **:orange[{compiled_stats.get('alert_types', {}).get('alert_types_available', 0)}]**"
            )
            st.markdown(
                f"Number of Alert Types covered with data sources: **:orange[{compiled_stats.get('alert_types', {}).get('alert_types_covered', 0)}]**"
            )
            st.markdown(
                f"Number of Alert Types triggered in time period: **:orange[{compiled_stats.get('alert_types', {}).get('alert_types_triggered', 0)}]**"
            )


def display_coverage_tables(compiled_stats: dict[str, dict[str, Any]]):
    st.subheader("Coverage Tables", divider=True)

    st.caption(
        "Use the search box to filter results. Tables are sortable by clicking on the column headers. Tables default to being sorted by the 'Covered' column in descending order.",
    )

    tab1, tab2, tab3 = st.tabs(["Tactics", "Techniques", "Alert Types"])

    with tab1:
        display_tactics_table(compiled_stats)

    with tab2:
        display_techniques_table(compiled_stats)

    with tab3:
        display_alert_types_table(compiled_stats)


def display_coverage_matrix(compiled_stats: dict[str, dict[str, Any]]):
    st.subheader("Coverage Matrix", divider=True)
    st.caption(
        "Visual representation of detection coverage based on selected data sources. Uses either the MITRE ATT&CK® Navigator or a Plotly Chart for visualization."
    )
    # st.info(
    #     "The Coverage Matrix provides a visual representation of your detection coverage. "
    #     "Darker colors indicate higher coverage. Click cells for details.",
    #     icon="ℹ️",
    # )

    # Generate technique scores based on coverage data
    technique_scores = {}
    technique_stats = compiled_stats.get("techniques", {}).get("technique_stats", {})
    custom_detections = st.session_state.stca.get_custom_detections()

    technique_ids_map: dict[str, str] = {
        cd.get("xdr_event", {}).get("technique", {}).get("name", ""): cd.get(
            "xdr_event", {}
        )
        .get("technique", {})
        .get("id", "")
        for cd in custom_detections
    }

    for tactic_techniques in technique_stats.values():
        for technique_id, stats in tactic_techniques.items():
            available = stats.get("total_alert_types_available", 0)
            covered = stats.get("total_alert_types_covered", 0)
            score = (covered / available * 100) if available > 0 else 0

            if technique_id in technique_ids_map:
                technique_scores[technique_ids_map[technique_id]] = score
            elif str(technique_id).removeprefix("X") in technique_ids_map:
                sub_technique_id = str(technique_id).removeprefix("X")
                technique_scores[technique_ids_map[sub_technique_id]] = score
                logger.debug(
                    f"Technique ID: {technique_id} not found in Mitre Techniques, but {sub_technique_id} was. Using {sub_technique_id} instead."
                )
            else:
                technique_scores[technique_id] = score
                logger.debug(
                    f"Technique ID: {technique_id} not found in Mitre Techniques. Skipping it."
                )

    # Generate navigator layer
    navigator_layer = st.session_state.stca.generate_navigator_layer(
        name="Stellar Cyber Coverage Analysis",
        techniques_with_scores=technique_scores,
        description="Coverage analysis of Stellar Cyber detections",
    )

    matrix_type = st.radio(
        "Matrix Type",
        options=["Plotly Chart", "MITRE ATT&CK® Navigator"],
        index=0,
        key="matrix_type",
        horizontal=True,
    )

    col1, col2, col3, col4 = st.columns(4)
    with col3:
        st.download_button(
            label="Download as MITRE ATT&CK® Navigator Layer",
            data=json.dumps(navigator_layer, indent=2),
            file_name="stellar-mitre-coverage.json",
            mime="application/json",
            help="Download Coverage as MITRE ATT&CK® Navigator layer JSON file",
        )

    with col4:
        st.link_button(
            "Open MITRE ATT&CK® Navigator in new tab",
            "https://mitre-attack.github.io/attack-navigator/",
            help="Open MITRE ATT&CK® Navigator in a new tab to import the coverage layer.",
        )

    st.divider()

    if matrix_type == "Plotly Chart":
        alert_types_table: dict[str, Any] = create_alert_types_table(compiled_stats)
        create_coverage_matrix(alert_types_table)
    else:
        components.iframe(
            "https://mitre-attack.github.io/attack-navigator/",
            scrolling=True,
            height=800,
        )

    # alert_types_table: dict[str, Any] = create_alert_types_table(compiled_stats)
    # chart_state = create_coverage_matrix(alert_types_table)
    # logger.debug(f"Chart State: {chart_state.get('selection')}")  # type: ignore


def display_tactics_table(compiled_stats: dict[str, dict[str, Any]]):
    """Display tactics table with improved formatting and interaction."""
    tactics_table = []
    for key, value in compiled_stats.get("tactics", {}).get("tactic_stats", {}).items():
        tactics_table.append(
            {
                "tactic": key,
                "available": value.get("total_alert_types_available", 0) > 0,
                "covered": value.get("total_alert_types_covered", 0) > 0,
                "triggered": value.get("total_alert_types_triggered", 0) > 0,
                "recommended": value.get("recommended_data_sources", []),
            }
        )

    tactics_table_df = pl.DataFrame(tactics_table).sort(
        by=[pl.col("covered")], descending=True
    )
    st.dataframe(
        data=tactics_table_df,
        use_container_width=True,
        hide_index=True,
        column_order=["tactic", "available", "covered", "triggered", "recommended"],
        column_config={
            "tactic": st.column_config.TextColumn(
                label="Tactic", width="medium", help="Tactic Name"
            ),
            "available": st.column_config.CheckboxColumn(
                label="Available",
                width="small",
                help="Whether Alert types are available",
            ),
            "covered": st.column_config.CheckboxColumn(
                label="Covered", width="small", help="Whether Alert Types are covered"
            ),
            "triggered": st.column_config.CheckboxColumn(
                label="Triggered",
                width="small",
                help="Whether Alert Types were triggered",
            ),
            "recommended": st.column_config.ListColumn(
                label="Recommended Data Sources",
                width="large",
                help="Recommended Data Sources",
            ),
        },
    )


def display_techniques_table(compiled_stats: dict[str, dict[str, Any]]):
    """Display techniques table with improved formatting and interaction."""
    techniques_table = []
    for key, value in (
        compiled_stats.get("techniques", {}).get("technique_stats", {}).items()
    ):
        for technique, stats in value.items():
            techniques_table.append(
                {
                    "tactic": key,
                    "technique": technique,
                    "available": stats.get("total_alert_types_available", 0) > 0,
                    "covered": stats.get("total_alert_types_covered", 0) > 0,
                    "triggered": stats.get("total_alert_types_triggered", 0) > 0,
                    "recommended": stats.get("recommended_data_sources", []),
                }
            )

    techniques_table_df = pl.DataFrame(techniques_table).sort(
        by=[pl.col("covered")], descending=True
    )
    st.dataframe(
        data=techniques_table_df,
        use_container_width=True,
        hide_index=True,
        column_order=[
            "tactic",
            "technique",
            "available",
            "covered",
            "triggered",
            "recommended",
        ],
        column_config={
            "tactic": st.column_config.TextColumn(
                label="Tactic", width="small", help="Tactic Name"
            ),
            "technique": st.column_config.TextColumn(
                label="Technique", width="medium", help="Technique Name"
            ),
            "available": st.column_config.CheckboxColumn(
                label="Available",
                width="small",
                help="Whether Alert types are available",
            ),
            "covered": st.column_config.CheckboxColumn(
                label="Covered", width="small", help="Whether Alert Types are covered"
            ),
            "triggered": st.column_config.CheckboxColumn(
                label="Triggered",
                width="small",
                help="Whether Alert Types were triggered",
            ),
            "recommended": st.column_config.ListColumn(
                label="Recommended Data Sources",
                width="medium",
                help="Recommended Data Sources",
            ),
        },
    )


def display_alert_types_table(compiled_stats: dict[str, dict[str, Any]]):
    """Display alert types table with improved formatting and interaction."""
    alert_types_table = (
        compiled_stats.get("alert_types", {})
        .get("alert_type_stats", {})
        .get("alert_type_details", [])
    )
    alert_types_table_df = pl.DataFrame(alert_types_table).sort(
        by=[pl.col("covered")], descending=True
    )
    st.dataframe(
        data=alert_types_table_df,
        use_container_width=True,
        hide_index=True,
        column_order=[
            "tactic",
            "technique",
            "alert_type",
            "covered",
            "triggered",
            "recommended_data_sources",
        ],
        column_config={
            "tactic": st.column_config.TextColumn(
                label="Tactic", width="small", help="Tactic Name"
            ),
            "technique": st.column_config.TextColumn(
                label="Technique", width="small", help="Technique Name"
            ),
            "alert_type": st.column_config.TextColumn(
                label="Alert Type", width="medium", help="Alert Type Name"
            ),
            "covered": st.column_config.CheckboxColumn(
                label="Covered", width="small", help="Whether the Alert Type is covered"
            ),
            "triggered": st.column_config.CheckboxColumn(
                label="Triggered",
                width="small",
                help="Whether the Alert Type was triggered",
            ),
            "recommended_data_sources": st.column_config.ListColumn(
                label="Recommended Data Sources",
                width="large",
                help="Recommended Data Sources",
            ),
        },
    )


def display_recommendations(
    data_source_options: list[str], selected_data_sources: list[str]
) -> None:
    """Display data source recommendations with improved formatting."""
    st.subheader("Recommended Data Sources", divider=True)
    st.caption(
        "Table of all the data sources NOT configured (or selected if modeling additional data sources) and their associated counts of Tactics, Techniques, and Alert Types covered."
    )
    try:
        ds_stats = st.session_state.stca.get_datasource_stats(
            [ds for ds in data_source_options if ds not in selected_data_sources]
        )

        ds_stats_table = [
            {
                "data_source": ds_stat.get("data_source", ""),
                "tactics_covered": len(ds_stat.get("tactics_covered", [])),
                "tactics_covered_list": ds_stat.get("tactics_covered", []),
                "techniques_covered": len(ds_stat.get("techniques_covered", [])),
                "techniques_covered_list": ds_stat.get("techniques_covered", []),
                "alert_types_covered": len(ds_stat.get("alert_types_covered", [])),
                "alert_types_covered_list": ds_stat.get("alert_types_covered", []),
            }
            for ds_stat in ds_stats
        ]

        ds_stats_df = pl.DataFrame(ds_stats_table).sort(
            by=[pl.col("alert_types_covered"), pl.col("techniques_covered")],
            descending=True,
        )
        st.dataframe(
            ds_stats_df,
            use_container_width=True,
            hide_index=True,
            column_order=[
                "data_source",
                "tactics_covered",
                "techniques_covered",
                "alert_types_covered",
            ],
            column_config={
                "data_source": st.column_config.TextColumn(
                    label="Data Source", width="medium", help="Data Source Name"
                ),
                "tactics_covered": st.column_config.NumberColumn(
                    label="Tactics Covered",
                    width="small",
                    help="Number of Tactics Covered",
                ),
                "techniques_covered": st.column_config.NumberColumn(
                    label="Techniques Covered",
                    width="small",
                    help="Number of Techniques Covered",
                ),
                "alert_types_covered": st.column_config.NumberColumn(
                    label="Alert Types Covered",
                    width="small",
                    help="Number of Alert Types Covered",
                ),
            },
        )
        with st.sidebar:
            st.subheader("Data Source Recommendations", divider=True)
            st.dataframe(
                ds_stats_df.select(pl.col("data_source").head(10).alias("Top 10")),
                hide_index=True,
                use_container_width=True,
            )
            st.caption(
                "Based on your currently installed data sources and your calculated coverage, these are the top 10 recommended data sources to add to make the most impact to improving your coverage based on the number of techniques and alert types related to these data sources.",
            )
    except Exception as e:
        logger.exception(f"Error displaying recommendations: {str(e)}")
        st.error("Error displaying recommendations. Please try refreshing the page.")


def create_alert_types_table(
    compiled_stats: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Create alert types DataFrame for visualization."""
    alert_types_table = (
        compiled_stats.get("alert_types", {})
        .get("alert_type_stats", {})
        .get("alert_type_details", [])
    )
    return alert_types_table
