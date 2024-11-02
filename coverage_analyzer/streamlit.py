import json

# import os
# from collections.abc import Callable
# from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

# import machineid
import pandas as pd
import polars as pl
import streamlit as st

# from st_cookies_manager import EncryptedCookieManager
from streamlit import cache_data, cache_resource
# from streamlit.runtime.scriptrunner import add_script_run_ctx

# from coverage_analyzer import __version__
from coverage_analyzer.mitre import StellarMitre
from coverage_analyzer.stellar import StellarCyberAPI
from coverage_analyzer.vars import (
    APP_DIR,
    DATASOURCE_DISPLAY_NAME_MAP,
    STELLAR_EXTRA_TACTICS_MAP,
    # get_thread_pool_executor,
    logger,
    # read_hosts_config,
)


# class CoverageAnalyzerApp:
#     """Main Streamlit application class for Coverage Analyzer."""

#     cookies: EncryptedCookieManager | None = None
#     thread_executor: ThreadPoolExecutor | None = None

#     def __init__(self):
#         """Initialize the Coverage Analyzer streamlit session_state."""
#         self._init_state()

#     def _init_state(self):
#         """Initialize application state and configuration."""
#         st.set_page_config(
#             page_title="Coverage Analyzer",
#             page_icon="docs/images/logo.png",
#             layout="wide",
#             initial_sidebar_state="expanded",
#             menu_items={
#                 "Get Help": "https://github.com/yourusername/coverage-analyzer/issues",
#                 "Report a bug": "https://github.com/yourusername/coverage-analyzer/issues/new",
#                 "About": f"Coverage Analyzer v{__version__}",
#             },
#         )
#         if not st.session_state.get("initialized", False):
#             self.cookies = EncryptedCookieManager(
#                 prefix="coverage-analyzer/",
#                 password=os.environ.get(
#                     "STCA_COOKIES_PASSWORD", machineid.hashed_id("coverage-analyzer")
#                 ),
#             )
#             self.thread_executor = get_thread_pool_executor()
#             for t in self.thread_executor._threads:
#                 add_script_run_ctx(t)

#             if not self.cookies.ready():
#                 st.stop()

#             logger.info("Loading saved host configs into session state.")

#             configs = {}
#             global_configs = read_hosts_config()
#             cookie_configs = json.loads(self.cookies.get("configs", "{}"))
#             configs.update(global_configs)
#             configs.update(cookie_configs)
#             st.session_state.configs = configs
#             st.session_state.initialized = True

#     def background_run(self, func: Callable, callback: Callable | None = None) -> None:
#         """Run a function in the background with an optional callback."""
#         if self.thread_executor is not None:
#             future = self.thread_executor.submit(func)
#             logger.info(f"Started background task: {func.__name__}.")
#             if callback is not None:
#                 future.add_done_callback(callback)
#                 logger.info(
#                     f"Added callback: {callback.__name__} to background task: {func.__name__}."
#                 )
#         else:
#             logger.error("Thread pool executor not initialized.")
#             logger.error(f"Cannot run background task: {func.__name__}.")

#     def header(self):
#         """Display the application header."""
#         st.title("Coverage Analyzer")
#         st.caption(f"Version: {__version__}")
#         st.subheader("Overview", divider=True)

#         # Show overview in expander
#         with st.expander(
#             "",
#             expanded=not st.session_state.get("selected_tenant", False)
#             or not st.session_state.get("selected_timeframe", False),
#             icon=":material/help:",
#         ):
#             from coverage_analyzer.vars import OVERVIEW_MARKDOWN

#             st.markdown(
#                 OVERVIEW_MARKDOWN,
#                 unsafe_allow_html=True,
#             )

#     def sidebar(self):
#         """Display and manage the sidebar interface."""
#         from coverage_analyzer.callbacks import refresh_state, save_state
#         from coverage_analyzer.ui import analyze_coverage, config_dialog

#         st.sidebar.selectbox(
#             "Select Configuration",
#             options=st.session_state.get("configs", {}).keys(),
#             key="config",
#             help="Select a saved configuration to load",
#             on_change=refresh_state,
#         )

#         left, middle, right = st.sidebar.columns(3)
#         if left.button(label="", icon=":material/add:", use_container_width=True):
#             config_dialog(callback=save_state, edit=False)

#         if middle.button(
#             label="",
#             icon=":material/edit:",
#             disabled=not st.session_state.config,
#             use_container_width=True,
#         ):
#             config_dialog(callback=save_state, edit=True)

#         if right.button(
#             label="",
#             icon=":material/delete:",
#             disabled=not st.session_state.config,
#             use_container_width=True,
#         ):
#             if st.session_state.config:
#                 configs = st.session_state.configs
#                 del configs[st.session_state.config]
#                 st.session_state.configs = configs
#                 self.cookies["configs"] = json.dumps(configs)  # type: ignore
#                 self.cookies.save()  # type: ignore
#                 st.session_state.config = None

#         if st.session_state.config:
#             refresh_state()
#             tenant_options = st.session_state.stca.get_tenants()
#             tenant_options.insert(0, "All Tenants")
#             st.sidebar.divider()
#             st.sidebar.selectbox(
#                 label="Select Tenant",
#                 options=tenant_options,
#                 key="selected_tenant",
#                 index=None,
#             )
#             st.sidebar.date_input(
#                 "Time Range",
#                 value=[
#                     datetime.now(tz=timezone.utc).date() - timedelta(days=7),
#                     datetime.now(tz=timezone.utc).date(),
#                 ],
#                 help="Select the time range to run the dashboard for.",
#                 key="selected_timeframe",
#             )
#             st.sidebar.divider()
#             if not st.session_state.get(
#                 "selected_tenant", False
#             ) or not st.session_state.get("selected_timeframe", False):
#                 st.stop()

#             analyze_coverage()

#         else:
#             st.sidebar.warning(
#                 "No saved configurations found in cookies. Please add one to connect to Stellar Cyber API and use dashboard."
#             )

#     def run(self):
#         """Run the Streamlit application."""
#         self.header()
#         self.sidebar()


class StreamlitCoverageAnalyzerClient:
    """
    This class is used by a streamlit app to interact with the Stellar Cyber API and MITRE ATT&CK framework

    This class introduces caching and streamlit session management of data using coverage_analyzer.stellar.StellarCyberAPI and coverage_analyzer.mitre.StellarMitre classes.

    Args:
        host: Stellar Cyber host URL (e.g. https://example.stellarcyber.cloud)
        username: Stellar Cyber username (Generally an email address)
        api_key: Stellar Cyber API key
        version: Stellar Cyber Platform version, defaults to "5.2.x"
        verify_ssl: Boolean to verify SSL of Stellar Cyber Host, defaults to True
        cache_ttl: The time to live for cached data, defaults to 15m.

    Attributes:
        version: The version of the Stellar Cyber Platform to interact with.
        cache_ttl: The time to live for cached data.

    """

    def __init__(
        self,
        name: str,
        host: str,
        username: str,
        api_key: str,
        version: Literal[
            "5.3.x", "5.2.x", "5.1.x", "4.3.7", "4.3.1", "4.3.0"
        ] = "5.2.x",
        verify_ssl: bool | None = None,
        cache_ttl: float | timedelta | str | None = "15m",
    ):
        self.version: Literal["5.3.x", "5.2.x", "5.1.x", "4.3.7", "4.3.1", "4.3.0"] = (
            version
        )
        self.name: str = name
        self.host: str = host
        self.cache_ttl: float | timedelta | str | None = cache_ttl
        self._stellar: StellarCyberAPI = StellarCyberAPI(
            host, username, api_key, version, bool(verify_ssl)
        )
        self._mitre: StellarMitre = StellarMitre()

        self._start_date: date = datetime.now(tz=timezone.utc).date() - timedelta(
            days=7
        )

        self._end_date: date = datetime.now(tz=timezone.utc).date()

        self._cache: dict[str, Any] = {}

    @st.cache_resource(ttl=600)
    @staticmethod
    def get_scstca_client(
        name: str,
        host: str,
        username: str,
        api_key: str,
        version: Literal[
            "5.3.x", "5.2.x", "5.1.x", "4.3.7", "4.3.1", "4.3.0"
        ] = "5.2.x",
        verify_ssl: bool | None = None,
    ):
        return StreamlitCoverageAnalyzerClient(
            name, host, username, api_key, version, verify_ssl
        )

    @logger.catch
    def generate_navigator_layer(
        self,
        name: str,
        techniques_with_scores: dict[str, float],
        description: str | None = None,
    ) -> dict[str, Any]:
        """
        Public method to generate a MITRE ATT&CK Navigator layer file.

        Args:
            name: Name of the layer
            techniques_with_scores: Dictionary mapping technique IDs to scores (0-100)
            description: Optional description of the layer

        Returns:
            Dictionary containing the ATT&CK Navigator layer data
        """
        return self._mitre.generate_navigator_layer(
            name=name,
            techniques_with_scores=techniques_with_scores,
            description=description,
        )

    @logger.catch
    def get_tactics(self) -> list[dict[str, str]]:
        """
        Public method to return a list of tactics from the MITRE ATT&CK framework.

        Returns:
            List of tactics as dictionaries.
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_tactics(
            _self: StreamlitCoverageAnalyzerClient,
        ) -> list[dict[str, Any]]:
            return _self._mitre.get_tactics()

        return _get_tactics(self)

    @logger.catch
    def get_tactics_and_techniques(self) -> list[dict[str, Any]]:
        """
        Public method to return a dictionary of tactics and techniques from the MITRE ATT&CK framework.

        Returns:
            Dictionary of tactics and techniques.
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_tactics_and_techniques(
            _self: StreamlitCoverageAnalyzerClient,
        ) -> list[dict[str, Any]]:
            return _self._mitre.get_tactics_and_techniques()

        return _get_tactics_and_techniques(self)

    @logger.catch
    def get_alert_type_hits(
        self, start_date: date, end_date: date, tenant_name: str | None = None
    ) -> dict[str, Any]:
        """
        Public method to return a dictionary of alert type hits from Stellar Cyber API

        Args:
            start_date: The start date to filter alert type hits by.
            end_date: The end date to filter alert type hits by.
            tenant_name: The tenant name to filter alert type hits by.

        Returns:
            Dictionary of alert type hits.
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_alert_type_hits(
            _self: StreamlitCoverageAnalyzerClient,
            start_date: date,
            end_date: date,
            tenant_name: str | None = None,
        ):
            return _self._stellar.alert_stats(
                start_date=start_date, end_date=end_date, tenant=tenant_name
            )

        return _get_alert_type_hits(self, start_date, end_date, tenant_name).get(
            "alert_type_hits", {}
        )

    @logger.catch
    def get_matching_alert_types_count_from_hits(
        self,
        alert_type_hits: dict[str, Any],
        tactic: str,
        technique: str | None = None,
    ) -> int:
        """
        Public method to return a count of matching alert types based on hits from Stellar Cyber API

        Args:
            alert_type_hits: The alert type hits dictionary to filter alert types by.
            tactic: The tactic to filter alert types by.
            technique: The technique to filter alert types by.

        Returns:
            Count of matching alert types.
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_matching_alert_types_count_from_hits(
            _self: StreamlitCoverageAnalyzerClient,
            alert_type_hits: dict[str, Any],
            tactic: str,
            technique: str | None,
        ):
            detections_df = pd.DataFrame(_self.get_detections())
            # Create a query to filter the dataframe
            # The query checks if the 'XDR Tactic' column matches the given tactic
            # and if the 'XDR Display Name' column is in the list of hit alert types
            query = (detections_df["XDR Tactic"] == tactic) & (
                detections_df["XDR Display Name"].isin(alert_type_hits)
            )

            # If a technique is given, add it to the query
            # The query now also checks if the 'XDR Technique' column matches the given technique
            if technique:
                query &= detections_df["XDR Technique"] == technique

            # Apply the query to the dataframe and return the number of rows in the resulting dataframe
            return detections_df[query].shape[0]

        return _get_matching_alert_types_count_from_hits(
            self, alert_type_hits, tactic, technique
        )

    @logger.catch
    def get_matching_alert_types_count_from_ds(
        self, data_sources: list[str], tactic: str, technique: str | None = None
    ) -> int:
        """
        Public method to return a count of matching alert types based on data sources from Stellar Cyber API

        Args:
            data_sources: The data sources to filter alert types by.
            tactic: The tactic to filter alert types by.
            technique: The technique to filter alert types by.

        Returns:
            Count of matching alert types.
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_matching_alert_types_count_from_ds(
            _self: StreamlitCoverageAnalyzerClient,
            data_sources: list[str],
            tactic: str,
            technique: str | None,
        ):
            detections_df = pd.DataFrame(_self.get_detections())
            # datasources = _self.get_detections_datasources(as_options=True)
            # Create a boolean mask for rows where the tactic matches
            tactic_mask = detections_df["XDR Tactic"] == tactic

            # Create a boolean mask for rows where the technique matches (if technique is not None)
            technique_mask = (
                detections_df["XDR Technique"] == technique if technique else True
            )

            # Create a boolean mask for rows where any of the data sources match
            data_sources_mask = detections_df["data_sources_combined"].apply(
                lambda x: any(item in x for item in data_sources)
            )

            # Return the count of rows where all masks are True
            return detections_df[
                tactic_mask & technique_mask & data_sources_mask
            ].shape[0]

        return _get_matching_alert_types_count_from_ds(
            self, data_sources, tactic, technique
        )

    @logger.catch
    def get_tactics_stats(
        self,
        data_sources: list[str],
        start_date: date,
        end_date: date,
        tenant_name: str | None = None,
        with_recommendations: bool | None = None,
    ) -> dict[str, Any]:
        """
        Public method to return a dictionary of statistics for the provided list of tactics from the MITRE ATT&CK framework.

        Args:
            data_sources: The data sources to filter statistics by.
            start_date: The start date to filter statistics by.
            end_date: The end date to filter statistics by.
            tenant_name: The tenant name to filter statistics by.
            with_recommendations: If True, include recomendations in the statistics. Defaults to False.

        Returns:
            Dictionary of tactics statistics for the provided list of tactics.
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_tactics_stats(
            _self: StreamlitCoverageAnalyzerClient,
            data_sources: list[str],
            start_date: date,
            end_date: date,
            tenant_name: str | None = None,
            with_recommendations: bool | None = None,
        ):
            tactic_stats = {}
            tactics = tactics = [tactic["name"] for tactic in _self.get_tactics()]
            detections_df = pl.DataFrame(_self.get_detections())
            alert_type_hits = _self.get_alert_type_hits(
                start_date, end_date, tenant_name
            )
            for tactic in tactics:
                if tactic not in tactic_stats:
                    tactic_stats[tactic] = {}
                tactic_stats[tactic]["total_alert_types_available"] = (
                    detections_df.filter(
                        (pl.col("XDR Tactic") == tactic)
                        | (
                            pl.col("XDR Tactic").is_in(
                                STELLAR_EXTRA_TACTICS_MAP.get(tactic, [])
                            )
                        )
                    ).shape[0]
                )
                tactic_stats[tactic]["total_alert_types_covered"] = (
                    _self.get_matching_alert_types_count_from_ds(
                        data_sources, tactic, None
                    )
                )
                tactic_stats[tactic]["total_alert_types_triggered"] = (
                    _self.get_matching_alert_types_count_from_hits(
                        alert_type_hits, tactic, None
                    )
                )
                if with_recommendations:
                    if tactic_stats[tactic]["total_alert_types_covered"] == 0:
                        recommendended_datasources = (
                            detections_df.filter(
                                (pl.col("XDR Tactic") == tactic)
                                | (
                                    pl.col("XDR Tactic").is_in(
                                        STELLAR_EXTRA_TACTICS_MAP.get(tactic, [])
                                    )
                                )
                            )
                            .select(pl.col("data_sources_combined").explode().unique())
                            .to_dict()
                        )
                        tactic_stats[tactic]["recommended_data_sources"] = [
                            ds
                            for ds in recommendended_datasources.get(
                                "data_sources_combined", []
                            )
                            if ds not in data_sources
                        ]
                    else:
                        tactic_stats[tactic]["recommended_data_sources"] = []

            return tactic_stats

        return _get_tactics_stats(
            self, data_sources, start_date, end_date, tenant_name, with_recommendations
        )

    @logger.catch
    def get_technique_stats(
        self,
        data_sources: list[str],
        start_date: date,
        end_date: date,
        tenant_name: str | None = None,
        with_recommendations: bool | None = None,
    ) -> dict[str, Any]:
        """
        Public method to return a dictionary of statistics for the provided list of tactics and their techniques from the MITRE ATT&CK framework.

        Args:
            data_sources: The data sources to filter statistics by.
            start_date: The start date to filter statistics by.
            end_date: The end date to filter statistics by.
            tenant_name: The tenant name to filter statistics by.
            with_recommendations: If True, include recomendations in the statistics. Defaults to False.

        Returns:
            Dictionary of technique statistics for the provided list of tactics.
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_technique_stats(
            _self: StreamlitCoverageAnalyzerClient,
            data_sources: list[str],
            start_date: date,
            end_date: date,
            tenant_name: str | None = None,
            with_recommendations: bool | None = None,
        ):
            technique_stats = {}
            tactics = [tactic["name"] for tactic in _self.get_tactics()]
            detections_df = pl.DataFrame(_self.get_detections())
            # custom_detections = pl.DataFrame(_self.get_custom_detections(tenant_name))
            alert_type_hits = _self.get_alert_type_hits(
                start_date, end_date, tenant_name
            )

            for tactic in tactics:
                technique_stats[tactic] = {}
                for technique in detections_df.filter(
                    (pl.col("XDR Tactic") == tactic)
                    | (
                        pl.col("XDR Tactic").is_in(
                            STELLAR_EXTRA_TACTICS_MAP.get(tactic, [])
                        )
                    )
                )["XDR Technique"].unique():
                    technique_stats[tactic][technique] = {}
                    technique_stats[tactic][technique][
                        "total_alert_types_available"
                    ] = detections_df.filter(
                        (
                            (pl.col("XDR Tactic") == tactic)
                            | (
                                pl.col("XDR Tactic").is_in(
                                    STELLAR_EXTRA_TACTICS_MAP.get(tactic, [])
                                )
                            )
                        )
                        & (pl.col("XDR Technique") == technique)
                    ).shape[0]
                    technique_stats[tactic][technique]["total_alert_types_covered"] = (
                        _self.get_matching_alert_types_count_from_ds(
                            data_sources, tactic, technique
                        )
                    )
                    technique_stats[tactic][technique][
                        "total_alert_types_triggered"
                    ] = _self.get_matching_alert_types_count_from_hits(
                        alert_type_hits, tactic, technique
                    )
                    if with_recommendations:
                        if (
                            technique_stats[tactic][technique][
                                "total_alert_types_covered"
                            ]
                            == 0
                        ):
                            recommendended_datasources = (
                                detections_df.filter(
                                    (
                                        (pl.col("XDR Tactic") == tactic)
                                        | (
                                            pl.col("XDR Tactic").is_in(
                                                STELLAR_EXTRA_TACTICS_MAP.get(
                                                    tactic, []
                                                )
                                            )
                                        )
                                    )
                                    & (pl.col("XDR Technique") == technique)
                                )
                                .select(
                                    pl.col("data_sources_combined").explode().unique()
                                )
                                .to_dict()
                            )
                            technique_stats[tactic][technique][
                                "recommended_data_sources"
                            ] = [
                                ds
                                for ds in recommendended_datasources.get(
                                    "data_sources_combined", []
                                )
                                if ds not in data_sources
                            ]
                        else:
                            technique_stats[tactic][technique][
                                "recommended_data_sources"
                            ] = []

            return technique_stats

        return _get_technique_stats(
            self, data_sources, start_date, end_date, tenant_name, with_recommendations
        )

    @logger.catch
    def get_alert_stats(
        self,
        alert_type_hits: dict[str, Any],
        data_sources: list[str],
        with_recommendations: bool | None = None,
    ) -> dict[str, Any]:
        """
        Public method to return a dictionary of alert statistics from Stellar Cyber API

        Args:
            alert_type_hits: The alert type hits dictionary to filter alert statistics by.
            data_sources: The data sources to filter alert statistics by.
            with_recommendations: If True, include recomendations in the statistics. Defaults to False.

        Returns:
            Dictionary of alert statistics.
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_alert_stats(
            _self: StreamlitCoverageAnalyzerClient,
            alert_type_hits: dict[str, Any],
            data_sources: list[str],
            with_recommendations: bool | None = None,
        ):
            detections_df = pl.DataFrame(_self.get_detections())
            alert_type_stats = {
                "total_alert_types_available": detections_df.shape[0],
                "total_alert_types_triggered": len(alert_type_hits),
                "alert_type_details": [],
            }
            count = 0
            for row in detections_df.iter_rows(named=True):
                detail = {
                    "alert_type": row["XDR Display Name"],
                    "tactic": row["XDR Tactic"],
                    "technique": row["XDR Technique"],
                }
                if any(item in row["data_sources_combined"] for item in data_sources):
                    count += 1
                    detail["covered"] = True
                else:
                    detail["covered"] = False
                detail["triggered"] = False
                if (
                    row["XDR Display Name"] in alert_type_hits
                    and alert_type_hits[row["XDR Display Name"]] > 0
                ):
                    detail["triggered"] = True

                if with_recommendations:
                    if not detail["covered"]:
                        detail["recommended_data_sources"] = [
                            ds
                            for ds in row["data_sources_combined"]
                            if ds not in data_sources
                        ]
                    else:
                        detail["recommended_data_sources"] = []

                alert_type_stats["alert_type_details"].append(detail)
            alert_type_stats["total_alert_types_covered"] = count
            return alert_type_stats

        return _get_alert_stats(
            self, alert_type_hits, data_sources, with_recommendations
        )

    @logger.catch
    def get_datasource_stats(self, data_sources: list[str]) -> list[dict[str, Any]]:
        """
        Public method to return a dictionary of data source statistics from Stellar Cyber API

        Args:
            data_sources: The data sources to filter data source statistics by.

        Returns:
            Dictionary of data source statistics.
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_datasource_stats(
            _self: StreamlitCoverageAnalyzerClient, data_sources: list[str]
        ):
            data_source_stats = []
            detections_df = pl.DataFrame(_self.get_detections())

            for ds in data_sources:
                ds_alert_types = detections_df.filter(
                    pl.col("data_sources_combined").list.contains(ds)
                )
                ds_stat = {
                    "data_source": ds,
                    "alert_types_covered": ds_alert_types["XDR Display Name"]
                    .unique()
                    .to_list(),
                    "techniques_covered": [
                        technique
                        for technique in ds_alert_types["XDR Technique"]
                        .unique()
                        .to_list()
                        if technique != ""
                    ],
                    "tactics_covered": [
                        tactic
                        for tactic in ds_alert_types["XDR Tactic"].unique().to_list()
                        if tactic != ""
                    ],
                }
                # filtered_ds_stactics = set()
                # for tactic in ds_stat["tactics_covered"]:
                #     if tactic not in STELLAR_EXTRA_TACTICS:
                #         filtered_ds_stactics.add(tactic)
                #     else:
                #         for key, value in STELLAR_EXTRA_TACTICS_MAP.items():
                #             if tactic in value:
                #                 filtered_ds_stactics.add(key)
                #                 break
                # ds_stat["tactics_covered"] = list(filtered_ds_stactics)

                data_source_stats.append(ds_stat)
            return data_source_stats

        return _get_datasource_stats(self, data_sources)

    @logger.catch
    def compile_stats(
        self,
        data_sources: list[str],
        start_date: date,
        end_date: date,
        tenant_name: str | None = None,
    ) -> dict[str, dict[str, Any]]:
        """
        Public method to compile statistics from tactics, techniques, and data sources into a single dictionary.

        Args:
            data_sources: The data sources to filter statistics by.
            start_date: The start date to filter statistics by.
            end_date: The end date to filter statistics by.
            tenant_name: The tenant name to filter statistics by.

        Returns:
            Dictionary of compiled statistics.
        """

        @cache_data(ttl=self.cache_ttl)
        def _compile_stats(
            _self: StreamlitCoverageAnalyzerClient,
            data_sources: list[str],
            start_date: date,
            end_date: date,
            tenant_name: str | None = None,
        ):
            tactic_stats = _self.get_tactics_stats(
                data_sources,
                start_date,
                end_date,
                tenant_name,
                with_recommendations=True,
            )
            technique_stats = _self.get_technique_stats(
                data_sources,
                start_date,
                end_date,
                tenant_name,
                with_recommendations=True,
            )
            alert_type_hits = _self.get_alert_type_hits(
                start_date, end_date, tenant_name
            )
            alert_stats = _self.get_alert_stats(
                alert_type_hits, data_sources, with_recommendations=True
            )
            # ds_stats = _self.get_datasource_stats(data_sources)

            compiled_tactics = {
                "tactic_stats": tactic_stats,
                "tactics_covered": sum(
                    1
                    for val in tactic_stats.values()
                    if val["total_alert_types_covered"] > 0
                ),
                "tactics_triggered": sum(
                    1
                    for val in tactic_stats.values()
                    if val["total_alert_types_triggered"] > 0
                ),
                "tactics_available": len(tactic_stats),
                "tactics_covered_per": sum(
                    1
                    for val in tactic_stats.values()
                    if val["total_alert_types_covered"] > 0
                )
                / len(tactic_stats)
                if len(tactic_stats) > 0
                else 0,
            }

            compiled_techniques = {
                "technique_stats": technique_stats,
                "techniques_covered": sum(
                    1
                    for tactic in technique_stats.values()
                    for val in tactic.values()
                    if val["total_alert_types_covered"] > 0
                ),
                "techniques_triggered": sum(
                    1
                    for tactic in technique_stats.values()
                    for val in tactic.values()
                    if val["total_alert_types_triggered"] > 0
                ),
                "techniques_available": sum(
                    len(tactic) for tactic in technique_stats.values()
                ),
                "techniques_covered_per": sum(
                    1
                    for tactic in technique_stats.values()
                    for val in tactic.values()
                    if val["total_alert_types_covered"] > 0
                )
                / sum(len(tactic) for tactic in technique_stats.values())
                if sum(len(tactic) for tactic in technique_stats.values()) > 0
                else 0,
            }

            compiled_alert_types = {
                "alert_type_stats": alert_stats,
                "alert_types_covered": alert_stats["total_alert_types_covered"],
                "alert_types_triggered": alert_stats["total_alert_types_triggered"],
                "alert_types_available": alert_stats["total_alert_types_available"],
                "alert_types_covered_per": alert_stats["total_alert_types_covered"]
                / alert_stats["total_alert_types_available"]
                if alert_stats["total_alert_types_available"] > 0
                else 0,
            }

            return {
                "tactics": compiled_tactics,
                "techniques": compiled_techniques,
                "alert_types": compiled_alert_types,
            }

        return _compile_stats(self, data_sources, start_date, end_date, tenant_name)

    @logger.catch
    def get_used_datasources(
        self, start_date: date, end_date: date, tenant_name: str | None = None
    ) -> list[str]:
        """
        Public method to return a list of used data sources from Stellar Cyber API

        Args:
            start_date: The start date to filter data sources by.
            end_date: The end date to filter data sources by.
            tenant_name: The tenant name to filter data sources by.

        Returns:
            List of used data sources as strings
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_used_datasources(
            _self: StreamlitCoverageAnalyzerClient,
            start_date: date,
            end_date: date,
            tenant_name: str | None = None,
        ):
            used_datasources = []
            data_sources_df = pd.DataFrame(
                _self.get_detections_datasources(as_options=False)
            )[["_id", "name"]]
            log_sources = _self._stellar.get_connector_log_data_sources(
                start_date=start_date, end_date=end_date, tenant=tenant_name
            )
            sensor_sources = _self._stellar.get_sensor_sources(
                start_date=start_date, end_date=end_date, tenant=tenant_name
            )
            for ds in log_sources + sensor_sources:
                if (
                    ds in DATASOURCE_DISPLAY_NAME_MAP
                    and ds not in data_sources_df["_id"].to_numpy()
                ):
                    tmp_ds = data_sources_df[
                        data_sources_df["name"] == DATASOURCE_DISPLAY_NAME_MAP[ds]
                    ]
                    if tmp_ds.shape[0] > 0:
                        used_datasources.append(tmp_ds["_id"].to_numpy()[0])
                elif ds in data_sources_df["_id"].to_numpy():
                    used_datasources.append(ds)

            return sorted(used_datasources, key=str.lower)

        return _get_used_datasources(self, start_date, end_date)

    @logger.catch
    def get_detections_datasources(
        self, as_options: bool | None = None
    ) -> list[str] | list[dict[str, Any]]:
        """
        Public method to return a list of data sources objects from detections.stellarcyber.ai

        Args:
            as_options: If True, return a list of data sources as strings. Defaults to True.

        Returns:
            List of detection data sources as dictionaries.
        """

        @cache_resource(ttl=self.cache_ttl)
        def _get_detections_datasources(
            _self: StreamlitCoverageAnalyzerClient, as_options: bool | None = None
        ) -> list[str] | list[dict[str, Any]]:
            return _self._mitre.get_detections_datasources(as_options=as_options)

        return _get_detections_datasources(self, as_options=as_options)

    @logger.catch
    def get_detections(self) -> list[dict[str, Any]]:
        """
        Public method to return a list of detections from detections.stellarcyber.ai

        Returns:
            List of detections as dictionaries
        """

        @cache_resource(ttl=self.cache_ttl)
        def _get_detections(
            _self: StreamlitCoverageAnalyzerClient,
            version: Literal["4.3.0", "4.3.1", "4.3.7", "5.1.x", "5.2.x", "5.3.x"],
        ) -> list[dict[str, Any]]:
            return _self._mitre.get_detections(version)

        return _get_detections(self, self.version)

    @logger.catch
    def get_custom_detections(
        self,
        tenant_id: str | None = None,
        only_builtin: bool | None = None,
        only_custom: bool | None = None,
    ) -> list[dict[str, Any]]:
        """
        Public method to return a list of custom detections from Stellar Cyber API

        Args:
            tenant_id: The tenant ID to filter detections by.
            only_builtin: Filter only builtin detections.
            only_custom: Filter only custom detections

        Returns:
            List of detections as dictionaries
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_custom_detections(
            _self: StreamlitCoverageAnalyzerClient,
            tenant_id: str | None,
            only_builtin: bool | None = None,
            only_custom: bool | None = None,
        ) -> list[dict[str, Any]]:
            custom_detections = _self._stellar.get_detections(
                tenant_id, only_builtin, only_custom
            )
            if not Path(APP_DIR + "/custom_detections.json").exists():
                with Path(APP_DIR + "/custom_detections.json").open("w") as file:
                    json.dump(custom_detections, file)
            return custom_detections

        return _get_custom_detections(self, tenant_id, only_builtin, only_custom)

    @logger.catch
    def get_tenants(self) -> list[str] | list[dict[str, Any]]:
        """
        Public method to return a list of tenants from Stellar Cyber API

        Returns:
            List of tenants as strings
        """

        @cache_data(ttl=self.cache_ttl)
        def _get_tenants(_self: StreamlitCoverageAnalyzerClient):
            return _self._stellar.get_tenants(as_options=True)

        return _get_tenants(self)
