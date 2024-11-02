import json
from typing import Any

import streamlit as st

from coverage_analyzer.streamlit import StreamlitCoverageAnalyzerClient
from coverage_analyzer.vars import COOKIES, logger


def save_state(config: dict[str, Any]):
    global COOKIES
    logger.info("Saving host config to session state and cookies.")
    configs = st.session_state.get("configs", {})
    host = config["host"]
    configs[host] = config
    st.session_state.configs = configs
    st.session_state.config = host
    COOKIES["configs"] = json.dumps(configs)  # type: ignore
    COOKIES.save()  # type: ignore


def refresh_state():
    if st.session_state.get("stca"):
        if (
            st.session_state.config == st.session_state.stca.name
            or st.session_state.config == st.session_state.stca.host
        ):
            return
    logger.info("Refreshing Stellar Cyber API connection.")
    config = st.session_state.configs[st.session_state.config]
    st.session_state.stca = StreamlitCoverageAnalyzerClient.get_scstca_client(
        name=st.session_state.config,
        host=config["host"],
        username=config["user"],
        api_key=config["api_key"],
        version=config["version"],
        verify_ssl=config["verify_ssl"],
    )
    # st.session_state.stca = StreamlitCoverageAnalyzerClient(
    #     name=config,
    #     host=config["host"],
    #     username=config["user"],
    #     api_key=config["api_key"],
    #     version=config["version"],
    #     verify_ssl=config["verify_ssl"],
    # )