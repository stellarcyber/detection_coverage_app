import json
import streamlit as st

from coverage_analyzer import __version__
from coverage_analyzer.ui import header, sidebar
from coverage_analyzer.vars import (
    COOKIES,
    get_cookie_manager,
    logger,
    read_hosts_config,
)


def init_state():
    global COOKIES
    st.set_page_config(
        page_title="Coverage Analyzer",
        page_icon="docs/images/logo.png",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "Get Help": "https://github.com/yourusername/coverage-analyzer/issues",
            "Report a bug": "https://github.com/yourusername/coverage-analyzer/issues/new",
            "About": f"Coverage Analyzer v{__version__}",
        },
    )
    if COOKIES is None:
        COOKIES = get_cookie_manager()


    if not COOKIES.ready():
        st.stop()
    
    if st.session_state.get("cookie_manager", None) is None:
        st.session_state.cookie_manager = COOKIES

    if not st.session_state.get("configs", False):
        logger.info("Loading saved host configs into session state.")
        configs = {}
        global_configs = read_hosts_config()
        cookie_configs = json.loads(st.session_state.get("cookie_manager", {}).get("configs", "{}"))
        configs.update(global_configs)
        configs.update(cookie_configs)
        st.session_state.configs = configs



def main():
    init_state()
    header()
    sidebar()


if __name__ == "__main__":
    main()
