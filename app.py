import json

# import logging
# from datetime import datetime, timedelta, timezone
from collections.abc import Callable
import streamlit as st
from streamlit.runtime.scriptrunner import add_script_run_ctx

from coverage_analyzer import __version__
from coverage_analyzer.ui import header, sidebar
from coverage_analyzer.vars import (
    COOKIES,
    get_cookie_manager,
    get_thread_pool_executor,
    logger,
    read_hosts_config,
    thread_executor,
)


def init_state():
    global COOKIES
    global thread_executor
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

    if thread_executor is None:
        thread_executor = get_thread_pool_executor()
        for t in thread_executor._threads:
            add_script_run_ctx(t)

    if not COOKIES.ready():
        st.stop()

    if not st.session_state.get("configs", False):
        logger.info("Loading saved host configs into session state.")
        configs = {}
        global_configs = read_hosts_config()
        cookie_configs = json.loads(COOKIES.get("configs", "{}"))
        configs.update(global_configs)
        configs.update(cookie_configs)
        st.session_state.configs = configs


def background_run(func: Callable, callback: Callable | None = None) -> None:
    global thread_executor
    if thread_executor is not None:
        future = thread_executor.submit(func)
        logger.info(f"Started background task: {func.__name__}.")
        if callback is not None:
            future.add_done_callback(callback)
            logger.info(
                f"Added callback: {callback.__name__} to background task: {func.__name__}."
            )
    else:
        logger.error("Thread pool executor not initialized.")
        logger.error(f"Cannot run background task: {func.__name__}.")


def main():
    init_state()
    header()
    sidebar()


if __name__ == "__main__":
    main()
