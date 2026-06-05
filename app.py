"""Streamlit entrypoint.

Run with:
    streamlit run app.py
"""

from __future__ import annotations

from collections.abc import Callable

from dotenv import load_dotenv

# Keep .env authoritative over stale shell exports, matching scripts/run_scan.py.
load_dotenv(override=True)

import streamlit as st  # noqa: E402

from agent import SecurityAgent  # noqa: E402
from config import settings  # noqa: E402
from rag import build_default_retriever  # noqa: E402
from ui.chat import render_chat  # noqa: E402


def main() -> None:
    """Bootstrap the app shell and mount the Streamlit chat UI."""
    st.set_page_config(
        page_title="Home Network Security Auditor",
        page_icon=":shield:",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _inject_styles()
    render_chat(_create_agent)


@st.cache_resource(show_spinner=False)
def _build_llm():
    """Construct the Azure OpenAI chat model from settings."""
    from langchain_openai import AzureChatOpenAI

    return AzureChatOpenAI(
        azure_deployment=settings.azure_openai_chat_deployment,
        azure_endpoint=settings.azure_openai_endpoint,
        api_key=settings.azure_openai_api_key,
        api_version=settings.azure_openai_api_version,
        temperature=0,
    )


@st.cache_resource(show_spinner=False)
def _build_retriever():
    """Construct the KB retriever once per Streamlit process."""
    return build_default_retriever()


def _create_agent(on_event: Callable[[str], None] | None = None) -> SecurityAgent:
    return SecurityAgent(_build_llm(), _build_retriever(), on_event=on_event)


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
        div[data-testid="stMetric"] {
            border: 1px solid rgba(49, 51, 63, 0.18);
            border-radius: 8px;
            padding: 0.75rem 0.9rem;
            background: rgba(250, 250, 252, 0.72);
        }
        section[data-testid="stSidebar"] button {
            min-height: 2.4rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
