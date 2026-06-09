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
        :root { --brand: #4f46e5; }

        div[data-testid="stMetric"] {
            border: 1px solid rgba(49, 51, 63, 0.12);
            border-radius: 10px;
            padding: 0.7rem 0.9rem;
            background: rgba(250, 250, 252, 0.7);
        }
        section[data-testid="stSidebar"] button { min-height: 2.4rem; }

        /* Grade hero */
        .grade-hero {
            display: flex; align-items: center; gap: 1.1rem;
            padding: 1.1rem 1.3rem; border-radius: 14px; margin: 0.1rem 0 1.1rem;
            border: 1px solid rgba(49, 51, 63, 0.12);
            background: linear-gradient(135deg, rgba(79, 70, 229, 0.06), rgba(250, 250, 252, 0.6));
        }
        .grade-badge {
            flex: 0 0 auto; width: 74px; height: 74px; border-radius: 16px;
            display: flex; align-items: center; justify-content: center;
            font-size: 2.5rem; font-weight: 800; color: #fff;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.12);
        }
        .grade-label { font-size: 1.15rem; font-weight: 700; margin-bottom: 0.35rem; }
        .grade-chips .chip {
            display: inline-block; padding: 0.16rem 0.6rem; border-radius: 999px;
            background: rgba(49, 51, 63, 0.08); color: #374151;
            font-size: 0.8rem; font-weight: 600; margin: 0.12rem 0.3rem 0.12rem 0;
        }
        .chip.chip-high { background: rgba(220, 38, 38, 0.12); color: #b91c1c; }
        .chip.chip-medium { background: rgba(217, 119, 6, 0.12); color: #b45309; }
        .grade-A .grade-badge { background: #16a34a; }
        .grade-B .grade-badge { background: #3f9142; }
        .grade-C .grade-badge { background: #d97706; }
        .grade-D .grade-badge { background: #ea580c; }
        .grade-F .grade-badge { background: #dc2626; }

        /* Finding cards */
        .finding-card {
            border: 1px solid rgba(49, 51, 63, 0.12); border-left: 5px solid #9ca3af;
            border-radius: 10px; padding: 0.65rem 0.9rem; margin: 0.5rem 0;
            background: rgba(250, 250, 252, 0.65);
        }
        .finding-card.sev-high { border-left-color: #dc2626; }
        .finding-card.sev-medium { border-left-color: #d97706; }
        .finding-card.sev-low { border-left-color: #2563eb; }
        .finding-card.sev-info { border-left-color: #6b7280; }
        .finding-head { display: flex; align-items: center; gap: 0.5rem; }
        .sev-pill {
            display: inline-block; padding: 0.08rem 0.5rem; border-radius: 999px;
            font-size: 0.68rem; font-weight: 800; color: #fff;
            text-transform: uppercase; letter-spacing: 0.04em;
        }
        .sev-pill.sev-high { background: #dc2626; }
        .sev-pill.sev-medium { background: #d97706; }
        .sev-pill.sev-low { background: #2563eb; }
        .sev-pill.sev-info { background: #6b7280; }
        .finding-dim { color: #6b7280; font-size: 0.82rem; }
        .finding-title { font-weight: 700; font-size: 1rem; margin: 0.4rem 0 0.25rem; }
        .finding-desc { font-size: 0.92rem; line-height: 1.5; color: #1f2937; }
        .finding-cve { font-size: 0.84rem; color: var(--brand); margin-top: 0.35rem; font-weight: 600; }
        .finding-rec { font-size: 0.88rem; margin-top: 0.3rem; color: #1f2937; }
        .finding-rec b { color: #111827; }
        </style>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
