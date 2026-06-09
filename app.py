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
        :root { --brand: #6366f1; }

        /* Surfaces use neutral grey alpha tints + inherited text so they read
           naturally on BOTH the light and dark Streamlit themes. Only the
           saturated accent colours (severity, grade badge) are hard-coded. */
        div[data-testid="stMetric"] {
            border: 1px solid rgba(128, 128, 128, 0.25);
            border-radius: 10px;
            padding: 0.7rem 0.9rem;
            background: rgba(128, 128, 128, 0.08);
        }
        section[data-testid="stSidebar"] button { min-height: 2.4rem; }

        /* Grade hero */
        .grade-hero {
            display: flex; align-items: center; gap: 1.1rem;
            padding: 1.1rem 1.3rem; border-radius: 14px; margin: 0.1rem 0 1.1rem;
            border: 1px solid rgba(99, 102, 241, 0.28);
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.18), rgba(99, 102, 241, 0.02));
        }
        .grade-badge {
            flex: 0 0 auto; width: 74px; height: 74px; border-radius: 16px;
            display: flex; align-items: center; justify-content: center;
            font-size: 2.5rem; font-weight: 800; color: #fff;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.18);
        }
        .grade-label { font-size: 1.15rem; font-weight: 700; margin-bottom: 0.35rem; color: inherit; }
        .grade-chips .chip {
            display: inline-block; padding: 0.16rem 0.6rem; border-radius: 999px;
            background: rgba(128, 128, 128, 0.18); color: inherit;
            font-size: 0.8rem; font-weight: 600; margin: 0.12rem 0.3rem 0.12rem 0;
        }
        .chip.chip-high { background: rgba(220, 38, 38, 0.16); color: #ef4444; }
        .chip.chip-medium { background: rgba(217, 119, 6, 0.16); color: #f59e0b; }
        .grade-A .grade-badge { background: #16a34a; }
        .grade-B .grade-badge { background: #3f9142; }
        .grade-C .grade-badge { background: #d97706; }
        .grade-D .grade-badge { background: #ea580c; }
        .grade-F .grade-badge { background: #dc2626; }

        /* Finding cards */
        .finding-card {
            border: 1px solid rgba(128, 128, 128, 0.22); border-left: 5px solid #9ca3af;
            border-radius: 10px; padding: 0.65rem 0.9rem; margin: 0.5rem 0;
            background: rgba(128, 128, 128, 0.08);
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
        .finding-dim { color: inherit; opacity: 0.6; font-size: 0.82rem; }
        .finding-title { font-weight: 700; font-size: 1rem; margin: 0.4rem 0 0.25rem; color: inherit; }
        .finding-desc { font-size: 0.92rem; line-height: 1.5; color: inherit; opacity: 0.85; }
        .finding-cve { font-size: 0.84rem; color: var(--brand); margin-top: 0.35rem; font-weight: 600; }
        .finding-rec { font-size: 0.88rem; margin-top: 0.3rem; color: inherit; }
        .finding-rec b { color: inherit; }

        /* Landing page */
        .welcome-band {
            display: flex; align-items: center; gap: 1rem;
            padding: 1.2rem 1.4rem; border-radius: 14px; margin: 0.2rem 0 1.2rem;
            border: 1px solid rgba(99, 102, 241, 0.28);
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.18), rgba(99, 102, 241, 0.02));
        }
        .welcome-icon { color: var(--brand); line-height: 0; display: inline-flex; }
        .welcome-text { font-size: 1rem; color: inherit; opacity: 0.85; line-height: 1.5; }
        .feature-card {
            height: 100%; border: 1px solid rgba(128, 128, 128, 0.22); border-radius: 12px;
            padding: 1rem; background: rgba(128, 128, 128, 0.08);
            transition: transform 0.12s ease, box-shadow 0.12s ease;
        }
        .feature-card:hover { transform: translateY(-2px); box-shadow: 0 6px 18px rgba(0, 0, 0, 0.18); }
        .feature-icon { color: var(--brand); line-height: 0; margin-bottom: 0.15rem; display: inline-flex; }
        .feature-title { font-weight: 700; margin: 0.45rem 0 0.3rem; color: inherit; }
        .feature-body { font-size: 0.85rem; color: inherit; opacity: 0.7; line-height: 1.45; }
        .defaults-label {
            margin: 1.3rem 0 0.4rem; font-size: 0.8rem; font-weight: 700;
            text-transform: uppercase; letter-spacing: 0.05em; color: inherit; opacity: 0.55;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
