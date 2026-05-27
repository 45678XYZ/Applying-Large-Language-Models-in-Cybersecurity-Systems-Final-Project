"""Streamlit chat surface.

Two states:
    * pre-scan   → "Start Scan" CTA + (optional) preferences
    * post-scan  → conversation history + Q&A input

Live tool-execution progress is streamed via a Streamlit `status` block
that subscribes to LangChain callbacks fired from `agent.core`.
"""

from agent import SecurityAgent


def render_chat(agent: SecurityAgent) -> None:
    """Mount the chat UI onto the current Streamlit page."""
    raise NotImplementedError
