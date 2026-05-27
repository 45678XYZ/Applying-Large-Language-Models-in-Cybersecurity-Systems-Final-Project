"""Streamlit entrypoint.

Run with:
    streamlit run app.py
"""

from agent import SecurityAgent
from rag import Retriever
from ui.chat import render_chat


def main() -> None:
    """Bootstrap LLM, retriever, agent, then mount the chat UI."""
    raise NotImplementedError


if __name__ == "__main__":
    main()
