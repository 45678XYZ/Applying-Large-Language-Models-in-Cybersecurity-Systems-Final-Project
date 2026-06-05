"""Streamlit chat surface for scanning and report follow-up Q&A."""

from __future__ import annotations

from collections.abc import Callable

import streamlit as st

from agent import SecurityAgent
from models import ScanReport
from scripts.demo_scenarios import build_demo_report, scenario_choices
from ui.report_view import render_report

ProgressSink = Callable[[str], None]
AgentFactory = Callable[[ProgressSink | None], SecurityAgent]


def render_chat(create_agent: AgentFactory) -> None:
    """Mount the scan CTA, report surface, and Q&A history."""
    _init_state()
    _render_sidebar(create_agent)

    st.title("Home Network Security Auditor")
    st.caption("Sequential LAN scan, CVE lookup, graded report, and grounded follow-up Q&A.")

    report: ScanReport | None = st.session_state.get("report")
    if report is None:
        _render_pre_scan()
        return

    render_report(report)
    _render_history()
    _render_chat_input()


def _init_state() -> None:
    st.session_state.setdefault("report", None)
    st.session_state.setdefault("agent", None)
    st.session_state.setdefault("messages", [])
    _load_query_demo()


def _load_query_demo() -> None:
    scenario_id = st.query_params.get("demo")
    if not scenario_id or st.session_state.report is not None:
        return

    try:
        report = build_demo_report(scenario_id)
    except ValueError:
        st.warning(f"Unknown demo scenario: {scenario_id}")
        return

    st.session_state.report = report
    st.session_state.agent = None
    st.session_state.messages = [
        {
            "role": "assistant",
            "content": (
                f"Demo report loaded with grade {report.overall_grade}. "
                "Use it to validate the report layout and screenshots."
            ),
        }
    ]


def _render_sidebar(create_agent: AgentFactory) -> None:
    with st.sidebar:
        st.header("Run")
        st.write("Use a live scan for the demo network, or load a deterministic fixture.")

        if st.button("Start Scan", type="primary", use_container_width=True):
            _run_live_scan(create_agent)

        choices = scenario_choices()
        selected_label = st.selectbox("Demo scenario", list(choices), index=0)
        if st.button("Load Demo Report", use_container_width=True):
            _load_demo_report(create_agent, choices[selected_label])

        if st.button("Reset", use_container_width=True):
            st.session_state.report = None
            st.session_state.agent = None
            st.session_state.messages = []
            st.rerun()


def _render_pre_scan() -> None:
    st.info("Start a scan or load the demo report to view results.")
    cols = st.columns(3)
    cols[0].metric("Default port scan", "Top 100")
    cols[1].metric("OS detection", "Off")
    cols[2].metric("Report mode", "A-F grade")


def _run_live_scan(create_agent: AgentFactory) -> None:
    progress = st.empty()
    events: list[str] = []

    with st.status("Running scan", expanded=True) as status:

        def on_event(message: str) -> None:
            events.append(message)
            status.write(message)
            progress.caption(" | ".join(events[-3:]))

        try:
            agent = create_agent(on_event)
            report = agent.run_full_scan()
        except Exception as exc:  # noqa: BLE001 - UI should report bootstrap/scan failures.
            status.update(label="Scan failed", state="error")
            st.error(f"Could not complete the scan: {exc}")
            return

        st.session_state.agent = agent
        st.session_state.report = report
        st.session_state.messages = [
            {
                "role": "assistant",
                "content": (
                    f"Scan complete. The network received grade {report.overall_grade}. "
                    "Ask a follow-up question about the findings or remediation steps."
                ),
            }
        ]
        status.update(label=f"Scan complete - grade {report.overall_grade}", state="complete")
    st.rerun()


def _load_demo_report(create_agent: AgentFactory, scenario_id: str) -> None:
    report = build_demo_report(scenario_id)
    agent: SecurityAgent | None = None

    try:
        agent = create_agent(None)
        agent.load_report(report)
    except Exception as exc:  # noqa: BLE001 - demo report can still render without Q&A.
        st.warning(f"Demo report loaded, but Q&A is unavailable: {exc}")

    st.session_state.agent = agent
    st.session_state.report = report
    st.session_state.messages = [
        {
            "role": "assistant",
            "content": (
                f"Demo report loaded with grade {report.overall_grade}. "
                "Use it to validate the report layout, screenshots, and Q&A flow."
            ),
        }
    ]
    st.rerun()


def _render_history() -> None:
    st.markdown("#### Follow-up Q&A")
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])


def _render_chat_input() -> None:
    agent: SecurityAgent | None = st.session_state.get("agent")
    disabled = agent is None
    prompt = "Ask about the latest report" if not disabled else "Q&A unavailable"
    question = st.chat_input(prompt, disabled=disabled)
    if not question:
        return

    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        with st.spinner("Checking the report and knowledge base"):
            try:
                answer = agent.ask(question) if agent is not None else "Q&A is unavailable."
            except Exception as exc:  # noqa: BLE001 - keep the UI recoverable.
                answer = f"Could not answer from the current report: {exc}"
            st.markdown(answer)
    st.session_state.messages.append({"role": "assistant", "content": answer})
