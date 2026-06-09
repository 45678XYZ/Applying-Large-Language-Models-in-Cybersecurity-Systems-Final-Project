"""Streamlit chat surface for scanning and report follow-up Q&A."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator

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
    st.session_state.setdefault("scanning", False)
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

        # A live scan blocks the script run, so the buttons can't visually
        # disable mid-scan. Use a flag instead: the first click flags the scan
        # and reruns, this rerun draws the buttons disabled and then performs
        # the scan, which clears the flag when it finishes.
        scanning = st.session_state.get("scanning", False)

        if st.button(
            "Scanning…" if scanning else "Start Scan",
            type="primary",
            width="stretch",
            disabled=scanning,
        ):
            st.session_state.scanning = True
            st.rerun()

        choices = scenario_choices()
        selected_label = st.selectbox(
            "Demo scenario", list(choices), index=0, disabled=scanning
        )
        if st.button("Load Demo Report", width="stretch", disabled=scanning):
            _load_demo_report(create_agent, choices[selected_label])

        if st.button("Reset", width="stretch", disabled=scanning):
            st.session_state.report = None
            st.session_state.agent = None
            st.session_state.messages = []
            st.rerun()

        if scanning:
            _run_live_scan(create_agent)


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
            st.session_state.scanning = False
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
    st.session_state.scanning = False
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
        if agent is None:
            answer = "Q&A is unavailable."
            st.markdown(answer)
        else:
            try:
                # write_stream renders chunks as they arrive and returns the
                # full concatenated text once the stream is exhausted; the
                # spinner covers the retrieval + first-token wait before it.
                answer = st.write_stream(
                    _spinner_until_first_chunk(agent.ask_stream(question))
                )
            except Exception as exc:  # noqa: BLE001 - keep the UI recoverable.
                answer = f"Could not answer from the current report: {exc}"
                st.markdown(answer)
    st.session_state.messages.append({"role": "assistant", "content": answer})


def _spinner_until_first_chunk(
    stream: Iterable[str],
    message: str = "Checking the report and knowledge base",
) -> Iterator[str]:
    """Show a spinner until the first streamed chunk arrives, then pass through.

    The first `next()` is where the agent does its RAG retrieval and waits for
    the first token, so wrapping just that call keeps the spinner visible during
    the pre-stream latency without blocking the token-by-token render after it.
    """
    iterator = iter(stream)
    with st.spinner(message):
        first = next(iterator, None)
    if first is None:
        return
    yield first
    yield from iterator
