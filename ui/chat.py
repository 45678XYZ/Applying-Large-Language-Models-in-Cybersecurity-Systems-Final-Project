"""Streamlit chat surface for scanning and report follow-up Q&A."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Iterator

import streamlit as st

from agent import SecurityAgent
from models import ScanReport
from scripts.demo_scenarios import build_demo_report, scenario_choices
from ui.report_view import render_report

ProgressSink = Callable[[str], None]
AgentFactory = Callable[[ProgressSink | None], SecurityAgent]

# Inline line icons (Lucide paths) — replace emoji so the landing page stays
# clean and picks up the brand colour via `currentColor` on both themes.
_ICON_SHIELD = (
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6'
    'a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5'
    'a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>'
)
_ICON_SEARCH = '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>'
_ICON_DATABASE = (
    '<ellipse cx="12" cy="5" rx="9" ry="3"/>'
    '<path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/>'
)
_ICON_CHART = '<path d="M3 3v18h18"/><path d="M18 17V9"/><path d="M13 17V5"/><path d="M8 17v-3"/>'
_ICON_CHAT = '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'


def _icon(paths: str, size: int = 26) -> str:
    """Wrap Lucide path data in an SVG that inherits the parent's text colour."""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round">{paths}</svg>'
    )


def render_chat(create_agent: AgentFactory) -> None:
    """Mount the scan CTA, report surface, and Q&A history."""
    _init_state()
    _render_sidebar(create_agent)

    st.title("Home Network Security Auditor")
    st.caption("Sequential LAN scan, CVE lookup, graded report, and grounded follow-up Q&A.")
    _show_notice()

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
    st.session_state.setdefault("notice", None)
    _load_query_demo()


def _show_notice() -> None:
    """Render a banner queued before an `st.rerun()`, which would otherwise
    discard anything written in the run that queued it."""
    notice = st.session_state.pop("notice", None)
    if not notice:
        return
    level, text = notice
    (st.error if level == "error" else st.warning)(text)


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
    st.markdown(
        '<div class="welcome-band">'
        f'<div class="welcome-icon">{_icon(_ICON_SHIELD, 40)}</div>'
        '<div class="welcome-text"><b>Pick a path to begin.</b> Click '
        "<b>Start Scan</b> in the sidebar to audit your live network, or "
        "<b>Load Demo Report</b> to explore a deterministic example.</div>"
        "</div>",
        unsafe_allow_html=True,
    )

    features = [
        (_ICON_SEARCH, "Discover devices", "An nmap sweep finds hosts, open ports, and services on your LAN."),
        (_ICON_DATABASE, "Match real CVEs", "RAG over an NVD knowledge base cites real CVEs for what it finds."),
        (_ICON_CHART, "Graded A–F report", "A deterministic rubric scores five risk dimensions."),
        (_ICON_CHAT, "Grounded Q&A", "Ask follow-up questions; answers stay grounded in your scan."),
    ]
    for col, (icon, title, body) in zip(st.columns(len(features)), features, strict=True):
        col.markdown(
            f'<div class="feature-card"><div class="feature-icon">{_icon(icon)}</div>'
            f'<div class="feature-title">{title}</div>'
            f'<div class="feature-body">{body}</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="defaults-label">How a scan runs</div>', unsafe_allow_html=True)
    os_detection = hasattr(os, "geteuid") and os.geteuid() == 0
    cols = st.columns(3)
    cols[0].metric("Port scan", "Top 100 ports")
    cols[1].metric("OS detection", "On · root" if os_detection else "Off · sudo enables")
    cols[2].metric("Scope", "Local LAN")


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
            # Rerun rather than just returning: this run already drew every
            # sidebar control disabled, so without a rerun the page would be
            # left with no enabled widget to recover from.
            st.session_state.scanning = False
            st.session_state.notice = ("error", f"Could not complete the scan: {exc}")
            st.rerun()

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
        st.session_state.notice = ("warning", f"Demo report loaded, but Q&A is unavailable: {exc}")

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
