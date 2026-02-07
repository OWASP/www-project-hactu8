"""
Prompt Injection Tests - IAC Core

A Streamlit extension for the IAC Host that runs predefined prompt injection
tests against a configured AI endpoint and reports results.

This extension reads its configuration from config.json (written by the host)
and writes test results to the shared results directory.
"""

import os
import sys
import json
import streamlit as st
import streamlit.components.v1 as components
from tests.runner import run_all_tests, save_results
from tests.payloads import TEST_CASES

# Import shared IAC theme (one directory up)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from iac_theme import apply_iac_theme, inject_theme_toggle


def post_results_to_host(run_result: dict) -> None:
    """Send test results to the IAC Host via window.postMessage.

    When this Streamlit app is embedded as an iframe inside the IAC Host,
    the host listens for 'iac-extension-results' messages and stores them
    in localStorage so the Assurance Results page can display them.
    """
    payload_json = json.dumps(run_result)
    js = f"""
    <script>
    (function() {{
        if (window.parent && window.parent !== window) {{
            window.parent.postMessage({{
                type: 'iac-extension-results',
                payload: {payload_json}
            }}, '*');
        }}
    }})();
    </script>
    """
    components.html(js, height=0, width=0)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")


def load_config() -> dict:
    """Load host-provided config.json, falling back to defaults."""
    defaults = {
        "hostVersion": "unknown",
        "extensionId": "iac-prompt-injection-tests",
        "port": 8501,
        "resultsDir": "~/.iac/results/iac-prompt-injection-tests",
        "settings": {
            "targetUrl": "http://localhost:8000",
            "timeout": 30,
            "verbose": False,
        },
    }
    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
            # Merge settings with defaults
            merged_settings = {**defaults["settings"], **config.get("settings", {})}
            return {**defaults, **config, "settings": merged_settings}
    except FileNotFoundError:
        return defaults
    except json.JSONDecodeError:
        return defaults


# ---------------------------------------------------------------------------
# Streamlit App
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Prompt Injection Tests",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
)

# Apply shared IAC theme (typography, spacing, CSS custom properties)
apply_iac_theme()

config = load_config()
settings = config["settings"]

st.title("Prompt Injection Tests - IAC Core")
st.caption(f"Extension v0.1.0 | Host v{config['hostVersion']}")

# ---------------------------------------------------------------------------
# Sidebar — Configuration
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("Configuration")

    target_url = st.text_input(
        "Target URL",
        value=settings.get("targetUrl", "http://localhost:8000"),
        help="The AI endpoint to test (must expose /api/copilot/chat).",
    )
    timeout = st.number_input(
        "Timeout (seconds)",
        min_value=5,
        max_value=120,
        value=int(settings.get("timeout", 30)),
    )
    verbose = st.checkbox(
        "Verbose output",
        value=bool(settings.get("verbose", False)),
        help="Include full request/response data in results.",
    )

    st.divider()
    st.subheader("Test Suite")
    st.metric("Total tests", len(TEST_CASES))

    # Group by category for display
    categories = {}
    for tc in TEST_CASES:
        cat = tc["category"]
        categories[cat] = categories.get(cat, 0) + 1

    for cat, count in categories.items():
        st.text(f"  {cat}: {count}")

    st.divider()
    st.caption(f"Results dir: {config['resultsDir']}")

    # Theme toggle
    st.divider()
    if "iac_theme" not in st.session_state:
        st.session_state["iac_theme"] = "light"

    theme_label = "Switch to Dark" if st.session_state["iac_theme"] == "light" else "Switch to Light"
    if st.button(theme_label, key="theme_toggle"):
        st.session_state["iac_theme"] = "dark" if st.session_state["iac_theme"] == "light" else "light"
        st.rerun()

    inject_theme_toggle(st.session_state["iac_theme"])

# ---------------------------------------------------------------------------
# Main area — Run tests & display results
# ---------------------------------------------------------------------------

col1, col2 = st.columns([1, 3])

with col1:
    run_button = st.button("Run All Tests", type="primary", use_container_width=True)

# Initialize session state for results
if "last_run" not in st.session_state:
    st.session_state["last_run"] = None

if run_button:
    progress_bar = st.progress(0, text="Running tests...")
    status_text = st.empty()

    def update_progress(current, total):
        progress_bar.progress(current / total, text=f"Running test {current}/{total}...")

    with st.spinner("Running prompt injection tests..."):
        run_result = run_all_tests(
            target_url=target_url,
            timeout=timeout,
            verbose=verbose,
            progress_callback=update_progress,
        )

    # Save results to shared results directory
    try:
        results_path = save_results(run_result, config["resultsDir"])
        st.success(f"Results saved to: {results_path}")
    except Exception as e:
        st.warning(f"Could not save results: {e}")

    # Send results to IAC Host via postMessage (for Assurance Results page)
    post_results_to_host(run_result)

    progress_bar.empty()
    st.session_state["last_run"] = run_result

# ---------------------------------------------------------------------------
# Display results
# ---------------------------------------------------------------------------

run_result = st.session_state.get("last_run")

if run_result:
    st.divider()
    summary = run_result["summary"]

    # Summary metrics
    st.subheader("Results Summary")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total", summary["total"])
    m2.metric("Passed", summary["passed"])
    m3.metric("Failed", summary["failed"])
    m4.metric("Errors", summary["errors"])
    m5.metric("Duration", f"{summary['duration']}ms")

    # Pass rate
    if summary["total"] > 0:
        pass_rate = summary["passed"] / summary["total"] * 100
        st.progress(pass_rate / 100, text=f"Pass rate: {pass_rate:.0f}%")

    # Detailed results table
    st.subheader("Test Details")

    # Failed tests first, then errors, then passed
    status_order = {"fail": 0, "error": 1, "pass": 2, "skip": 3}
    sorted_results = sorted(run_result["results"], key=lambda r: status_order.get(r["status"], 99))

    for r in sorted_results:
        icon = {"pass": "\u2705", "fail": "\u274c", "error": "\u26a0\ufe0f", "skip": "\u23ed\ufe0f"}.get(r["status"], "\u2753")
        with st.expander(f"{icon} {r['name']} — {r['status'].upper()} ({r.get('duration', 0)}ms)"):
            st.write(f"**ID:** {r['id']}")
            st.write(f"**Status:** {r['status']}")
            st.write(f"**Message:** {r['message']}")
            if r.get("details"):
                st.code(r["details"], language="json")

    # Raw JSON export
    with st.expander("Raw JSON"):
        st.json(run_result)

else:
    st.info("Click **Run All Tests** to execute the prompt injection test suite against the configured target.")

    # Show available test cases
    st.subheader("Available Tests")
    for tc in TEST_CASES:
        with st.expander(f"{tc['name']} ({tc['category']})"):
            st.write(f"**ID:** {tc['id']}")
            st.write(f"**Description:** {tc['description']}")
            st.code(tc["payload"], language="text")
