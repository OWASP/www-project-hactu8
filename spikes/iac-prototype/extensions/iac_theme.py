"""
IAC Host theme utilities for Streamlit extensions.

Usage:
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from iac_theme import apply_iac_theme, inject_theme_toggle

    st.set_page_config(...)
    apply_iac_theme()

    # In sidebar:
    inject_theme_toggle(st.session_state.get("iac_theme", "light"))

This injects CSS that matches the IAC host's typography, font sizing, and
compact spacing. Uses CSS custom properties so a dark/light toggle can
switch themes at runtime.

IMPORTANT: Do NOT apply font-family to bare `span` elements — Streamlit
uses Material Icon fonts rendered in <span> tags for expander arrows,
checkboxes, etc. Overriding font-family on spans breaks those icons.
"""

import streamlit as st
import streamlit.components.v1 as components

# ---------------------------------------------------------------------------
# CSS with custom properties for light/dark theme support
# ---------------------------------------------------------------------------

IAC_CSS = """
<style>
/* ── IAC Theme – CSS custom properties ──
   Light theme is default (matches config.toml base="light").
   Dark theme activated via html[data-iac-theme="dark"].
   IMPORTANT: Do NOT put font-family on bare `span` — it breaks
   Streamlit's Material Icon font used for expander arrows, etc.
*/

/* ── Light theme (default) ── */
:root {
    --iac-bg: #ffffff;
    --iac-surface: #f8fafc;
    --iac-surface-elevated: #f1f5f9;
    --iac-text: #213547;
    --iac-text-secondary: #64748b;
    --iac-border: #e2e8f0;
    --iac-accent: #0284c7;
    --iac-accent-hover: #0369a1;
    --iac-progress: #0284c7;
}

/* ── Dark theme (toggled via JS) ── */
html[data-iac-theme="dark"] {
    --iac-bg: #0f172a;
    --iac-surface: #1e293b;
    --iac-surface-elevated: #213547;
    --iac-text: #e2e8f0;
    --iac-text-secondary: #94a3b8;
    --iac-border: #334155;
    --iac-accent: #b1d0dd;
    --iac-accent-hover: #b1d0dd;
    --iac-progress: #b1d0dd;
}

/* ── Base font (html/body level only) ── */
html, body, [class*="css"] {
    font-family: system-ui, Avenir, Helvetica, Arial, sans-serif !important;
    font-weight: 400;
    line-height: 1.5;
    font-synthesis: none;
    text-rendering: optimizeLegibility;
    -webkit-font-smoothing: antialiased;
}

/* ── Page title (h1) ── */
h1, .stMarkdown h1 {
    font-size: 1.25rem !important;
    font-weight: 700 !important;
    letter-spacing: -0.01em;
    margin-bottom: 0.25rem !important;
    line-height: 1.3 !important;
}

/* ── Subheadings ── */
h2, .stMarkdown h2 {
    font-size: 1.05rem !important;
    font-weight: 600 !important;
    margin-top: 1rem !important;
    margin-bottom: 0.5rem !important;
}

h3, h4, h5, h6,
.stMarkdown h3, .stMarkdown h4 {
    font-size: 0.9rem !important;
    font-weight: 600 !important;
    margin-top: 0.75rem !important;
    margin-bottom: 0.35rem !important;
}

/* ── Body text — target text elements, NOT bare span ── */
p, li, label,
.stMarkdown p, .stMarkdown li {
    font-size: 0.875rem;
    font-weight: 400;
    line-height: 1.5;
}

/* ── Captions / secondary text ── */
.stCaption, small, .stMarkdown small {
    font-size: 0.75rem !important;
    color: var(--iac-text-secondary) !important;
}

/* ── Code blocks ── */
code, pre, .stCode {
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace !important;
    font-size: 0.8rem;
}

/* ── Metric cards ── */
[data-testid="stMetricValue"] {
    font-size: 1.5rem !important;
    font-weight: 700 !important;
}

[data-testid="stMetricLabel"] {
    font-size: 0.75rem !important;
    color: var(--iac-text-secondary) !important;
    text-transform: none !important;
}

[data-testid="stMetric"] {
    padding: 0.5rem !important;
}

/* ── Buttons ── */
.stButton > button {
    font-size: 0.85rem !important;
    font-weight: 600;
    padding: 0.4rem 1.2rem !important;
    border-radius: 4px !important;
    letter-spacing: 0.01em;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] li,
section[data-testid="stSidebar"] label {
    font-size: 0.8rem !important;
}

section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2 {
    font-size: 0.95rem !important;
    font-weight: 600 !important;
}

/* ── Expander headers — DO NOT override font-family here ── */
.streamlit-expanderHeader {
    font-size: 0.85rem !important;
    font-weight: 500 !important;
}

details summary p {
    font-size: 0.85rem !important;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab"] {
    font-size: 0.85rem !important;
    font-weight: 500;
}

/* ── Input fields ── */
.stTextInput input, .stNumberInput input, .stSelectbox select {
    font-size: 0.85rem !important;
    padding: 0.4rem 0.6rem !important;
}

.stTextInput label, .stNumberInput label,
.stSelectbox label, .stCheckbox label {
    font-size: 0.8rem !important;
}

/* ── Dividers ── */
hr {
    border-color: var(--iac-border) !important;
    margin-top: 0.75rem !important;
    margin-bottom: 0.75rem !important;
}

/* ── Progress bar ── */
.stProgress > div > div {
    background-color: var(--iac-progress) !important;
}

/* ── Alerts ── */
.stAlert {
    border-radius: 6px;
    font-size: 0.85rem !important;
    padding: 0.6rem 0.8rem !important;
}

/* ── Reduce Streamlit default page padding ── */
.block-container {
    padding-top: 1.5rem !important;
    padding-bottom: 1rem !important;
}

/* ── Tighter column gaps ── */
[data-testid="stHorizontalBlock"] {
    gap: 0.75rem !important;
}

/* ── Reduce whitespace between elements ── */
.element-container {
    margin-bottom: 0.5rem !important;
}
</style>
"""


def apply_iac_theme():
    """Inject IAC host typography, spacing, and theme CSS custom properties.

    Call this immediately after st.set_page_config().
    Pair with inject_theme_toggle() for dark/light switching.
    """
    st.markdown(IAC_CSS, unsafe_allow_html=True)


def inject_theme_toggle(theme: str = "light"):
    """Inject JavaScript that sets the data-iac-theme attribute on <html>.

    This activates the dark CSS custom-property overrides when theme="dark".
    Call this after the toggle button logic so it runs on every Streamlit rerun.

    Parameters
    ----------
    theme : str
        "light" or "dark". Defaults to "light".
    """
    js = f"""
    <script>
    (function() {{
        var theme = '{theme}';
        document.documentElement.setAttribute('data-iac-theme', theme);
    }})();
    </script>
    """
    components.html(js, height=0, width=0)
