import streamlit as st

# ---------- Config ----------
st.set_page_config(layout="wide")

# ---------- Sample Data ----------
modules = {
    "Extension A": ["Test A1", "Test A2"],
    "Extension B": ["Test B1", "Test B2"],
}

details = {
    "Test A1": "🛠️ Panel for A1 – details and interactive test results.",
    "Test A2": "🧪 Panel for A2 – run configurations, results, etc.",
    "Test B1": "🔍 Panel for B1 – vulnerability analysis output.",
    "Test B2": "📊 Panel for B2 – scoring, logs, trace summaries.",
}

# ---------- URL Query Params ----------
params = st.query_params
selected_module = params.get("module", None)
selected_item = params.get("item", None)

# ---------- Styles ----------
st.markdown("""
<style>
html, body, [data-testid="stApp"] {
    height: 100%;
}
.nav-column {
    padding: 1rem;
    height: 100vh;
    overflow-y: auto;
    border-right: 1px solid #ccc;
}
.panel-a {
    background-color: #2c3e50;  /* dark blue */
    color: white;
}
.panel-b {
    background-color: #34495e;  /* slightly lighter */
    color: white;
}
.panel-c {
    background-color: #ecf0f1;  /* light gray */
    color: #333;
}
.nav-link {
    padding: 0.5rem 1rem;
    margin-bottom: 0.5rem;
    display: block;
    border-radius: 6px;
    text-decoration: none;
    font-weight: 500;
    cursor: pointer;
}
.nav-link:hover {
    background-color: rgba(255,255,255,0.1);
}
.nav-selected {
    background-color: #1abc9c !important;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# ---------- Layout ----------
col1, col2, col3 = st.columns([1.2, 1.2, 3])

# --- Column A: Extensions ---
with col1:
    st.markdown("<div class='nav-column panel-a'>", unsafe_allow_html=True)
    st.markdown("### 🧩 Extensions", unsafe_allow_html=True)
    for module in modules:
        css_class = "nav-link"
        if selected_module == module:
            css_class += " nav-selected"
        st.markdown(
            f"<a class='{css_class}' href='?module={module}'>{module}</a>",
            unsafe_allow_html=True
        )
    st.markdown("</div>", unsafe_allow_html=True)

# --- Column B: Tests ---
with col2:
    st.markdown("<div class='nav-column panel-b'>", unsafe_allow_html=True)
    st.markdown("### ✅ Tests", unsafe_allow_html=True)
    if selected_module and selected_module in modules:
        for test in modules[selected_module]:
            css_class = "nav-link"
            if selected_item == test:
                css_class += " nav-selected"
            st.markdown(
                f"<a class='{css_class}' href='?module={selected_module}&item={test}'>{test}</a>",
                unsafe_allow_html=True
            )
    else:
        st.markdown("_Select a module to view tests_")
    st.markdown("</div>", unsafe_allow_html=True)

# --- Column C: Panel ---
with col3:
    st.markdown("<div class='nav-column panel-c'>", unsafe_allow_html=True)
    st.markdown("### 📋 Test Panel", unsafe_allow_html=True)
    if selected_item and selected_item in details:
        st.markdown(f"<p style='padding: 1rem; font-size: 1.1rem;'>{details[selected_item]}</p>", unsafe_allow_html=True)
    else:
        st.markdown("_Select a test to view its panel_")
    st.markdown("</div>", unsafe_allow_html=True)