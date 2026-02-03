import streamlit as st
import pandas as pd
import numpy as np

# Page config - must be first
st.set_page_config(
    page_title="HACTU8 Dashboard", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# HACTU8 DARK THEME - OWASP BRAND COLORS
# Updated by Keith Rambo
# ============================================
# OWASP Color Palette:
# Primary Blue: #2D72D2
# Dark Blue: #1A4B8E
# Light Blue: #4A90E2
# Black: #0A0A0A
# Dark Gray: #1C1C1C
# Medium Gray: #333333
# 
# Status Colors (Grayscale with Accent):
# Pass/Success: #A3E635 (Lime accent)
# Fail/Error: #94A3B8 (Gray)
# Warning: #CBD5E1 (Light gray)
# ============================================

st.markdown("""
<style>
    /* Import Google Font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
    
    /* Main background - OWASP Dark */
    .stApp {
        background-color: #0A0A0A;
        font-family: 'Inter', sans-serif;
    }
    
    /* Sidebar - OWASP Dark Blue tint */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0F1A2E 0%, #0A0A0A 100%);
        border-right: 1px solid #1A4B8E;
    }
    
    [data-testid="stSidebar"] .stMarkdown {
        color: #FFFFFF;
    }
    
    /* Text colors */
    .stMarkdown, .stText, p, span, label {
        color: #FFFFFF !important;
    }
    
    h1, h2, h3, h4, h5, h6 {
        color: #FFFFFF !important;
    }
    
    /* OWASP Blue accent for links and highlights */
    a {
        color: #2D72D2 !important;
    }
    
    /* KPI Card Styling - OWASP themed */
    .kpi-card {
        background: linear-gradient(180deg, #1C1C1C 0%, #0F0F0F 100%);
        border: 1px solid #333333;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        position: relative;
        overflow: hidden;
    }
    
    .kpi-card-green {
        border-top: 3px solid #A3E635;
    }
    
    .kpi-card-red {
        border-top: 3px solid #94A3B8;
    }
    
    .kpi-card-blue {
        border-top: 3px solid #2D72D2;
    }
    
    .kpi-card-yellow {
        border-top: 3px solid #CBD5E1;
    }
    
    .kpi-label {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #999999 !important;
        margin-bottom: 8px;
    }
    
    .kpi-value {
        font-size: 36px;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        margin: 8px 0;
    }
    
    .kpi-value-green { color: #A3E635 !important; }
    .kpi-value-red { color: #94A3B8 !important; }
    .kpi-value-blue { color: #2D72D2 !important; }
    .kpi-value-yellow { color: #CBD5E1 !important; }
    
    .kpi-trend {
        font-size: 12px;
        color: #999999 !important;
    }
    
    .kpi-trend-up { color: #A3E635 !important; }
    .kpi-trend-down { color: #94A3B8 !important; }
    
    /* Risk Score Gauge - OWASP Blue accent */
    .risk-gauge {
        background: linear-gradient(180deg, #1C1C1C 0%, #0F0F0F 100%);
        border: 1px solid #333333;
        border-radius: 12px;
        padding: 30px;
        text-align: center;
    }
    
    .risk-score {
        font-size: 48px;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        color: #2D72D2 !important;
    }
    
    .risk-grade {
        display: inline-block;
        background: rgba(45, 114, 210, 0.2);
        color: #4A90E2 !important;
        padding: 6px 16px;
        border-radius: 20px;
        font-size: 14px;
        font-weight: 600;
        margin-top: 10px;
        border: 1px solid #2D72D2;
    }
    
    /* System Health Card - Grayscale with accent */
    .health-card {
        background: #1C1C1C;
        border: 1px solid #333333;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    
    .health-card-warning {
        border-left: 3px solid #CBD5E1;
    }
    
    .health-card-active {
        border-left: 3px solid #A3E635;
    }
    
    .health-card-error {
        border-left: 3px solid #94A3B8;
    }
    
    .health-name {
        font-size: 14px;
        font-weight: 600;
        color: #FFFFFF !important;
    }
    
    .health-type {
        font-size: 12px;
        color: #999999 !important;
    }
    
    .health-status {
        font-size: 12px;
        font-weight: 600;
    }
    
    .status-active { color: #A3E635 !important; }
    .status-warning { color: #CBD5E1 !important; }
    .status-error { color: #94A3B8 !important; }
    
    /* Section headers - OWASP Blue accent */
    .section-header {
        background: linear-gradient(90deg, #1A4B8E 0%, #1C1C1C 100%);
        border: 1px solid #2D72D2;
        border-radius: 12px 12px 0 0;
        padding: 16px 20px;
        margin-bottom: 0;
        border-bottom: none;
    }
    
    .section-title {
        font-size: 14px;
        font-weight: 600;
        color: #FFFFFF !important;
        margin: 0;
    }
    
    .section-body {
        background: #1C1C1C;
        border: 1px solid #333333;
        border-top: none;
        border-radius: 0 0 12px 12px;
        padding: 20px;
    }
    
    /* Tables */
    .stTable {
        background: #1C1C1C;
    }
    
    [data-testid="stTable"] {
        background: #1C1C1C;
    }
    
    /* Status badges - Grayscale with accent */
    .badge-pass {
        background: rgba(163, 230, 53, 0.15);
        color: #A3E635 !important;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    
    .badge-fail {
        background: rgba(148, 163, 184, 0.15);
        color: #94A3B8 !important;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    
    .badge-warning {
        background: rgba(203, 213, 225, 0.15);
        color: #CBD5E1 !important;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
    }
    
    /* Severity badges - Grayscale with OWASP Blue accent */
    .severity-critical {
        background: #64748B;
        color: white !important;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
    }
    
    .severity-high {
        background: #475569;
        color: white !important;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
    }
    
    .severity-medium {
        background: #334155;
        color: #CBD5E1 !important;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
    }
    
    .severity-low {
        background: #2D72D2;
        color: #FFFFFF !important;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
    }
    
    /* Notification item - Grayscale with accent */
    .notification-item {
        background: #1C1C1C;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 8px;
        border-left: 3px solid #2D72D2;
    }
    
    .notification-item-warning {
        border-left-color: #CBD5E1;
    }
    
    .notification-item-success {
        border-left-color: #A3E635;
    }
    
    .notification-title {
        font-size: 13px;
        font-weight: 600;
        color: #FFFFFF !important;
    }
    
    .notification-time {
        font-size: 11px;
        color: #666666 !important;
    }
    
    /* Buttons - OWASP Blue */
    .stButton > button {
        background: #2D72D2;
        color: #FFFFFF;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 10px 16px;
    }
    
    .stButton > button:hover {
        background: #4A90E2;
    }
    
    /* Input fields */
    .stTextInput > div > div > input {
        background: #1C1C1C;
        border: 1px solid #333333;
        color: #FFFFFF;
        border-radius: 6px;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #2D72D2;
        box-shadow: 0 0 0 1px #2D72D2;
    }
    
    .stTextArea > div > div > textarea {
        background: #1C1C1C;
        border: 1px solid #333333;
        color: #FFFFFF;
        border-radius: 6px;
    }
    
    .stTextArea > div > div > textarea:focus {
        border-color: #2D72D2;
    }
    
    .stSelectbox > div > div {
        background: #1C1C1C;
        border: 1px solid #333333;
        color: #FFFFFF;
        border-radius: 6px;
    }
    
    /* Radio buttons in sidebar */
    [data-testid="stSidebar"] .stRadio label {
        color: #999999 !important;
    }
    
    [data-testid="stSidebar"] .stRadio label:hover {
        color: #FFFFFF !important;
    }
    
    /* OWASP Logo area in sidebar */
    .owasp-logo {
        color: #2D72D2 !important;
        font-weight: 700;
    }
    
    /* Dataframe styling */
    [data-testid="stDataFrame"] {
        background: #1C1C1C;
    }
    
    /* Metric styling */
    [data-testid="stMetric"] {
        background: #1C1C1C;
        border: 1px solid #333333;
        border-radius: 8px;
        padding: 16px;
    }
    
    [data-testid="stMetricValue"] {
        color: #2D72D2 !important;
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# SIDEBAR NAVIGATION - OWASP BRANDED
# ============================================
st.sidebar.markdown("## <span class='owasp-logo'>🛡️ OWASP</span> HACTU8", unsafe_allow_html=True)
st.sidebar.markdown("##### Intelligence Assurance Center")
st.sidebar.markdown("---")

menu = st.sidebar.radio(
    "Navigation", 
    ["Dashboard", "Workbench", "Extensions", "Settings"],
    label_visibility="collapsed"
)

st.sidebar.markdown("---")
st.sidebar.markdown("##### Registry")
st.sidebar.markdown("🤖 AI Systems")
st.sidebar.markdown("🔗 MCP Servers")
st.sidebar.markdown("📦 Test Packages")

st.sidebar.markdown("---")
st.sidebar.markdown("##### Quick Actions")
if st.sidebar.button("▶️ Run All Tests"):
    st.sidebar.success("Tests started!")
if st.sidebar.button("➕ Add System"):
    st.sidebar.info("Opening wizard...")

# ============================================
# DASHBOARD PAGE
# ============================================
if menu == "Dashboard":
    
    # Header
    st.markdown("## 🛡️ HACTU8 Security Dashboard")
    st.markdown("*Last scan: Today at 11:40 AM • 5 systems registered*")
    st.markdown("---")
    
    # ========================================
    # KPI CARDS ROW
    # ========================================
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    
    with kpi1:
        st.markdown("""
        <div class="kpi-card kpi-card-green">
            <div class="kpi-label">Tests Passed</div>
            <div class="kpi-value kpi-value-green">7</div>
            <div class="kpi-trend kpi-trend-up">↑ 2 from last week</div>
        </div>
        """, unsafe_allow_html=True)
    
    with kpi2:
        st.markdown("""
        <div class="kpi-card kpi-card-red">
            <div class="kpi-label">Tests Failed</div>
            <div class="kpi-value kpi-value-red">3</div>
            <div class="kpi-trend kpi-trend-down">↑ 1 from last week</div>
        </div>
        """, unsafe_allow_html=True)
    
    with kpi3:
        st.markdown("""
        <div class="kpi-card kpi-card-blue">
            <div class="kpi-label">Systems Scanned</div>
            <div class="kpi-value kpi-value-blue">5</div>
            <div class="kpi-trend kpi-trend-up">↑ 1 new system</div>
        </div>
        """, unsafe_allow_html=True)
    
    with kpi4:
        st.markdown("""
        <div class="kpi-card kpi-card-yellow">
            <div class="kpi-label">Warnings</div>
            <div class="kpi-value kpi-value-yellow">2</div>
            <div class="kpi-trend">— No change</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # ========================================
    # MAIN CONTENT: CHART + RISK SCORE
    # ========================================
    col_chart, col_risk = st.columns([2, 1])
    
    with col_chart:
        st.markdown("""
        <div class="section-header">
            <span class="section-title">📈 Security Posture Over Time (Last 30 Days)</span>
        </div>
        """, unsafe_allow_html=True)
        
        # Realistic chart data - security scores trending upward over 30 days
        days = pd.date_range(end=pd.Timestamp.today(), periods=30, freq='D')
        chart_data = pd.DataFrame({
            "Overall Score": [62, 63, 61, 65, 64, 66, 65, 68, 67, 69, 
                             68, 70, 69, 71, 70, 72, 71, 73, 72, 74,
                             73, 72, 74, 75, 74, 76, 75, 77, 78, 70],
            "Tests Passed %": [60, 60, 60, 70, 70, 70, 70, 70, 70, 70,
                              70, 70, 70, 70, 70, 80, 80, 80, 80, 80,
                              80, 80, 80, 80, 80, 80, 80, 80, 80, 70],
        }, index=days)
        st.line_chart(chart_data, height=300)
    
    with col_risk:
        st.markdown("""
        <div class="section-header">
            <span class="section-title">🛡️ Overall Risk Score</span>
        </div>
        """, unsafe_allow_html=True)
        
        # Calculate grade based on score
        risk_score = 70
        if risk_score >= 90:
            grade = "A"
        elif risk_score >= 80:
            grade = "B"
        elif risk_score >= 70:
            grade = "C"
        elif risk_score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        st.markdown(f"""
        <div class="risk-gauge">
            <div class="risk-score">{risk_score}</div>
            <div style="color: #8B949E; font-size: 14px;">out of 100</div>
            <div class="risk-grade">Grade: {grade}</div>
            <br><br>
            <div style="color: #8B949E; font-size: 12px;">
                ↑ 5 points from last week
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # ========================================
    # ASSURANCE RESULTS TABLE WITH TOOLTIPS
    # ========================================
    st.markdown("""
    <div class="section-header">
        <span class="section-title">🛡️ OWASP LLM Top 10 Assurance Results</span>
    </div>
    """, unsafe_allow_html=True)
    
    # OWASP LLM Top 10 Definitions for tooltips
    owasp_definitions = {
        "LLM01: Prompt Injection": "Manipulating LLMs via crafted inputs to cause unintended actions or responses.",
        "LLM02: Insecure Output Handling": "Failing to validate/sanitize LLM outputs before passing to other systems.",
        "LLM03: Training Data Poisoning": "Manipulation of training data to introduce vulnerabilities or biases.",
        "LLM04: Model Denial of Service": "Overloading LLMs with resource-heavy operations causing service degradation.",
        "LLM05: Supply Chain Vulnerabilities": "Risks from third-party components, training data, or pre-trained models.",
        "LLM06: Sensitive Data Disclosure": "LLMs inadvertently revealing confidential information in responses.",
        "LLM07: Insecure Plugin Design": "Plugins with inadequate access controls or input validation.",
        "LLM08: Excessive Agency": "LLMs given too much autonomy to take impactful actions without oversight.",
        "LLM09: Overreliance": "Uncritical dependence on LLM outputs without verification.",
        "LLM10: Unsafe Plugin Execution": "Plugins executing malicious code or unauthorized system commands."
    }
    
    # Display definitions as expandable section
    with st.expander("ℹ️ What do these vulnerabilities mean? (Click to expand)"):
        for vuln, definition in owasp_definitions.items():
            st.markdown(f"**{vuln}**: {definition}")
    
    # Create results as HTML table with colored indicators
    # Colors: Critical/High=#94A3B8, Medium=#CBD5E1, Low/Pass=#A3E635
    
    assurance_html = """
    <style>
        .assurance-table {
            width: 100%;
            border-collapse: collapse;
            background: #1C1C1C;
            border-radius: 0 0 12px 12px;
            overflow: hidden;
        }
        .assurance-table th {
            text-align: left;
            padding: 14px 16px;
            background: #252525;
            color: #8B949E;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid #333;
        }
        .assurance-table td {
            padding: 14px 16px;
            color: #E6EDF3;
            font-size: 14px;
            border-bottom: 1px solid #2A2A2A;
        }
        .assurance-table tr:hover {
            background: #252525;
        }
        .severity-critical, .severity-high {
            color: #94A3B8;
        }
        .severity-medium {
            color: #CBD5E1;
        }
        .severity-low {
            color: #A3E635;
        }
        .result-pass {
            color: #A3E635;
        }
        .result-fail {
            color: #94A3B8;
        }
        .result-warning {
            color: #CBD5E1;
        }
    </style>
    <table class="assurance-table">
        <thead>
            <tr>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Result</th>
                <th>Last Run</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>LLM01: Prompt Injection</td>
                <td class="severity-critical">● Critical</td>
                <td class="result-pass">✓ Pass</td>
                <td>Today, 11:40 AM</td>
            </tr>
            <tr>
                <td>LLM02: Insecure Output Handling</td>
                <td class="severity-critical">● Critical</td>
                <td class="result-fail">✗ Fail</td>
                <td>Yesterday, 11:59 AM</td>
            </tr>
            <tr>
                <td>LLM03: Training Data Poisoning</td>
                <td class="severity-high">● High</td>
                <td class="result-fail">✗ Fail</td>
                <td>Today, 10:12 AM</td>
            </tr>
            <tr>
                <td>LLM04: Model Denial of Service</td>
                <td class="severity-medium">◐ Medium</td>
                <td class="result-pass">✓ Pass</td>
                <td>Yesterday, 3:03 PM</td>
            </tr>
            <tr>
                <td>LLM05: Supply Chain Vulnerabilities</td>
                <td class="severity-medium">◐ Medium</td>
                <td class="result-warning">⚠ Warning</td>
                <td>2 days ago</td>
            </tr>
            <tr>
                <td>LLM06: Sensitive Data Disclosure</td>
                <td class="severity-high">● High</td>
                <td class="result-pass">✓ Pass</td>
                <td>Yesterday, 2:22 PM</td>
            </tr>
            <tr>
                <td>LLM07: Insecure Plugin Design</td>
                <td class="severity-medium">◐ Medium</td>
                <td class="result-pass">✓ Pass</td>
                <td>2 days ago</td>
            </tr>
            <tr>
                <td>LLM08: Excessive Agency</td>
                <td class="severity-medium">◐ Medium</td>
                <td class="result-pass">✓ Pass</td>
                <td>Yesterday, 9:14 AM</td>
            </tr>
            <tr>
                <td>LLM09: Overreliance</td>
                <td class="severity-low">○ Low</td>
                <td class="result-pass">✓ Pass</td>
                <td>Yesterday, 8:00 AM</td>
            </tr>
            <tr>
                <td>LLM10: Unsafe Plugin Execution</td>
                <td class="severity-high">● High</td>
                <td class="result-fail">✗ Fail</td>
                <td>2 days ago</td>
            </tr>
        </tbody>
    </table>
    """
    
    st.markdown(assurance_html, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # ========================================
    # BOTTOM ROW: HEALTH CARDS + NOTIFICATIONS
    # ========================================
    col_health, col_notify = st.columns(2)
    
    with col_health:
        st.markdown("""
        <div class="section-header">
            <span class="section-title">💻 System Health Cards</span>
        </div>
        """, unsafe_allow_html=True)
        
        # System Health Cards with realistic data
        systems = [
            {"name": "gpt-3.5-turbo", "type": "Model", "provider": "Azure", "status": "active", "score": 85, "tests": "8/10", "last_scan": "11:40 AM", "issues": 2},
            {"name": "claude-3", "type": "Model", "provider": "Anthropic", "status": "active", "score": 92, "tests": "9/10", "last_scan": "11:35 AM", "issues": 1},
            {"name": "mistral-7b", "type": "Model", "provider": "Local", "status": "active", "score": 78, "tests": "7/10", "last_scan": "Yesterday", "issues": 3},
            {"name": "semantic-index", "type": "RAG Application", "provider": "Internal", "status": "warning", "score": 65, "tests": "5/10", "last_scan": "10:12 AM", "issues": 5},
            {"name": "Drive MCP Server", "type": "MCP Server", "provider": "Google", "status": "active", "score": 100, "tests": "10/10", "last_scan": "Yesterday", "issues": 0},
        ]
        
        for sys in systems:
            status_class = f"health-card-{sys['status']}"
            status_color = "status-active" if sys['status'] == 'active' else "status-warning" if sys['status'] == 'warning' else "status-error"
            status_icon = "●" if sys['status'] == 'active' else "●" if sys['status'] == 'warning' else "●"
            issue_text = f"{sys['issues']} issues" if sys['issues'] > 0 else "No issues"
            
            st.markdown(f"""
            <div class="health-card {status_class}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="health-name">{sys['name']}</div>
                        <div class="health-type">{sys['type']} • {sys['provider']}</div>
                        <div class="health-type">Last scan: {sys['last_scan']} • {issue_text}</div>
                    </div>
                    <div style="text-align: right;">
                        <div class="health-status {status_color}">{status_icon} {sys['status'].title()}</div>
                        <div class="health-type" style="font-size: 18px; font-weight: 600; color: #2D72D2;">{sys['score']}%</div>
                        <div class="health-type">Tests: {sys['tests']}</div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
    
    with col_notify:
        st.markdown("""
        <div class="section-header">
            <span class="section-title">🔔 Notifications</span>
        </div>
        """, unsafe_allow_html=True)
        
        notifications = [
            {"title": "Model update available", "time": "10:15 AM", "type": "warning"},
            {"title": "New LLM tool detected", "time": "Yesterday, 6:37 PM", "type": "info"},
            {"title": "Redaction Test Passed", "time": "Yesterday, 3:03 PM", "type": "success"},
            {"title": "MCP Scan: Drive Server registered", "time": "Yesterday, 10:21 AM", "type": "info"},
            {"title": "Security scan completed", "time": "2 days ago", "type": "success"},
        ]
        
        for notif in notifications:
            notif_class = f"notification-item-{notif['type']}" if notif['type'] != 'info' else ""
            icon = "⚠️" if notif['type'] == 'warning' else "✅" if notif['type'] == 'success' else "🔔"
            
            st.markdown(f"""
            <div class="notification-item {notif_class}">
                <div class="notification-title">{icon} {notif['title']}</div>
                <div class="notification-time">{notif['time']}</div>
            </div>
            """, unsafe_allow_html=True)

# ============================================
# WORKBENCH PAGE
# ============================================
elif menu == "Workbench":
    st.markdown("## ⚙️ Prompt Workbench")
    st.markdown("*Test prompts against your registered AI systems*")
    st.markdown("---")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.text_area(
            "Enter your test prompt",
            "Describe your red team prompt here...",
            height=200
        )
        
        col_btn1, col_btn2, col_btn3 = st.columns(3)
        with col_btn1:
            if st.button("▶️ Run Test"):
                st.success("Prompt test sent (simulated)")
        with col_btn2:
            if st.button("📋 Save Prompt"):
                st.info("Prompt saved")
        with col_btn3:
            if st.button("🔄 Clear"):
                st.experimental_rerun()
    
    with col2:
        st.markdown("### Target System")
        st.selectbox("Select AI System", ["gpt-3.5-turbo", "claude-3", "mistral-7b", "semantic-index"])
        
        st.markdown("### Test Type")
        st.selectbox("Select Test", [
            "Prompt Injection",
            "Jailbreak Attempt",
            "Data Extraction",
            "Role Manipulation",
            "Custom Test"
        ])

# ============================================
# EXTENSIONS PAGE
# ============================================
elif menu == "Extensions":
    st.markdown("## 🔌 Extensions")
    st.markdown("*Manage test packages and plugins*")
    st.markdown("---")
    
    st.info("No extensions loaded. This area will support redaction, assurance, and custom test packages.")
    
    st.markdown("### Available Extensions")
    extensions = [
        {"name": "OWASP LLM Top 10 Tests", "status": "Installed", "version": "1.0.0"},
        {"name": "MCP Security Scanner", "status": "Available", "version": "0.9.0"},
        {"name": "Prompt Injection Suite", "status": "Available", "version": "1.2.0"},
    ]
    
    for ext in extensions:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.markdown(f"**{ext['name']}**")
        with col2:
            st.markdown(f"v{ext['version']}")
        with col3:
            if ext['status'] == 'Installed':
                st.success("Installed")
            else:
                st.button(f"Install", key=ext['name'])

# ============================================
# SETTINGS PAGE
# ============================================
elif menu == "Settings":
    st.markdown("## ⚙️ Settings")
    st.markdown("*Configure your HACTU8 instance*")
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### User Settings")
        st.text_input("Admin Email", "")
        st.selectbox("Theme", ["Dark", "Light"])
        st.checkbox("Enable notifications")
        st.checkbox("Auto-run tests on system registration")
    
    with col2:
        st.markdown("### API Configuration")
        st.text_input("API Endpoint", "https://api.hactu8.org")
        st.text_input("API Key", type="password")
        
    st.markdown("---")
    st.markdown("### Feature Flags")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.checkbox("Enable Help Chat", value=True)
    with col2:
        st.checkbox("Enable LLM Assistance", value=True)
    with col3:
        st.checkbox("Enable Health Checks", value=True)
