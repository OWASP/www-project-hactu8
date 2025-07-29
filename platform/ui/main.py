
import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(page_title="HACTU8 Dashboard", layout="wide")

# Sidebar navigation
st.sidebar.title("OWASP HACTU8")
menu = st.sidebar.radio("Navigation", ["Dashboard", "Workbench", "Extensions", "Settings"])

# Top navbar
st.markdown("### HACTU8 Reference Dashboard")

if menu == "Dashboard":
    col1, col2 = st.columns((2, 1))
    with col1:
        st.subheader("LLM Events")
        chart_data = pd.DataFrame(np.random.randn(20, 3), columns=["Azure::gpt-3.5-turbo", "semantic-index", "Prime MCP"])
        st.line_chart(chart_data)        
        st.markdown("""
        - 11:37:08 AM — System prompt set at index 2  
        - 11:37:39 AM — Token limit exceeded  
        - 10:25:44 AM — System prompt set at ms  
        """)

    with col2:
        st.subheader("Intelligent Systems Registry")
        st.table({
            "Name": ["gpt-3.5-turbo", "claude-3", "mistral-7b", "semantic-index", "Drive MCP Server"],
            "Type": ["Model", "Model", "Model", "Application", "MCP Server"],
            "Status": ["🟢 Active", "🟢 Active", "🟢 Active", "🟠 Warning", "🟢 Active"]
        })

    col3, col4 = st.columns(2)
    with col3:
        st.subheader("Assurance Results")
        assurance_data = {
            "Vulnerability": [
                "Prompt Injection", "Training Data Poisoning", "Model Denial of Service",
                "Sensitive Data Disclosure", "Insecure Output Handling", "Excessive Agency",
                "Overreliance", "Data Leakage via Logs", "MCP Spoofing", "Unsafe Plugin Execution"
            ],
            "Result": [
                "✅ Pass", "❌ Fail", "✅ Pass", "✅ Pass", "❌ Fail", "✅ Pass",
                "✅ Pass", "✅ Pass", "✅ Pass", "❌ Fail"
            ],
            "Last Run": [
                "Today, 11:40 AM", "Today, 10:12 AM", "Yesterday, 3:03 PM", "Yesterday, 2:22 PM",
                "Yesterday, 11:59 AM", "Yesterday, 9:14 AM", "Yesterday, 8:00 AM",
                "2 days ago", "2 days ago", "2 days ago"
            ]
        }
        st.table(assurance_data)

    with col4:
        st.subheader("Notifications")
        st.markdown("""
        - 10:15 AM — Model update available  
        - Yesterday, 6:37 PM — New LLM tool detected  
        - Yesterday, 3:03 PM — Redaction Test Passed  
        - Yesterday, 10:21 AM — MCP Scan: Drive Server registered  
        """)

elif menu == "Workbench":
    st.subheader("Prompt Workbench")
    st.text_area("Prompt", "Describe your red team prompt here...")
    if st.button("Run Test"):
        st.success("Prompt test sent (simulated)")

elif menu == "Extensions":
    st.subheader("Extensions")
    st.info("No extensions loaded. This area will support redaction, assurance, etc.")

elif menu == "Settings":
    st.subheader("Settings")
    st.text_input("Admin email", "")
    st.selectbox("Theme", ["Light", "Dark"])
