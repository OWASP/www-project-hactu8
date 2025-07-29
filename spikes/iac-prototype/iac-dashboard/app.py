import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
from typing import Dict, List, Any
import time

# Set page configuration
st.set_page_config(
    page_title="Enterprise AI Monitoring Dashboard",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem;
    }
    .sidebar .sidebar-content {
        background-color: #f0f2f6;
    }
    .stAlert {
        border-radius: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state for real-time updates
if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now()
if 'ai_events_count' not in st.session_state:
    st.session_state.ai_events_count = 0

def generate_mock_data():
    """Generate mock data for the dashboard"""
    
    # Generate time series data for the last 30 days
    dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
    
    # AI Agent performance data
    agents = ['Azure OpenAI GPT-4', 'Custom RAG Agent', 'Copilot Assistant', 
              'Document Analyzer', 'Code Assistant', 'Data Insights AI']
    
    agent_data = []
    for date in dates:
        for agent in agents:
            agent_data.append({
                'date': date,
                'agent': agent,
                'requests': np.random.randint(100, 1000),
                'success_rate': np.random.uniform(0.85, 0.99),
                'avg_response_time': np.random.uniform(0.5, 3.0),
                'cost': np.random.uniform(10, 150)
            })
    
    return pd.DataFrame(agent_data)

def generate_ai_services():
    """Generate mock AI services registry"""
    return [
        {
            'service_name': 'Azure OpenAI Service',
            'type': 'Language Model',
            'status': 'Active',
            'endpoint': 'https://myopenai.openai.azure.com/',
            'model': 'gpt-4o',
            'last_used': datetime.now() - timedelta(minutes=5),
            'total_requests': 15420,
            'cost_this_month': 2840.50
        },
        {
            'service_name': 'Azure Cognitive Search',
            'type': 'Search & Retrieval',
            'status': 'Active',
            'endpoint': 'https://mysearch.search.windows.net',
            'model': 'semantic-search',
            'last_used': datetime.now() - timedelta(minutes=12),
            'total_requests': 8930,
            'cost_this_month': 450.75
        },
        {
            'service_name': 'Custom RAG Pipeline',
            'type': 'Document Intelligence',
            'status': 'Active',
            'endpoint': 'https://myrag.azurewebsites.net',
            'model': 'rag-v2.1',
            'last_used': datetime.now() - timedelta(hours=1),
            'total_requests': 3420,
            'cost_this_month': 180.25
        },
        {
            'service_name': 'Azure Form Recognizer',
            'type': 'Document Processing',
            'status': 'Active',
            'endpoint': 'https://myforms.cognitiveservices.azure.com/',
            'model': 'prebuilt-document',
            'last_used': datetime.now() - timedelta(hours=3),
            'total_requests': 1250,
            'cost_this_month': 95.60
        },
        {
            'service_name': 'GitHub Copilot Enterprise',
            'type': 'Code Assistant',
            'status': 'Active',
            'endpoint': 'https://api.github.com/copilot',
            'model': 'copilot-enterprise',
            'last_used': datetime.now() - timedelta(minutes=2),
            'total_requests': 12580,
            'cost_this_month': 1200.00
        }
    ]

def generate_mcp_servers():
    """Generate mock MCP (Model Context Protocol) servers"""
    return [
        {
            'server_name': 'Azure Resource Manager MCP',
            'type': 'Azure Integration',
            'status': 'Connected',
            'endpoint': 'mcp://azure-arm.local:8080',
            'capabilities': ['resource-management', 'deployment', 'monitoring'],
            'last_heartbeat': datetime.now() - timedelta(seconds=30),
            'active_connections': 15
        },
        {
            'server_name': 'Enterprise Data MCP',
            'type': 'Data Access',
            'status': 'Connected',
            'endpoint': 'mcp://enterprise-data.local:8081',
            'capabilities': ['sql-query', 'data-retrieval', 'analytics'],
            'last_heartbeat': datetime.now() - timedelta(seconds=45),
            'active_connections': 8
        },
        {
            'server_name': 'Security Compliance MCP',
            'type': 'Security',
            'status': 'Connected',
            'endpoint': 'mcp://security.local:8082',
            'capabilities': ['policy-check', 'audit', 'compliance'],
            'last_heartbeat': datetime.now() - timedelta(minutes=1),
            'active_connections': 3
        },
        {
            'server_name': 'Code Repository MCP',
            'type': 'Development',
            'status': 'Disconnected',
            'endpoint': 'mcp://code-repo.local:8083',
            'capabilities': ['code-analysis', 'version-control', 'ci-cd'],
            'last_heartbeat': datetime.now() - timedelta(minutes=15),
            'active_connections': 0
        }
    ]

def generate_recent_events():
    """Generate mock AI events"""
    events = []
    event_types = ['Model Deployment', 'High Usage Alert', 'Cost Threshold', 'Security Scan', 'Performance Issue', 'New Registration']
    severities = ['Info', 'Warning', 'Critical']
    
    for i in range(20):
        events.append({
            'timestamp': datetime.now() - timedelta(minutes=np.random.randint(1, 1440)),
            'event_type': np.random.choice(event_types),
            'severity': np.random.choice(severities),
            'source': np.random.choice(['Azure OpenAI', 'Custom Agent', 'MCP Server', 'Monitoring System']),
            'description': f"Event {i+1}: System notification for enterprise AI monitoring",
            'status': np.random.choice(['Resolved', 'Active', 'Investigating'])
        })
    
    return sorted(events, key=lambda x: x['timestamp'], reverse=True)

# Main Dashboard
def main():
    # st.markdown('<h1 class="main-header">🤖 Enterprise AI Monitoring Dashboard</h1>', unsafe_allow_html=True)
    
    # Sidebar for navigation
    st.sidebar.title("📊 Dashboard Navigation")
    selected_view = st.sidebar.selectbox(
        "Select View",
        ["Overview", "AI Activity Tracking", "Event Monitoring", "Agent Performance", 
         "MCP Servers", "Registered Services", "Cost Analysis", "Security & Compliance"]
    )
    
    # Auto-refresh option
    auto_refresh = st.sidebar.checkbox("Auto-refresh (30s)", value=False)
    if auto_refresh:
        st.rerun()
    
    # Generate data
    agent_df = generate_mock_data()
    ai_services = generate_ai_services()
    mcp_servers = generate_mcp_servers()
    recent_events = generate_recent_events()
    
    if selected_view == "Overview":
        show_overview(agent_df, ai_services, mcp_servers, recent_events)
    elif selected_view == "AI Activity Tracking":
        show_activity_tracking(agent_df)
    elif selected_view == "Event Monitoring":
        show_event_monitoring(recent_events)
    elif selected_view == "Agent Performance":
        show_agent_performance(agent_df)
    elif selected_view == "MCP Servers":
        show_mcp_servers(mcp_servers)
    elif selected_view == "Registered Services":
        show_registered_services(ai_services)
    elif selected_view == "Cost Analysis":
        show_cost_analysis(agent_df, ai_services)
    elif selected_view == "Security & Compliance":
        show_security_compliance()

def show_overview(agent_df, ai_services, mcp_servers, recent_events):
    """Show overview dashboard"""
    st.subheader("📈 Enterprise AI Overview")
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_requests = agent_df['requests'].sum()
        st.metric("Total AI Requests", f"{total_requests:,}", delta="↗️ 12%")
    
    with col2:
        active_services = len([s for s in ai_services if s['status'] == 'Active'])
        st.metric("Active AI Services", active_services, delta="→ 0")
    
    with col3:
        connected_mcp = len([m for m in mcp_servers if m['status'] == 'Connected'])
        st.metric("Connected MCP Servers", f"{connected_mcp}/{len(mcp_servers)}")
    
    with col4:
        avg_success_rate = agent_df['success_rate'].mean() * 100
        st.metric("Avg Success Rate", f"{avg_success_rate:.1f}%", delta="↗️ 2.1%")
    
    # Recent activity and alerts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔔 Recent Alerts")
        critical_events = [e for e in recent_events[:5] if e['severity'] == 'Critical']
        if critical_events:
            for event in critical_events:
                st.warning(f"**{event['event_type']}** - {event['source']}")
        else:
            st.success("No critical alerts in the last 24 hours")
    
    with col2:
        st.subheader("📊 Agent Performance Trend")
        daily_requests = agent_df.groupby('date')['requests'].sum().reset_index()
        fig = px.line(daily_requests, x='date', y='requests', 
                     title="Daily AI Requests Trend")
        st.plotly_chart(fig, use_container_width=True)

def show_activity_tracking(agent_df):
    """Show AI activity tracking"""
    st.subheader("🔍 AI Activity Tracking")
    
    # Activity filters
    col1, col2, col3 = st.columns(3)
    with col1:
        selected_agents = st.multiselect("Filter by Agent", 
                                       agent_df['agent'].unique(), 
                                       default=agent_df['agent'].unique())
    with col2:
        date_range = st.date_input("Date Range", 
                                 value=(agent_df['date'].min(), agent_df['date'].max()),
                                 min_value=agent_df['date'].min(),
                                 max_value=agent_df['date'].max())
    
    # Filter data
    filtered_df = agent_df[agent_df['agent'].isin(selected_agents)]
    if len(date_range) == 2:
        filtered_df = filtered_df[
            (filtered_df['date'] >= pd.Timestamp(date_range[0])) & 
            (filtered_df['date'] <= pd.Timestamp(date_range[1]))
        ]
    
    # Activity metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Requests", f"{filtered_df['requests'].sum():,}")
    with col2:
        st.metric("Avg Response Time", f"{filtered_df['avg_response_time'].mean():.2f}s")
    with col3:
        st.metric("Success Rate", f"{filtered_df['success_rate'].mean()*100:.1f}%")
    
    # Activity heatmap
    st.subheader("📅 Activity Heatmap")
    pivot_data = filtered_df.pivot_table(values='requests', index='agent', columns='date', fill_value=0)
    fig = px.imshow(pivot_data.values, 
                   x=pivot_data.columns.strftime('%m-%d'),
                   y=pivot_data.index,
                   aspect="auto",
                   title="Request Volume Heatmap")
    st.plotly_chart(fig, use_container_width=True)
    
    # Real-time activity log
    st.subheader("⚡ Real-time Activity Log")
    activity_log = pd.DataFrame({
        'Timestamp': [datetime.now() - timedelta(minutes=i) for i in range(10)],
        'Agent': np.random.choice(selected_agents, 10),
        'Action': np.random.choice(['Query Processed', 'Model Inference', 'Cache Hit', 'API Call'], 10),
        'Status': np.random.choice(['Success', 'Warning', 'Error'], 10, p=[0.8, 0.15, 0.05])
    })
    st.dataframe(activity_log, use_container_width=True)

def show_event_monitoring(events):
    """Show event monitoring"""
    st.subheader("📋 Event Monitoring")
    
    # Event summary
    col1, col2, col3 = st.columns(3)
    
    with col1:
        critical_count = len([e for e in events if e['severity'] == 'Critical'])
        st.metric("Critical Events", critical_count, delta=f"↑ {np.random.randint(1,5)}")
    
    with col2:
        warning_count = len([e for e in events if e['severity'] == 'Warning'])
        st.metric("Warning Events", warning_count, delta=f"↓ {np.random.randint(1,3)}")
    
    with col3:
        active_count = len([e for e in events if e['status'] == 'Active'])
        st.metric("Active Events", active_count)
    
    # Event timeline
    st.subheader("📈 Event Timeline")
    events_df = pd.DataFrame(events)
    events_df['hour'] = events_df['timestamp'].dt.hour
    hourly_events = events_df.groupby(['hour', 'severity']).size().reset_index(name='count')
    
    fig = px.bar(hourly_events, x='hour', y='count', color='severity',
                title="Events by Hour and Severity",
                color_discrete_map={'Critical': 'red', 'Warning': 'orange', 'Info': 'blue'})
    st.plotly_chart(fig, use_container_width=True)
    
    # Event filters
    severity_filter = st.selectbox("Filter by Severity", ['All', 'Critical', 'Warning', 'Info'])
    status_filter = st.selectbox("Filter by Status", ['All', 'Active', 'Resolved', 'Investigating'])
    
    # Filter events
    filtered_events = events
    if severity_filter != 'All':
        filtered_events = [e for e in filtered_events if e['severity'] == severity_filter]
    if status_filter != 'All':
        filtered_events = [e for e in filtered_events if e['status'] == status_filter]
    
    # Event list
    st.subheader("🔍 Event Details")
    for event in filtered_events[:10]:
        severity_color = {'Critical': '🔴', 'Warning': '🟡', 'Info': '🔵'}[event['severity']]
        status_color = {'Active': '🟠', 'Resolved': '🟢', 'Investigating': '🔵'}[event['status']]
        
        with st.expander(f"{severity_color} {event['event_type']} - {event['source']} {status_color}"):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Timestamp:** {event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                st.write(f"**Source:** {event['source']}")
                st.write(f"**Severity:** {event['severity']}")
            with col2:
                st.write(f"**Status:** {event['status']}")
                st.write(f"**Description:** {event['description']}")

def show_agent_performance(agent_df):
    """Show agent performance comparison"""
    st.subheader("🤖 Agent Performance Comparison")
    
    # Performance metrics
    agent_summary = agent_df.groupby('agent').agg({
        'requests': 'sum',
        'success_rate': 'mean',
        'avg_response_time': 'mean',
        'cost': 'sum'
    }).reset_index()
    
    # Agent comparison chart
    fig = go.Figure()
    
    agents = agent_summary['agent'].tolist()
    fig.add_trace(go.Scatter(
        x=list(range(len(agents))), 
        y=agent_summary['requests'].tolist(),
        mode='lines+markers',
        name='Total Requests',
        line=dict(color='blue', width=3),
        marker=dict(size=8)
    ))
    
    fig.update_layout(
        title="Agent Performance - Total Requests Over Time",
        xaxis_title="Agents",
        yaxis_title="Total Requests",
        xaxis=dict(tickvals=list(range(len(agents))), ticktext=agents, tickangle=45),
        height=500
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Performance comparison table
    st.subheader("📊 Performance Metrics Comparison")
    agent_summary['success_rate'] = agent_summary['success_rate'].apply(lambda x: f"{x*100:.1f}%")
    agent_summary['avg_response_time'] = agent_summary['avg_response_time'].apply(lambda x: f"{x:.2f}s")
    agent_summary['cost'] = agent_summary['cost'].apply(lambda x: f"${x:.2f}")
    
    st.dataframe(agent_summary, use_container_width=True)
    
    # Individual agent deep dive
    st.subheader("🔍 Agent Deep Dive")
    selected_agent = st.selectbox("Select Agent for Details", agent_df['agent'].unique())
    
    agent_data = agent_df[agent_df['agent'] == selected_agent]
    
    col1, col2 = st.columns(2)
    with col1:
        fig = px.line(agent_data, x='date', y='success_rate', 
                     title=f"{selected_agent} - Success Rate Trend")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = px.line(agent_data, x='date', y='avg_response_time',
                     title=f"{selected_agent} - Response Time Trend")
        st.plotly_chart(fig, use_container_width=True)

def show_mcp_servers(mcp_servers):
    """Show MCP (Model Context Protocol) servers status"""
    st.subheader("🌐 MCP Servers Status")
    
    # MCP server overview
    col1, col2, col3 = st.columns(3)
    
    with col1:
        connected = len([s for s in mcp_servers if s['status'] == 'Connected'])
        st.metric("Connected Servers", f"{connected}/{len(mcp_servers)}")
    
    with col2:
        total_connections = sum(s['active_connections'] for s in mcp_servers)
        st.metric("Total Active Connections", total_connections)
    
    with col3:
        avg_heartbeat = np.mean([(datetime.now() - s['last_heartbeat']).seconds 
                                for s in mcp_servers if s['status'] == 'Connected'])
        st.metric("Avg Heartbeat Interval", f"{avg_heartbeat:.0f}s")
    
    # Server status cards
    st.subheader("🖥️ Server Details")
    
    for server in mcp_servers:
        status_color = "🟢" if server['status'] == 'Connected' else "🔴"
        
        with st.expander(f"{status_color} {server['server_name']} ({server['type']})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Status:** {server['status']}")
                st.write(f"**Endpoint:** `{server['endpoint']}`")
                st.write(f"**Type:** {server['type']}")
                st.write(f"**Active Connections:** {server['active_connections']}")
            
            with col2:
                st.write(f"**Last Heartbeat:** {server['last_heartbeat'].strftime('%H:%M:%S')}")
                st.write("**Capabilities:**")
                for cap in server['capabilities']:
                    st.write(f"  • {cap}")
                
                if server['status'] == 'Connected':
                    st.success("✅ Server is healthy")
                else:
                    st.error("❌ Server is disconnected")
    
    # MCP connection timeline
    st.subheader("📈 Connection Activity")
    
    # Generate mock connection data
    times = pd.date_range(end=datetime.now(), periods=24, freq='H')
    connection_data = []
    
    for time in times:
        for server in mcp_servers:
            if server['status'] == 'Connected':
                connections = np.random.randint(0, server['active_connections'] + 5)
            else:
                connections = 0
            
            connection_data.append({
                'time': time,
                'server': server['server_name'],
                'connections': connections
            })
    
    connection_df = pd.DataFrame(connection_data)
    fig = px.line(connection_df, x='time', y='connections', color='server',
                 title="MCP Server Connections Over Time")
    st.plotly_chart(fig, use_container_width=True)

def show_registered_services(ai_services):
    """Show registered AI services"""
    st.subheader("🔧 Registered AI Services")
    
    # Service overview
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        active_services = len([s for s in ai_services if s['status'] == 'Active'])
        st.metric("Active Services", active_services)
    
    with col2:
        total_requests = sum(s['total_requests'] for s in ai_services)
        st.metric("Total Requests", f"{total_requests:,}")
    
    with col3:
        total_cost = sum(s['cost_this_month'] for s in ai_services)
        st.metric("Monthly Cost", f"${total_cost:,.2f}")
    
    with col4:
        recently_used = len([s for s in ai_services 
                           if (datetime.now() - s['last_used']).total_seconds() < 3600])
        st.metric("Recently Used (1h)", recently_used)
    
    # Service registry table
    st.subheader("📋 Service Registry")
    
    services_df = pd.DataFrame(ai_services)
    services_df['last_used'] = services_df['last_used'].dt.strftime('%Y-%m-%d %H:%M')
    services_df['cost_this_month'] = services_df['cost_this_month'].apply(lambda x: f"${x:.2f}")
    
    st.dataframe(services_df, use_container_width=True)
    
    # Service health check
    st.subheader("🏥 Service Health Status")
    
    for service in ai_services:
        with st.expander(f"🔧 {service['service_name']} ({service['type']})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Status:** {'🟢 Active' if service['status'] == 'Active' else '🔴 Inactive'}")
                st.write(f"**Model:** {service['model']}")
                st.write(f"**Endpoint:** `{service['endpoint']}`")
                st.write(f"**Last Used:** {service['last_used'].strftime('%Y-%m-%d %H:%M:%S')}")
            
            with col2:
                st.write(f"**Total Requests:** {service['total_requests']:,}")
                st.write(f"**Monthly Cost:** ${service['cost_this_month']:.2f}")
                
                # Mock health metrics
                latency = np.random.uniform(50, 500)
                uptime = np.random.uniform(95, 99.9)
                error_rate = np.random.uniform(0.1, 2.0)
                
                st.write(f"**Avg Latency:** {latency:.0f}ms")
                st.write(f"**Uptime:** {uptime:.1f}%")
                st.write(f"**Error Rate:** {error_rate:.1f}%")
    
    # Service usage trends
    st.subheader("📈 Usage Trends")
    
    # Generate mock usage data
    dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
    usage_data = []
    
    for date in dates:
        for service in ai_services:
            usage_data.append({
                'date': date,
                'service': service['service_name'],
                'requests': np.random.randint(service['total_requests']//50, service['total_requests']//30)
            })
    
    usage_df = pd.DataFrame(usage_data)
    fig = px.line(usage_df, x='date', y='requests', color='service',
                 title="Service Usage Trends (Last 30 Days)")
    st.plotly_chart(fig, use_container_width=True)

def show_cost_analysis(agent_df, ai_services):
    """Show cost analysis"""
    st.subheader("💰 Cost Analysis")
    
    # Cost overview
    total_monthly_cost = sum(s['cost_this_month'] for s in ai_services)
    agent_monthly_cost = agent_df['cost'].sum()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Monthly Total", f"${total_monthly_cost:,.2f}")
    
    with col2:
        daily_avg = total_monthly_cost / 30
        st.metric("Daily Average", f"${daily_avg:.2f}")
    
    with col3:
        projected_annual = total_monthly_cost * 12
        st.metric("Projected Annual", f"${projected_annual:,.2f}")
    
    with col4:
        cost_per_request = total_monthly_cost / sum(s['total_requests'] for s in ai_services)
        st.metric("Cost per Request", f"${cost_per_request:.4f}")
    
    # Cost breakdown
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Cost by Service")
        service_costs = {s['service_name']: s['cost_this_month'] for s in ai_services}
        fig = px.pie(values=list(service_costs.values()), 
                    names=list(service_costs.keys()),
                    title="Monthly Cost Distribution")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("📈 Cost Trend")
        daily_costs = agent_df.groupby('date')['cost'].sum().reset_index()
        fig = px.line(daily_costs, x='date', y='cost',
                     title="Daily Cost Trend")
        st.plotly_chart(fig, use_container_width=True)
    
    # Cost optimization recommendations
    st.subheader("💡 Cost Optimization Recommendations")
    
    recommendations = [
        "🔧 Consider moving low-frequency workloads to consumption-based pricing",
        "📊 Implement request caching to reduce API calls by ~30%",
        "⚡ Use smaller models for simple tasks to reduce per-token costs",
        "🕐 Schedule non-urgent batch processing during off-peak hours",
        "📈 Monitor for unused or underutilized AI services"
    ]
    
    for rec in recommendations:
        st.info(rec)
    
    # Detailed cost breakdown
    st.subheader("📋 Detailed Cost Breakdown")
    
    cost_details = []
    for service in ai_services:
        cost_per_request = service['cost_this_month'] / service['total_requests']
        cost_details.append({
            'Service': service['service_name'],
            'Type': service['type'],
            'Requests': service['total_requests'],
            'Monthly Cost': f"${service['cost_this_month']:.2f}",
            'Cost per Request': f"${cost_per_request:.4f}",
            'Efficiency Score': f"{np.random.uniform(70, 95):.1f}%"
        })
    
    cost_df = pd.DataFrame(cost_details)
    st.dataframe(cost_df, use_container_width=True)

def show_security_compliance():
    """Show security and compliance dashboard"""
    st.subheader("🔒 Security & Compliance")
    
    # Security overview
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Security Score", "94/100", delta="↗️ +2")
    
    with col2:
        st.metric("Compliance Status", "98%", delta="→ 0")
    
    with col3:
        st.metric("Access Violations", "0", delta="↓ -2")
    
    with col4:
        st.metric("Data Breaches", "0", delta="→ 0")
    
    # Security checks
    st.subheader("🛡️ Security Checks")
    
    security_checks = [
        {"check": "Encryption at Rest", "status": "✅ Passed", "last_check": "2 hours ago"},
        {"check": "Encryption in Transit", "status": "✅ Passed", "last_check": "2 hours ago"},
        {"check": "Access Control Policies", "status": "✅ Passed", "last_check": "1 hour ago"},
        {"check": "API Key Rotation", "status": "⚠️ Warning", "last_check": "1 day ago"},
        {"check": "Audit Logging", "status": "✅ Passed", "last_check": "30 minutes ago"},
        {"check": "Data Residency", "status": "✅ Passed", "last_check": "4 hours ago"},
        {"check": "PII Detection", "status": "✅ Passed", "last_check": "1 hour ago"},
        {"check": "Model Access Controls", "status": "✅ Passed", "last_check": "3 hours ago"}
    ]
    
    for check in security_checks:
        col1, col2, col3 = st.columns([3, 2, 2])
        with col1:
            st.write(f"**{check['check']}**")
        with col2:
            st.write(check['status'])
        with col3:
            st.write(f"*{check['last_check']}*")
    
    # Compliance frameworks
    st.subheader("📋 Compliance Frameworks")
    
    frameworks = [
        {"framework": "SOC 2 Type II", "status": "✅ Compliant", "expiry": "2025-12-31"},
        {"framework": "GDPR", "status": "✅ Compliant", "expiry": "Ongoing"},
        {"framework": "HIPAA", "status": "✅ Compliant", "expiry": "2025-09-15"},
        {"framework": "ISO 27001", "status": "⚠️ In Progress", "expiry": "2025-06-30"},
        {"framework": "FedRAMP", "status": "❌ Not Applicable", "expiry": "N/A"}
    ]
    
    compliance_df = pd.DataFrame(frameworks)
    st.dataframe(compliance_df, use_container_width=True)
    
    # Recent security events
    st.subheader("🚨 Recent Security Events")
    
    security_events = [
        {"timestamp": datetime.now() - timedelta(hours=2), "event": "Successful login from new location", "severity": "Info", "action": "Notification sent"},
        {"timestamp": datetime.now() - timedelta(hours=8), "event": "API rate limit exceeded", "severity": "Warning", "action": "Rate limiting applied"},
        {"timestamp": datetime.now() - timedelta(days=1), "event": "Security policy updated", "severity": "Info", "action": "All users notified"},
        {"timestamp": datetime.now() - timedelta(days=2), "event": "Failed authentication attempt", "severity": "Warning", "action": "Account locked temporarily"}
    ]
    
    for event in security_events:
        severity_color = {"Info": "🔵", "Warning": "🟡", "Critical": "🔴"}[event['severity']]
        with st.expander(f"{severity_color} {event['event']} - {event['timestamp'].strftime('%Y-%m-%d %H:%M')}"):
            st.write(f"**Severity:** {event['severity']}")
            st.write(f"**Action Taken:** {event['action']}")
            st.write(f"**Timestamp:** {event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Security recommendations
    st.subheader("💡 Security Recommendations")
    
    recommendations = [
        "🔑 Implement automatic API key rotation every 90 days",
        "🔍 Enable advanced threat detection for all AI endpoints",
        "📝 Review and update access policies quarterly",
        "🛡️ Implement zero-trust network architecture",
        "📊 Enhanced monitoring for unusual AI usage patterns"
    ]
    
    for rec in recommendations:
        st.info(rec)

if __name__ == "__main__":
    main()