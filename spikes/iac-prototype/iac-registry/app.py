import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import random
from typing import Dict, List, Tuple, Optional, Union

# Color constants for theming
COLOR_TERMINAL_GREEN = "#00ff00"
COLOR_TERMINAL_AMBER = "#ffb000"
COLOR_CYAN = "#00ffff"
COLOR_MAGENTA = "#ff00ff"
COLOR_EDGE = "#444444"
COLOR_SELECTED_NODE = "#FFD700"
COLOR_NODE_BORDER = "white"
COLOR_PLOT_BG = "#000000"
COLOR_PAPER_BG = "#000000"

# Configure page
st.set_page_config(
    page_title="Enterprise Registry Visualization",
    page_icon="🏢",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
        color: #213547;
        border-bottom: 2px solid #213547;
        margin-bottom: 2rem;
    }
    .registry-section {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        border-left: 4px solid #213547;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 8px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    .node-info {
        background-color: #e8f4f8;
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid #1f77b4;
        margin-top: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Mock data for the registry
@st.cache_data
def load_registry_data():
    """Load mock registry data"""
    data = {
        "AI Applications": [
            {"name": "Customer Service Bot", "status": "Active", "department": "Support", "version": "v2.1"},
            {"name": "Fraud Detection AI", "status": "Active", "department": "Finance", "version": "v1.8"},
            {"name": "Document Analyzer", "status": "Maintenance", "department": "Legal", "version": "v3.0"},
            {"name": "Recommendation Engine", "status": "Active", "department": "Marketing", "version": "v2.5"},
            {"name": "Quality Control AI", "status": "Active", "department": "Manufacturing", "version": "v1.3"},
            {"name": "Inventory Optimizer", "status": "Testing", "department": "Supply Chain", "version": "v2.0-beta"},
        ],
        "Model Platforms": [
            {"name": "Azure OpenAI Service", "status": "Active", "department": "IT", "version": "GPT-4"},
            {"name": "AWS SageMaker", "status": "Active", "department": "Data Science", "version": "Latest"},
            {"name": "Google Vertex AI", "status": "Active", "department": "Research", "version": "v2.0"},
            {"name": "IBM Watson", "status": "Deprecated", "department": "Legacy", "version": "v1.5"},
            {"name": "Hugging Face Hub", "status": "Active", "department": "Research", "version": "v4.21"},
        ],
        "Agents": [
            {"name": "Data Collection Agent", "status": "Active", "department": "Analytics", "version": "v1.2"},
            {"name": "Monitoring Agent", "status": "Active", "department": "DevOps", "version": "v2.0"},
            {"name": "Security Agent", "status": "Active", "department": "Security", "version": "v1.7"},
            {"name": "Backup Agent", "status": "Active", "department": "IT", "version": "v3.1"},
            {"name": "Compliance Agent", "status": "Testing", "department": "Compliance", "version": "v1.0-beta"},
        ],
        "MCP Servers": [
            {"name": "Central Auth Server", "status": "Active", "department": "Security", "version": "v2.3"},
            {"name": "Data Gateway", "status": "Active", "department": "IT", "version": "v1.9"},
            {"name": "API Gateway", "status": "Active", "department": "Development", "version": "v2.1"},
            {"name": "Message Broker", "status": "Maintenance", "department": "Infrastructure", "version": "v1.5"},
        ]
    }
    return data

@st.cache_data
def generate_network_data(registry_data: Dict) -> Tuple[List, List]:
    """Generate network visualization data"""
    nodes = []
    edges = []
    
    # Color mapping for different types - Terminal/High-tech theme
    colors = {
        "AI Applications": COLOR_TERMINAL_GREEN,    # Terminal green
        "Model Platforms": COLOR_TERMINAL_AMBER,    # Terminal amber/orange
        "Agents": COLOR_CYAN,                       # Cyan
        "MCP Servers": COLOR_MAGENTA                # Magenta
    }
    
    # Department positions for layout
    dept_positions = {
        "Support": (0, 0),
        "Finance": (1, 0),
        "Legal": (2, 0),
        "Marketing": (0, 1),
        "Manufacturing": (1, 1),
        "Supply Chain": (2, 1),
        "IT": (0, 2),
        "Data Science": (1, 2),
        "Research": (2, 2),
        "Legacy": (0, 3),
        "Analytics": (1, 3),
        "DevOps": (2, 3),
        "Security": (0, 4),
        "Compliance": (1, 4),
        "Development": (2, 4),
        "Infrastructure": (0, 5)
    }
    
    node_id = 0
    node_mapping = {}
    
    # Create nodes
    for category, items in registry_data.items():
        for item in items:
            dept = item["department"]
            base_pos = dept_positions.get(dept, (random.uniform(0, 3), random.uniform(0, 5)))
            
            # Add some randomness to avoid overlap
            x = base_pos[0] + random.uniform(-0.3, 0.3)
            y = base_pos[1] + random.uniform(-0.3, 0.3)
            
            nodes.append({
                "id": node_id,
                "name": item["name"],
                "category": category,
                "department": dept,
                "status": item["status"],
                "version": item["version"],
                "x": x,
                "y": y,
                "color": colors[category]
            })
            
            node_mapping[f"{category}_{item['name']}"] = node_id
            node_id += 1
    
    # Create edges (mock relationships)
    # AI Applications connect to Model Platforms
    ai_apps = [n for n in nodes if n["category"] == "AI Applications"]
    platforms = [n for n in nodes if n["category"] == "Model Platforms"]
    
    for app in ai_apps:
        # Connect to a random platform
        platform = random.choice(platforms)
        edges.append({
            "source": app["id"],
            "target": platform["id"],
            "relationship": "uses"
        })
    
    # Agents connect to MCP Servers
    agents = [n for n in nodes if n["category"] == "Agents"]
    servers = [n for n in nodes if n["category"] == "MCP Servers"]
    
    for agent in agents:
        # Connect to a random server
        server = random.choice(servers)
        edges.append({
            "source": agent["id"],
            "target": server["id"],
            "relationship": "connects_to"
        })
    
    # Add some cross-category connections
    for _ in range(5):
        source = random.choice(nodes)
        target = random.choice(nodes)
        if source["id"] != target["id"]:
            edges.append({
                "source": source["id"],
                "target": target["id"],
                "relationship": "depends_on"
            })
    
    return nodes, edges

def create_network_visualization(nodes: List, edges: List, selected_node_id: Optional[int] = None):
    """Create the network visualization using Plotly"""
    
    # Create edge traces
    edge_x = []
    edge_y = []
    edge_info = []
    
    for edge in edges:
        source_node = next(n for n in nodes if n["id"] == edge["source"])
        target_node = next(n for n in nodes if n["id"] == edge["target"])
        
        edge_x.extend([source_node["x"], target_node["x"], None])
        edge_y.extend([source_node["y"], target_node["y"], None])
        edge_info.append(f"{source_node['name']} -> {target_node['name']}")
    
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color=COLOR_EDGE),  # Darker gray for high-tech look
        hoverinfo='none',
        mode='lines'
    )
    
    # Create node traces by category
    traces = [edge_trace]
    
    categories = list(set(n["category"] for n in nodes))
    for category in categories:
        category_nodes = [n for n in nodes if n["category"] == category]
        
        node_x = [n["x"] for n in category_nodes]
        node_y = [n["y"] for n in category_nodes]
        
        # Highlight selected node
        node_colors = []
        node_sizes = []
        for n in category_nodes:
            if selected_node_id and n["id"] == selected_node_id:
                node_colors.append(COLOR_SELECTED_NODE)  # Gold for selected
                node_sizes.append(20)
            else:
                node_colors.append(n["color"])
                node_sizes.append(15)
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=[n["name"] for n in category_nodes],
            textposition="top center",
            name=category,
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color=COLOR_NODE_BORDER)
            ),
            hovertext=[
                f"<b>{n['name']}</b><br>" +
                f"Category: {n['category']}<br>" +
                f"Department: {n['department']}<br>" +
                f"Status: {n['status']}<br>" +
                f"Version: {n['version']}"
                for n in category_nodes
            ],
            customdata=[n["id"] for n in category_nodes]
        )
        traces.append(node_trace)
    
    # Create figure
    fig = go.Figure(data=traces)
    
    # Center on selected node if specified
    if selected_node_id:
        selected_node = next(n for n in nodes if n["id"] == selected_node_id)
        x_range = [selected_node["x"] - 1.5, selected_node["x"] + 1.5]
        y_range = [selected_node["y"] - 1.5, selected_node["y"] + 1.5]
    else:
        x_range = [min(n["x"] for n in nodes) - 0.5, max(n["x"] for n in nodes) + 0.5]
        y_range = [min(n["y"] for n in nodes) - 0.5, max(n["y"] for n in nodes) + 0.5]
    
    fig.update_layout(
        title=dict(
            text="Enterprise Registry Network Visualization",
            font=dict(size=16)
        ),
        showlegend=True,
        hovermode='closest',
        margin=dict(b=20,l=5,r=5,t=40),
        annotations=[ dict(
            text="Click on nodes to center the view and see details",
            showarrow=False,
            xref="paper", yref="paper",
            x=0.005, y=-0.002,
            font=dict(color="gray", size=12)
        )],
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=x_range),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=y_range),
        plot_bgcolor=COLOR_PLOT_BG,  # Keep black background for scatter
        paper_bgcolor=COLOR_PAPER_BG,  # Keep black paper background for scatter
        height=500
    )
    
    return fig

def display_registry_list(registry_data: Dict, selected_category: Optional[str] = None):
    """Display the registry list in the sidebar"""
    st.markdown('<div class="main-header"><h2>🏢 Enterprise Registry</h2></div>', unsafe_allow_html=True)
    
    # Summary metrics
    total_items = sum(len(items) for items in registry_data.values())
    active_items = sum(len([item for item in items if item["status"] == "Active"]) for items in registry_data.values())
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Items", total_items)
    with col2:
        st.metric("Active Items", active_items)
    
    st.markdown("---")
    
    # Display each category
    selected_items = []
    for category, items in registry_data.items():
        with st.expander(f"📋 {category} ({len(items)})", expanded=(category == selected_category)):
            for item in items:
                status_emoji = "✅" if item["status"] == "Active" else "⚠️" if item["status"] == "Testing" else "🔧" if item["status"] == "Maintenance" else "❌"
                
                if st.button(f"{status_emoji} {item['name']}", key=f"btn_{category}_{item['name']}", use_container_width=True):
                    selected_items.append((category, item))
                
                st.caption(f"Dept: {item['department']} | Version: {item['version']}")
    
    return selected_items

def main():
    """Main application function"""
    # st.title("🏢 Enterprise Registry Visualization")
    # st.markdown("Explore and visualize your enterprise's AI applications, model platforms, agents, and MCP servers.")
    
    # Load data
    registry_data = load_registry_data()
    nodes, edges = generate_network_data(registry_data)
    
    # Initialize session state
    if 'selected_node_id' not in st.session_state:
        st.session_state.selected_node_id = None
    if 'selected_item_info' not in st.session_state:
        st.session_state.selected_item_info = None
    
    # Layout: 1/3 for registry list, 2/3 for visualization
    col1, col2 = st.columns([1, 2])
    
    with col1:
        # st.markdown("### 📋 Registry Items")
        selected_items = display_registry_list(registry_data)
        
        # Handle item selection from registry list
        if selected_items:
            category, item = selected_items[-1]  # Get the last clicked item
            # Find the corresponding node
            matching_node = next((n for n in nodes if n["name"] == item["name"] and n["category"] == category), None)
            if matching_node:
                st.session_state.selected_node_id = matching_node["id"]
                st.session_state.selected_item_info = matching_node
    
    with col2:
        st.markdown("### 🌐 Network Visualization")
        
        # Create and display the visualization
        fig = create_network_visualization(nodes, edges, st.session_state.selected_node_id)
        
        # Handle click events
        selected_data = st.plotly_chart(fig, use_container_width=True, key="network_viz")
        
        # Display selected node information
        if st.session_state.selected_item_info:
            node = st.session_state.selected_item_info
            st.markdown('<div class="node-info">', unsafe_allow_html=True)
            st.markdown(f"### 🎯 Selected: {node['name']}")
            
            info_col1, info_col2 = st.columns(2)
            with info_col1:
                st.write(f"**Category:** {node['category']}")
                st.write(f"**Department:** {node['department']}")
            with info_col2:
                st.write(f"**Status:** {node['status']}")
                st.write(f"**Version:** {node['version']}")
            
            # Show connections
            connections = [e for e in edges if e["source"] == node["id"] or e["target"] == node["id"]]
            if connections:
                st.write(f"**Connections:** {len(connections)} items")
                for conn in connections[:3]:  # Show first 3 connections
                    if conn["source"] == node["id"]:
                        target_node = next(n for n in nodes if n["id"] == conn["target"])
                        st.caption(f"→ {target_node['name']} ({conn['relationship']})")
                    else:
                        source_node = next(n for n in nodes if n["id"] == conn["source"])
                        st.caption(f"← {source_node['name']} ({conn['relationship']})")
            
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Reset selection button
        if st.button("🔄 Reset View", use_container_width=True):
            st.session_state.selected_node_id = None
            st.session_state.selected_item_info = None
            st.rerun()

if __name__ == "__main__":
    main()
