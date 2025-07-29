# Enterprise Registry Visualization App

A Streamlit application that displays a mock enterprise registry with interactive network visualization.

## Features

- **Registry List (Left Column - 1/3 width)**: Shows categorized items including:
  - AI Applications
  - Model Platforms  
  - Agents
  - MCP Servers

- **Network Visualization (Right Column - 2/3 width)**: Interactive network graph showing:
  - Nodes representing registry items
  - Color-coded by category
  - Clickable nodes for interactivity
  - Auto-centering on selected nodes
  - Connection relationships between items

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Run the Streamlit app:
```bash
streamlit run app.py
```

2. Open your browser to the URL shown in the terminal (typically http://localhost:8501)

## Usage

- Browse the registry items in the left column
- Click on any item in the registry list to center the visualization on that node
- Click on nodes in the visualization to see detailed information
- Use the "Reset View" button to return to the full network view
- Hover over nodes to see tooltips with item details

## Mock Data

The application includes sample data for demonstration:
- 6 AI Applications across different departments
- 5 Model Platforms (Azure OpenAI, AWS SageMaker, etc.)
- 5 Agents for various operational tasks
- 4 MCP Servers for infrastructure

The network shows relationships between these items, such as AI Applications connecting to Model Platforms and Agents connecting to MCP Servers.
