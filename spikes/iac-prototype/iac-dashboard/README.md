# Enterprise AI Monitoring Dashboard

A comprehensive Streamlit dashboard for tracking and monitoring AI activities in enterprise environments.

## Features

### 8 Core Tracking Capabilities:

1. **Overview Dashboard** - High-level metrics and alerts
2. **AI Activity Tracking** - Real-time activity monitoring with heatmaps
3. **Event Monitoring** - Critical events and alerts timeline
4. **Agent Performance** - Comparison of 6 competing AI agents
5. **MCP Servers** - Model Context Protocol server status
6. **Registered Services** - AI services registry and health
7. **Cost Analysis** - Cost tracking and optimization recommendations
8. **Security & Compliance** - Security checks and compliance status

## Key Components

### 📊 Monitoring Features
- **Real-time Activity Tracking**: Monitor AI agent requests, response times, and success rates
- **Event Timeline**: Track critical events, warnings, and system alerts
- **Performance Comparison**: Line charts comparing 6 competing agents
- **Cost Analysis**: Monthly cost breakdown and optimization recommendations
- **Security Dashboard**: Compliance status and security checks

### 🤖 AI Agents Tracked
- Azure OpenAI GPT-4
- Custom RAG Agent
- Copilot Assistant
- Document Analyzer
- Code Assistant
- Data Insights AI

### 🌐 MCP Server Integration
- Azure Resource Manager MCP
- Enterprise Data MCP
- Security Compliance MCP
- Code Repository MCP

### 🔧 Registered AI Services
- Azure OpenAI Service
- Azure Cognitive Search
- Custom RAG Pipeline
- Azure Form Recognizer
- GitHub Copilot Enterprise

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the dashboard:
```bash
streamlit run app.py
```

## Usage

The dashboard will be available at `http://localhost:8501`

### Navigation
Use the sidebar to navigate between different views:
- **Overview**: Key metrics and recent alerts
- **AI Activity Tracking**: Detailed activity monitoring
- **Event Monitoring**: System events and alerts
- **Agent Performance**: Performance comparison charts
- **MCP Servers**: Server status and connections
- **Registered Services**: Service registry and health
- **Cost Analysis**: Cost breakdown and optimization
- **Security & Compliance**: Security status and compliance

### Features
- **Auto-refresh**: Enable 30-second auto-refresh in the sidebar
- **Interactive Filters**: Filter data by date ranges, agents, and severity
- **Real-time Updates**: Live activity logs and event monitoring
- **Responsive Design**: Works on desktop and mobile devices

## Dashboard Views

### 1. Overview
- Total AI requests metrics
- Active services count
- MCP server connectivity status
- Average success rates
- Recent critical alerts
- Daily request trends

### 2. AI Activity Tracking
- Activity filters by agent and date
- Request volume heatmap
- Real-time activity log
- Performance metrics

### 3. Event Monitoring
- Event summary by severity
- Timeline visualization
- Event filtering and details
- Status tracking

### 4. Agent Performance
- Performance comparison charts
- Success rate trends
- Response time analysis
- Individual agent deep dive

### 5. MCP Servers
- Server connectivity status
- Active connections monitoring
- Heartbeat tracking
- Connection timeline

### 6. Registered Services
- Service registry table
- Health status monitoring
- Usage trends
- Cost per service

### 7. Cost Analysis
- Monthly cost breakdown
- Cost per request metrics
- Optimization recommendations
- Detailed cost analysis

### 8. Security & Compliance
- Security score dashboard
- Compliance framework status
- Security event monitoring
- Recommendations

## Customization

The dashboard uses mock data for demonstration. To integrate with real systems:

1. Replace mock data functions with actual API calls
2. Configure Azure authentication for real Azure services
3. Implement actual MCP server connections
4. Connect to your monitoring and logging systems

## Technical Architecture

- **Frontend**: Streamlit with Plotly charts
- **Data Processing**: Pandas for data manipulation
- **Visualization**: Plotly Express and Graph Objects
- **Styling**: Custom CSS for enhanced UI
- **Real-time Updates**: Session state management

## Azure Integration

The dashboard is designed to integrate with Azure services:
- Azure OpenAI Service
- Azure Cognitive Services
- Azure Monitor
- Azure Cost Management
- Azure Security Center

Follow Azure best practices for authentication and security when connecting to real services.
