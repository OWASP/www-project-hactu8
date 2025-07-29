#!/bin/bash

# Launch script for the Enterprise Registry Visualization App

echo "🚀 Starting Enterprise Registry Visualization App..."
echo "📍 Make sure you're in the correct directory"

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    echo "📦 Activating virtual environment..."
    source .venv/bin/activate
fi

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "📥 Installing dependencies..."
    pip install -r requirements.txt
fi

# Launch Streamlit app
echo "🌐 Launching Streamlit app..."
echo "🔗 The app will open in your browser automatically"
echo "📱 If it doesn't open, go to: http://localhost:8501"
echo ""
echo "💡 Tip: Use Ctrl+C to stop the application"
echo ""

streamlit run app.py
