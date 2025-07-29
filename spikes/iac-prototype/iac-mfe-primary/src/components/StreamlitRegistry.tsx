// src/components/IntelligentConsole.tsx
import React from 'react';

const url = "http://localhost:8504?embed=true"; // Replace with your Streamlit app's URL

const StreamlitRegistry: React.FC = () => {
    return (
        <div style={{ width: '100%', height: '100%', minHeight: 0, minWidth: 0, display: 'flex', flex: 1 }}>
            <iframe
                src={url}
                className="w-full h-full flex-1"
                allow="fullscreen"
                style={{ minHeight: '750px', minWidth: '750px', flex: 1, border: 'none'}}
                loading="lazy"
                title="IAC Registry"
            />
        </div>
    );
};

export default StreamlitRegistry;
