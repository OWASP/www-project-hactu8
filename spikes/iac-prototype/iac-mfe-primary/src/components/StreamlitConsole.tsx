// src/components/IntelligentConsole.tsx
import { useState } from 'react';

const url = "http://localhost:8503?embed=true"; // Replace with your Streamlit app's URL

const StreamlitConsole: React.FC = () => {

    const [loaded, setLoaded] = useState(false);

    return (


        <div style={{ background: '#111', width: '100%', height: '100%', minHeight: 0, minWidth: 0, display: 'flex', flex: 1 }}>
        {!loaded && <div className="iframe-loading-overlay" />}
        <iframe
            src={url}
            onLoad={() => setLoaded(true)}
            style={{ background: '#111', minHeight: '750px', minWidth: '750px', flex: 1, border: 'none' }}
            title="Embedded"
        />
        </div>
    );
};

export default StreamlitConsole;
