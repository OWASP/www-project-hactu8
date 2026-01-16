// src/components/IntelligentConsole.tsx
import React from 'react';
import SmartFrame from './SmartFrame';


const url = "http://localhost:8512?embed=true"; // Replace with your Streamlit app's URL

const StreamlitRegistry: React.FC = () => {
    return (
        <div
            style={{
                position: 'absolute', // key
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
            }}
        >
            <SmartFrame src={url} />
        </div>
    );
};

export default StreamlitRegistry;
