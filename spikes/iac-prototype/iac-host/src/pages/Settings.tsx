
import React, { useState } from 'react';

const sections = [
    { key: 'profile', label: 'Profile' },
    { key: 'security', label: 'Security' },
    { key: 'keys', label: 'API Keys' },
    { key: 'notifications', label: 'Notifications' },
    { key: 'billing', label: 'Billing' },
];

function SectionPanel({ section }: { section: string }) {
    switch (section) {
        case 'profile':
            return (
                <div>
                    <h3>Profile Settings</h3>
                    <p>Update your personal information, email, and avatar.</p>
                </div>
            );
        case 'security':
            return (
                <div>
                    <h3>Security</h3>
                    <p>Change your password, enable 2FA, and review recent activity.</p>
                </div>
            );
        case 'keys':
            return (
                <div>
                    <h3>API Keys</h3>
                    <p>Manage your API keys and access tokens.</p>
                </div>
            );
        case 'notifications':
            return (
                <div>
                    <h3>Notifications</h3>
                    <p>Configure your notification preferences.</p>
                </div>
            );
        case 'billing':
            return (
                <div>
                    <h3>Billing</h3>
                    <p>View invoices and manage payment methods.</p>
                </div>
            );
        default:
            return <div>Select a section</div>;
    }
}

const Settings = () => {
    const [selected, setSelected] = useState('profile');

    // Minimal, unstyled layout
    return (
        <div style={{ display: 'flex', minHeight: '60vh' }}>
            <aside style={{ width: 200 }}>
                <h3>Settings</h3>
                <nav>
                    <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                        {sections.map((s) => (
                            <li key={s.key}>
                                <button
                                    style={{
                                        width: '100%',
                                        padding: '0.75rem 1rem',
                                        background: selected === s.key ? '#213547' : 'transparent',
                                        border: 'none',
                                        textAlign: 'left',
                                        fontWeight: selected === s.key ? 600 : 400,
                                        cursor: 'pointer',
                                    }}
                                    onClick={() => setSelected(s.key)}
                                >
                                    {s.label}
                                </button>
                            </li>
                        ))}
                    </ul>
                </nav>
            </aside>
            <main style={{ flex: 1, padding: '2rem' }}>
                <SectionPanel section={selected} />
            </main>
        </div>
    );
};

export default Settings;
