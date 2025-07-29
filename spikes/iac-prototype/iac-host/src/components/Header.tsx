
import React from 'react';
import logo from '../assets/iac.logo.png';

interface HeaderProps {
  selectedConfig: string;
  setSelectedConfig: (val: string) => void;
}

const Header: React.FC<HeaderProps> = ({ selectedConfig, setSelectedConfig }) => {
  const headerIcon = (
    <img src={logo} alt="IAC Logo" style={{ width: 40, height: 40, marginRight: 12, objectFit: 'contain' }} />
  );
  const profileIcon = (
    <svg width="28" height="28" fill="currentColor" viewBox="0 0 20 20"><circle cx="10" cy="7" r="4"/><rect x="3" y="13" width="14" height="5" rx="2"/></svg>
  );
  return (
    <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 2rem', height: 64, background: '#213547', boxShadow: '0 2px 8px 0 #e5e7eb', zIndex: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        {headerIcon}
        <span style={{ fontWeight: 700, fontSize: 24, color: '#fff' }}>Intelligence Assurance Center</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <select value={selectedConfig} onChange={e => setSelectedConfig(e.target.value)} style={{ padding: '6px 12px', borderRadius: 6, border: '1px solid #e5e7eb', fontSize: 15 }}>
          <option value="config 1">config 1</option>
          <option value="config 2">config 2</option>
        </select>
        <button style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }} title="Profile">
          {profileIcon}
        </button>
      </div>
    </header>
  );
};

export default Header;
