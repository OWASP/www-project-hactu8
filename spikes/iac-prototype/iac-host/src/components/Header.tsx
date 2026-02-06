
import React from 'react';
import logo from '../assets/iac.logo.png';

interface HeaderProps {
  selectedConfig: string;
  setSelectedConfig: (val: string) => void;
}

const Header: React.FC<HeaderProps> = ({ selectedConfig, setSelectedConfig }) => {
  const headerIcon = (
    <img src={logo} alt="IAC Logo" className="header__logo" />
  );
  const profileIcon = (
    <svg className="header__profile-icon" viewBox="0 0 20 20"><circle cx="10" cy="7" r="4"/><rect x="3" y="13" width="14" height="5" rx="2"/></svg>
  );
  return (
    <header className="header">
      <div className="header__left">
        {headerIcon}
        <span className="header__title"><b>OWASP</b> HACTU8<br/>Intelligence Assurance Center</span>
      </div>
      <div className="header__right">
        {/* <select value={selectedConfig} onChange={e => setSelectedConfig(e.target.value)} style={{ padding: '6px 12px', borderRadius: 6, border: '1px solid #e5e7eb', fontSize: 15 }}>
          <option value="config 1">config 1</option>
          <option value="config 2">config 2</option>
        </select> */}
        <button className="header__profile-button" title="Profile">
          {profileIcon}
        </button>
      </div>
    </header>
  );
};

export default Header;
