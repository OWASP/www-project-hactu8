import { useEffect, useState } from 'react';
import logo from '../assets/iac.logo.png';
import { hactu8Api } from '../services/hactu8Api';
import type { Branding } from '../services/hactu8Api';

const fallback: Branding = {
  name: 'OWASP HACTU8',
  tagline: 'Repeatable assurance tests for AI systems',
  report_title: 'HACTU8 Assurance Report',
  primary_color: '#213547',
  accent_color: '#fbbf24',
};

export default function Header() {
  const [branding, setBranding] = useState(fallback);

  useEffect(() => {
    hactu8Api.branding().then(setBranding).catch(() => undefined);
  }, []);

  return (
    <header className="header" style={{ borderBottomColor: branding.accent_color }}>
      <div className="header__left">
        <img src={logo} alt="" className="header__logo" />
        <div>
          <div className="header__title">{branding.name}</div>
          <div className="header__tagline">{branding.tagline}</div>
        </div>
      </div>
      <span className="status-pill">PHASE 1 MVP</span>
    </header>
  );
}
