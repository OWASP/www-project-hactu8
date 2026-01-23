import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useFeatureFlags } from '../contexts/FeatureFlagContext';

const createOptions = [
  { key: 'project', label: 'New Project' },
  { key: 'prompt', label: 'New Prompt' },
  { key: 'note', label: 'New Note' },
  { key: 'team', label: 'New Team' },
];

interface NavbarProps {
  systemMessage?: string;
  messageType?: 'info' | 'warning' | 'error' | 'success';
  backgroundColor?: string;
  textColor?: string;
}

const Navbar: React.FC<NavbarProps> = ({
  systemMessage = '',
  messageType = 'info',
  backgroundColor = '#f3f4f6',
  textColor = '#6b7280',
}) => {
  const [showMenu, setShowMenu] = useState(false);
  const { flags } = useFeatureFlags();

  const handleCreate = (key: string) => {
    setShowMenu(false);
    // Placeholder: replace with modal or navigation as needed
    alert(`Create: ${key}`);
  };

  // Message type styling
  const getMessageStyle = () => {
    const baseStyle = {
      padding: '4px 12px',
      borderRadius: '4px',
      fontSize: '14px',
      fontWeight: 500,
    };

    switch (messageType) {
      case 'warning':
        return { ...baseStyle, background: '#fef3c7', color: '#92400e', border: '1px solid #fbbf24' };
      case 'error':
        return { ...baseStyle, background: '#fee2e2', color: '#991b1b', border: '1px solid #f87171' };
      case 'success':
        return { ...baseStyle, background: '#d1fae5', color: '#065f46', border: '1px solid #34d399' };
      case 'info':
      default:
        return { ...baseStyle, background: '#dbeafe', color: '#1e40af', border: '1px solid #60a5fa' };
    }
  };

  return (
    <nav style={{
      height: 44,
      background: backgroundColor,
      display: 'flex',
      alignItems: 'center',
      padding: '0 2rem',
      borderBottom: '1px solid #e5e7eb',
      position: 'relative',
      transition: 'background-color 0.3s ease',
    }}>
      {systemMessage ? (
        <div style={getMessageStyle()}>
          {systemMessage}
        </div>
      ) : (
        <span style={{ color: textColor, fontSize: 15, flex: 1 }}></span>
      )}
      <div style={{ flex: 1 }}></div>
      {flags.navbar.createNewResource && (
        <div style={{ position: 'relative' }}>
          <Link
            to="/create-new-resource"
            title="Create new resource"
            style={{
              background: 'none',
              border: 'none',
              height: 36,
              padding: 0,
              display: 'flex',
              alignItems: 'center',
              fontSize: 15,
              fontWeight: 500,
              cursor: 'pointer',
              marginLeft: 8,
              gap: 8,
              boxShadow: 'none',
              outline: 'none',
              color: textColor,
              textDecoration: 'none',
            }}
          >
            <span style={{ fontSize: 18, fontWeight: 400, marginRight: 2 }}>+</span> Create New Resource
          </Link>
        </div>
      )}
    </nav>
  );
};

export default Navbar;
