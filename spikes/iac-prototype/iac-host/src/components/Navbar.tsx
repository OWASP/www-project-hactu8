import React, { useState } from 'react';
import { Link } from 'react-router-dom';

const createOptions = [
  { key: 'project', label: 'New Project' },
  { key: 'prompt', label: 'New Prompt' },
  { key: 'note', label: 'New Note' },
  { key: 'team', label: 'New Team' },
];

const Navbar: React.FC = () => {
  const [showMenu, setShowMenu] = useState(false);

  const handleCreate = (key: string) => {
    setShowMenu(false);
    // Placeholder: replace with modal or navigation as needed
    alert(`Create: ${key}`);
  };

  return (
    <nav style={{ height: 44, background: '#f3f4f6', display: 'flex', alignItems: 'center', padding: '0 2rem', borderBottom: '1px solid #e5e7eb', position: 'relative' }}>
      <span style={{ color: '#6b7280', fontSize: 15, flex: 1 }}>Navigation Bar</span>
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
          }}
        >
          <span style={{ fontSize: 18, fontWeight: 400, marginRight: 2 }}>+</span> Create New Resource
        </Link>
      </div>
    </nav>
  );
};

export default Navbar;
