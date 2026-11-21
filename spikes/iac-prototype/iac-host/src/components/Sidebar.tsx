import { NavLink } from 'react-router-dom';

const items = [
  ['/learn', 'Learn'],
  ['/run', 'Run'],
  ['/results', 'Results'],
  ['/reports', 'Reports'],
  ['/registry', 'Registry'],
  ['/settings', 'Settings'],
];

export default function Sidebar() {
  return (
    <aside className="mvp-sidebar">
      <div className="mvp-sidebar__label">ASSURANCE CENTER</div>
      <nav className="mvp-nav">
        {items.map(([path, label]) => (
          <NavLink
            key={path}
            to={path}
            className={({ isActive }) => `mvp-nav__link${isActive ? ' active' : ''}`}
          >
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}

