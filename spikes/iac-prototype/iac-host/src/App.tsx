import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

import Header from './components/Header';
import Sidebar from './components/Sidebar';
import { RegistryProvider } from './contexts/RegistryProvider';
import Learn from './pages/Learn';
import Run from './pages/Console';
import Results from './pages/AssuranceResults';
import Reports from './pages/Reports';
import Registry from './pages/Registry';
import Settings from './pages/Settings';

export default function App() {
  return (
    <RegistryProvider>
      <BrowserRouter>
        <div className="app-shell">
          <Header />
          <div className="app-body">
            <Sidebar />
            <main className="app-main">
              <Routes>
                <Route path="/" element={<Navigate to="/learn" replace />} />
                <Route path="/learn" element={<Learn />} />
                <Route path="/run" element={<Run />} />
                <Route path="/results" element={<Results />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/registry" element={<Registry />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </main>
          </div>
        </div>
      </BrowserRouter>
    </RegistryProvider>
  );
}
