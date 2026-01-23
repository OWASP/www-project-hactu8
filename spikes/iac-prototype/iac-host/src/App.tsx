// src/App.tsx
import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Navbar from './components/Navbar';
import { FeatureFlagProvider } from './contexts/FeatureFlagContext';
import { SystemMessageProvider, useSystemMessage } from './contexts/SystemMessageContext';
import { getEffectiveConfig } from './config/environmentConfig';

import Dashboard from './pages/Dashboard';
import Events from './pages/Events';
import Logs from './pages/Logs';
import Agents from './pages/Agents';
import Reports from './pages/Reports';
import AssuranceResults from './pages/AssuranceResults';
import Console from './pages/Console';
import Project from './pages/Project';
import PromptInjection from './pages/PromptInjection';
import TrainingLeak from './pages/TrainingLeak';
import MisbehaviorMonitor from './pages/MisbehaviorMonitor';
import OverrelianceRisk from './pages/OverrelianceRisk';
import AgencyValidator from './pages/AgencyValidator';
import InsecureOutput from './pages/InsecureOutput';
import SupplyChain from './pages/SupplyChain';
import ModelIdentity from './pages/ModelIdentity';
import AuthContextAudit from './pages/AuthContextAudit';
import PrivacyCompliance from './pages/PrivacyCompliance';
import Workbench from './pages/Workbench';
import Registry from './pages/Registry';
import Users from './pages/Users';
import Settings from './pages/Settings';
import Profile from './pages/Profile';
import Extensions from './pages/Extensions';
import CreateNewResource from './pages/CreateNewResource';

// Internal component that uses the context
const AppContent: React.FC = () => {
  const [selectedConfig, setSelectedConfig] = useState<string>('config 1');
  const { message, messageType } = useSystemMessage();
  const envConfig = getEffectiveConfig();

  return (
    <Router>
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          height: '100dvh',
          width: '100vw',
          overflow: 'hidden',
        }}
      >
        <Header selectedConfig={selectedConfig} setSelectedConfig={setSelectedConfig} />
        <Navbar
          systemMessage={message}
          messageType={messageType}
          backgroundColor={envConfig.navbarColor}
          textColor={envConfig.navbarTextColor}
        />
          <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
            <Sidebar />
            <main
            style={{
              flex: 1,
              minHeight: 0,
              minWidth: 0,
              overflow: 'hidden',
              position: 'relative',
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            <div
              style={{
                position: 'relative',
                flex: 1,
                minHeight: 0,
                minWidth: 0,
                overflow: 'hidden',
              }}
            >
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/agents" element={<Agents />} />
                <Route path="/events" element={<Events />} />
                <Route path="/logs" element={<Logs />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/assurance" element={<AssuranceResults />} />
                <Route path="/console" element={<Console />} />
                <Route path="/projects/:projectId" element={<Project />} />
                <Route path="/prompt-injection" element={<PromptInjection />} />
                <Route path="/training-leak" element={<TrainingLeak />} />
                <Route path="/misbehavior-monitor" element={<MisbehaviorMonitor />} />
                <Route path="/overreliance-risk" element={<OverrelianceRisk />} />
                <Route path="/agency-validator" element={<AgencyValidator />} />
                <Route path="/insecure-output" element={<InsecureOutput />} />
                <Route path="/supply-chain" element={<SupplyChain />} />
                <Route path="/model-identity" element={<ModelIdentity />} />
                <Route path="/auth-context-audit" element={<AuthContextAudit />} />
                <Route path="/privacy-compliance" element={<PrivacyCompliance />} />
                <Route path="/workbench" element={<Workbench />} />
                <Route path="/registry" element={<Registry />} />
                <Route path="/users" element={<Users />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="/profile" element={<Profile />} />
                <Route path="/extensions" element={<Extensions />} />
                <Route path="/create-new-resource" element={<CreateNewResource />} />
              </Routes>
            </div>
          </main>
        </div>
      </div>
    </Router>
  );
};

function App() {
  return (
    <FeatureFlagProvider>
      <SystemMessageProvider>
        <AppContent />
      </SystemMessageProvider>
    </FeatureFlagProvider>
  );
}

export default App;