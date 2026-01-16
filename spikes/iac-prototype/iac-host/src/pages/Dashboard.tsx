import React, { Suspense } from 'react';

const StreamlitDashboard = React.lazy(() => import('iac_mfe_primary/StreamlitDashboard'));

const Dashboard = () => (
  <div className="flex flex-col min-h-screen w-full h-full">
    <header className="p-4 bg-white shadow z-10">
      <h2>IAC Dashboard</h2>
    </header>

    <main className="flex-1 relative overflow-hidden">
      <Suspense fallback={<div className="p-4">Loading Streamlit Dashboard...</div>}>
        <StreamlitDashboard />
      </Suspense>
    </main>
  </div>
);

export default Dashboard;