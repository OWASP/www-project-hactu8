import React, { Suspense } from 'react';

const StreamlitDashboard = React.lazy(() => import('iac_mfe_primary/StreamlitDashboard'));

type DashboardErrorBoundaryState = {
  hasError: boolean;
  message: string;
};

class DashboardErrorBoundary extends React.Component<React.PropsWithChildren, DashboardErrorBoundaryState> {
  state: DashboardErrorBoundaryState = {
    hasError: false,
    message: '',
  };

  static getDerivedStateFromError(error: unknown): DashboardErrorBoundaryState {
    return {
      hasError: true,
      message: error instanceof Error ? error.message : 'Unknown error loading dashboard.',
    };
  }

  componentDidCatch(error: unknown): void {
    console.error('Failed to load dashboard micro frontend:', error);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-4">
          <h3>Dashboard failed to load</h3>
          <p>
            Ensure the dashboard remote is running on port 3001 and Streamlit dashboard is available on port
            8511.
          </p>
          <pre className="whitespace-pre-wrap">{this.state.message}</pre>
        </div>
      );
    }

    return this.props.children;
  }
}

const Dashboard = () => (
  <div className="flex flex-col min-h-screen w-full h-full">
    <header className="p-4 bg-white shadow z-10">
      <h2>IAC Dashboard</h2>
    </header>

    <main className="flex-1 relative overflow-hidden">
      <DashboardErrorBoundary>
        <Suspense fallback={<div className="p-4">Loading Streamlit Dashboard...</div>}>
          <StreamlitDashboard />
        </Suspense>
      </DashboardErrorBoundary>
    </main>
  </div>
);

export default Dashboard;