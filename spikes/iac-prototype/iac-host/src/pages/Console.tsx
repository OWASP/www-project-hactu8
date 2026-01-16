import React, { Suspense } from 'react';

const StreamlitConsole = React.lazy(() => import('iac_mfe_primary/StreamlitConsole'));


const Console = () => (
  <div className="flex flex-col min-h-screen w-full h-full">
    <header className="p-4 bg-white shadow z-10">
      <h2>IAC Console</h2>
    </header>

    <main className="flex-1 relative overflow-hidden">
      <Suspense fallback={<div className="p-4">Loading Console...</div>}>
        <StreamlitConsole />
      </Suspense>
    </main>
  </div>
);

export default Console;