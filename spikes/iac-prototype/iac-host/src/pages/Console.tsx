import React, { Suspense } from 'react';

const StreamlitConsole = React.lazy(() => import('iac_mfe_primary/StreamlitConsole'));


const Console = () => (
  <div style={{ background: '#111' }} className="flex flex-col min-h-screen w-full h-full">
    <header className="p-4 bg-white shadow">
      <h2>IAC Console</h2>
    </header>
    <main className="flex-1 h-full overflow-hidden flex justify-center items-start">
      <div style={{ background: '#111' }}>
        <Suspense fallback={<div style={{ background: '#111', minHeight: 400 }}>Loading Streamlit Console ...</div>}>
          <StreamlitConsole />
        </Suspense>
      </div>
    </main>
  </div>
);

export default Console;