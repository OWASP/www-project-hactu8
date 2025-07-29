import React, { Suspense } from 'react';

const StreamlitRegistry = React.lazy(() => import('iac_mfe_primary/StreamlitRegistry'));


const Registry = () => (
  <div className="flex flex-col min-h-screen w-full h-full">
    <header className="p-4 bg-white shadow">
      <h2>IAC Registry</h2>
    </header>
    <main className="flex-1 h-full overflow-hidden flex justify-center items-start">
      <div>
      {/* <div className="w-full max-w-full sm:max-w-2xl md:max-w-3xl lg:max-w-4xl xl:max-w-6xl 2xl:max-w-7xl mx-auto h-full flex flex-col min-w-[1320px] min-h-[1400px] sm:min-w-[1500px] sm:min-h-[1500px] md:min-w-[1700px] md:min-h-[1600px]"> */}
        <Suspense fallback={<div>Loading Streamlit Registry ...</div>}>
          <StreamlitRegistry />
        </Suspense>
      </div>
    </main>
  </div>
);

export default Registry;