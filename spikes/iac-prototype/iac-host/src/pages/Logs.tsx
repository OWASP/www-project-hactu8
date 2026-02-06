
import React, { useState } from 'react';

const mockLogFiles = [
  'api-server.log',
  'worker-1.log',
  'db-events.log',
  'auth-service.log',
  'audit-trail.log',
  'registry-sync.log',
];

const mockLogs: Record<string, string[]> = {
  'api-server.log': [
    '[2025-07-29 10:01:23] INFO  Server started on port 8080',
    '[2025-07-29 10:02:10] WARN  Slow response for /api/validate',
    '[2025-07-29 10:03:45] ERROR  Unhandled exception: TypeError',
    '[2025-07-29 10:04:01] INFO  Health check passed',
  ],
  'worker-1.log': [
    '[2025-07-29 09:59:12] INFO  Worker initialized',
    '[2025-07-29 10:00:00] INFO  Task #123 completed',
    '[2025-07-29 10:05:00] INFO  Task #124 started',
  ],
  'db-events.log': [
    '[2025-07-29 10:01:00] INFO  Connection pool established',
    '[2025-07-29 10:02:30] WARN  Query took 1200ms',
    '[2025-07-29 10:03:00] INFO  Inserted 5 records',
  ],
  'auth-service.log': [
    '[2025-07-29 10:00:10] INFO  Auth token issued',
    '[2025-07-29 10:01:15] ERROR  Invalid credentials',
    '[2025-07-29 10:02:20] INFO  User logged out',
  ],
  'audit-trail.log': [
    '[2025-07-29 10:01:00] INFO  User admin updated settings',
    '[2025-07-29 10:02:00] INFO  User guest viewed logs',
    '[2025-07-29 10:03:00] INFO  User admin deleted API key',
  ],
  'registry-sync.log': [
    '[2025-07-29 10:00:00] INFO  Sync started',
    '[2025-07-29 10:01:00] INFO  Pulled 3 new records',
    '[2025-07-29 10:02:00] ERROR  Sync failed: timeout',
  ],
};

const Logs = () => {
  const [selected, setSelected] = useState(mockLogFiles[0]);

  return (
    <div style={{ display: 'flex', minHeight: '60vh', margin: '2rem' }}>
      <aside style={{ width: 300, borderRight: '1px solid #eee', padding: '1rem 1rem' }}>
        <h3>Log Files</h3>
        <nav>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {mockLogFiles.map((file) => (
              <li key={file}>
                <button
                  style={{
                    width: '100%',
                    padding: '0.75rem 1rem',
                    background: selected === file ? '#213547' : 'transparent',
                    // color: selected === file ? '#fff' : '#222',
                    border: 'none',
                    textAlign: 'left',
                    fontWeight: selected === file ? 600 : 400,
                    cursor: 'pointer',
                  }}
                  onClick={() => setSelected(file)}
                >
                  {file}
                </button>
              </li>
            ))}
          </ul>
        </nav>
      </aside>
      <main style={{ flex: 1, padding: '2rem' }}>
        <h3>{selected}</h3>
        <pre style={{ padding: '1rem', borderRadius: 4, fontSize: 14, overflowX: 'auto' }}>
          {(mockLogs[selected] || ['No log entries found.']).join('\n')}
        </pre>
      </main>
    </div>
  );
};

export default Logs;