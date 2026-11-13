import { hactu8Api } from '../services/hactu8Api';

export default function Settings() {
  return (
    <section className="page">
      <div className="page-heading"><div><h1>Settings</h1><p>MVP endpoints and safety posture.</p></div></div>
      <article className="panel settings-list">
        <div><span>HACTU8 API</span><code>{hactu8Api.baseUrl}</code></div>
        <div><span>Lamb target</span><code>http://127.0.0.1:5500</code></div>
        <div><span>Lamb MCP</span><code>http://127.0.0.1:5500/mcp</code></div>
        <div><span>Default model</span><code>echo (offline)</code></div>
        <div><span>Default classifier</span><code>keyword (offline)</code></div>
      </article>
    </section>
  );
}
