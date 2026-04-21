#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';

const ROOT = process.cwd();
const RUNTIME_DIR = path.join(ROOT, '.iac-runtime');
const STATE_FILE = path.join(RUNTIME_DIR, 'supervisor-state.json');
const START_TIMEOUT_MS = 60_000;
const SHUTDOWN_GRACE_MS = 8_000;
const DEFAULT_HOST_URL = 'http://localhost:3000';

const isWindows = process.platform === 'win32';

function commandName(name) {
  if (!isWindows) {
    return name;
  }

  if (name === 'npm') {
    return 'npm.cmd';
  }

  return name;
}

function venvPythonPath(serviceDir) {
  const winPath = path.join(ROOT, serviceDir, '.venv', 'Scripts', 'python.exe');
  const unixPath = path.join(ROOT, serviceDir, '.venv', 'bin', 'python');

  if (isWindows && fs.existsSync(winPath)) {
    return winPath;
  }

  if (!isWindows && fs.existsSync(unixPath)) {
    return unixPath;
  }

  return 'python';
}

const services = [
  {
    name: 'extension-api',
    cwd: ROOT,
    command: () => venvPythonPath('iac-console'),
    args: ['extension_api.py'],
    env: {
      EXTENSION_API_PORT: '5001',
      FLASK_ENV: 'development',
      FLASK_DEBUG: '1',
      PYTHONPATH: ROOT,
    },
    waitFor: { type: 'http', url: 'http://127.0.0.1:5001/health' },
  },
  {
    name: 'iac-dashboard',
    cwd: path.join(ROOT, 'iac-dashboard'),
    command: () => venvPythonPath('iac-dashboard'),
    args: [
      '-m',
      'streamlit',
      'run',
      'app.py',
      '--server.port',
      '8511',
      '--server.headless',
      'true',
      '--browser.gatherUsageStats',
      'false',
    ],
    env: {
      PYTHONPATH: path.join(ROOT, 'iac-dashboard'),
      STREAMLIT_DEBUG: 'true',
    },
    waitFor: { type: 'tcp', host: '127.0.0.1', port: 8511 },
  },
  {
    name: 'iac-registry',
    cwd: path.join(ROOT, 'iac-registry'),
    command: () => venvPythonPath('iac-registry'),
    args: [
      '-m',
      'streamlit',
      'run',
      'app.py',
      '--server.port',
      '8512',
      '--server.headless',
      'true',
      '--browser.gatherUsageStats',
      'false',
    ],
    env: {
      PYTHONPATH: path.join(ROOT, 'iac-registry'),
      STREAMLIT_DEBUG: 'true',
    },
    waitFor: { type: 'tcp', host: '127.0.0.1', port: 8512 },
  },
  {
    name: 'iac-console',
    cwd: path.join(ROOT, 'iac-console'),
    command: () => venvPythonPath('iac-console'),
    args: [
      '-m',
      'streamlit',
      'run',
      'app.py',
      '--server.port',
      '8513',
      '--server.headless',
      'true',
      '--browser.gatherUsageStats',
      'false',
    ],
    env: {
      PYTHONPATH: path.join(ROOT, 'iac-console'),
    },
    waitFor: { type: 'tcp', host: '127.0.0.1', port: 8513 },
  },
  {
    name: 'iac-copilot-api',
    cwd: path.join(ROOT, 'iac-copilot-api'),
    command: () => venvPythonPath('iac-copilot-api'),
    args: ['-m', 'uvicorn', 'app:app', '--reload', '--port', '8000'],
    env: {
      PYTHONPATH: path.join(ROOT, 'iac-copilot-api'),
      OWASP_REPOS_DISCOVER: '0',
    },
    waitFor: { type: 'tcp', host: '127.0.0.1', port: 8000 },
  },
  {
    name: 'iac-mfe-primary',
    cwd: path.join(ROOT, 'iac-mfe-primary'),
    command: () => commandName('npm'),
    args: ['run', 'serve:dist'],
    env: {
      VITE_PORT: '3001',
    },
    waitFor: { type: 'tcp', host: '127.0.0.1', port: 3001 },
  },
  {
    name: 'iac-host',
    cwd: path.join(ROOT, 'iac-host'),
    command: () => commandName('npm'),
    // '--' passes the remaining args to vite; --host 0.0.0.0 ensures IPv4 127.0.0.1 is reachable
    args: ['run', 'dev', '--', '--port', '3000', '--host', '0.0.0.0'],
    env: {
      VITE_CORS_ORIGIN: 'http://localhost:3001',
      VITE_PORT: '3000',
      VITE_EXTENSION_API_URL: 'http://localhost:5001',
      VITE_API_BASE_URL: 'http://localhost:5001',
    },
    waitFor: { type: 'tcp', host: '127.0.0.1', port: 3000 },
  },
];

const children = new Map();
let shuttingDown = false;

function ensureRuntimeDir() {
  if (!fs.existsSync(RUNTIME_DIR)) {
    fs.mkdirSync(RUNTIME_DIR, { recursive: true });
  }
}

function writeState() {
  ensureRuntimeDir();

  const state = {
    supervisorPid: process.pid,
    startedAt: new Date().toISOString(),
    services: Array.from(children.entries()).map(([name, child]) => ({
      name,
      pid: child.pid,
    })),
  };

  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function clearState() {
  if (fs.existsSync(STATE_FILE)) {
    fs.unlinkSync(STATE_FILE);
  }
}

function isPidAlive(pid) {
  if (!pid || typeof pid !== 'number') {
    return false;
  }

  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function waitForTcp(host, port, timeoutMs) {
  const start = Date.now();

  return new Promise((resolve, reject) => {
    const tryConnect = () => {
      const socket = new net.Socket();

      socket.setTimeout(1000);

      socket.once('connect', () => {
        socket.destroy();
        resolve();
      });

      socket.once('timeout', () => {
        socket.destroy();
        retry();
      });

      socket.once('error', () => {
        socket.destroy();
        retry();
      });

      socket.connect(port, host);
    };

    const retry = () => {
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`Timed out waiting for tcp ${host}:${port}`));
        return;
      }

      setTimeout(tryConnect, 400);
    };

    tryConnect();
  });
}

function waitForHttp(url, timeoutMs) {
  const start = Date.now();
  const isHttps = url.startsWith('https://');
  const client = isHttps ? https : http;

  return new Promise((resolve, reject) => {
    const ping = () => {
      const req = client.get(url, (res) => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 500) {
          res.resume();
          resolve();
          return;
        }

        res.resume();
        retry();
      });

      req.on('error', retry);
      req.setTimeout(1500, () => {
        req.destroy();
        retry();
      });
    };

    const retry = () => {
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`Timed out waiting for HTTP ${url}`));
        return;
      }

      setTimeout(ping, 500);
    };

    ping();
  });
}

function isPortInUse(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const done = (inUse) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(inUse);
      }
    };

    socket.setTimeout(800);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));

    socket.connect(port, host);
  });
}

async function assertServicePortFree(service) {
  if (!service.waitFor) {
    return;
  }

  let host;
  let port;

  if (service.waitFor.type === 'tcp') {
    host = service.waitFor.host;
    port = service.waitFor.port;
  }

  if (service.waitFor.type === 'http') {
    const parsed = new URL(service.waitFor.url);
    host = parsed.hostname;
    if (parsed.port) {
      port = Number(parsed.port);
    } else {
      port = parsed.protocol === 'https:' ? 443 : 80;
    }
  }

  if (!host || !port) {
    return;
  }

  const inUse = await isPortInUse(host, port);
  if (inUse) {
    throw new Error(
      `Port ${port} is already in use before starting ${service.name}. ` +
      `Run \"npm run iac:down\" (or stop the conflicting process) and retry.`
    );
  }
}

function assertNoRunningSupervisor() {
  if (!fs.existsSync(STATE_FILE)) {
    return;
  }

  try {
    const state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    if (state?.supervisorPid && isPidAlive(state.supervisorPid)) {
      throw new Error(
        `Supervisor already running (pid=${state.supervisorPid}). ` +
        `Run \"npm run iac:down\" first.`
      );
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes('Supervisor already running')) {
      throw err;
    }
  }

  // Stale state from a crashed run.
  clearState();
}

function raceProcessDeath(child, serviceName) {
  return new Promise((_, reject) => {
    child.once('exit', (code, signal) => {
      reject(new Error(`${serviceName} exited during startup (code=${code ?? 'null'}, signal=${signal ?? 'null'})`));
    });
  });
}

async function waitForService(service, child) {
  const deathRace = child ? raceProcessDeath(child, service.name) : null;

  const readyWait = (() => {
    if (!service.waitFor) {
      return sleep(1200);
    }

    if (service.waitFor.type === 'tcp') {
      return waitForTcp(service.waitFor.host, service.waitFor.port, START_TIMEOUT_MS);
    }

    if (service.waitFor.type === 'http') {
      return waitForHttp(service.waitFor.url, START_TIMEOUT_MS);
    }

    return Promise.reject(new Error(`Unsupported wait type for ${service.name}`));
  })();

  if (deathRace) {
    await Promise.race([readyWait, deathRace]);
  } else {
    await readyWait;
  }
}

function log(message) {
  console.log(`[iac-supervisor] ${message}`);
}

function shouldOpenBrowser() {
  const value = (process.env.IAC_OPEN_BROWSER ?? '1').toLowerCase();
  return !['0', 'false', 'no', 'off'].includes(value);
}

function openBrowser(url) {
  let command;
  let args;

  if (process.platform === 'darwin') {
    command = 'open';
    args = [url];
  } else if (isWindows) {
    command = 'cmd';
    args = ['/c', 'start', '', url];
  } else {
    command = 'xdg-open';
    args = [url];
  }

  try {
    const child = spawn(command, args, {
      detached: true,
      stdio: 'ignore',
      shell: false,
    });
    child.unref();
    log(`Opened browser at ${url}`);
  } catch (err) {
    log(`Failed to open browser automatically: ${err.message}`);
  }
}

function spawnService(service) {
  const command = service.command();
  const env = {
    ...process.env,
    ...service.env,
  };

  log(`Starting ${service.name}`);

  const child = spawn(command, service.args, {
    cwd: service.cwd,
    env,
    stdio: 'inherit',
    detached: !isWindows,
  });

  child.on('error', (err) => {
    if (shuttingDown) {
      return;
    }

    log(`${service.name} failed to start: ${err.message}`);
    shutdown(1).catch((shutdownErr) => {
      console.error(shutdownErr);
      process.exit(1);
    });
  });

  child.on('exit', (code, signal) => {
    children.delete(service.name);
    writeState();

    if (!shuttingDown) {
      log(`${service.name} exited unexpectedly (code=${code ?? 'null'}, signal=${signal ?? 'null'})`);
      shutdown(1).catch((err) => {
        console.error(err);
        process.exit(1);
      });
    }
  });

  children.set(service.name, child);
  writeState();

  return child;
}

async function terminateChildTree(child, force = false) {
  if (!child || !child.pid) {
    return;
  }

  if (isWindows) {
    const args = ['/pid', String(child.pid), '/t'];
    if (force) {
      args.push('/f');
    }

    await new Promise((resolve) => {
      const killer = spawn('taskkill', args, { stdio: 'ignore' });
      killer.on('exit', () => resolve());
      killer.on('error', () => resolve());
    });
    return;
  }

  const targetPid = -child.pid;
  try {
    process.kill(targetPid, force ? 'SIGKILL' : 'SIGTERM');
  } catch {
    try {
      process.kill(child.pid, force ? 'SIGKILL' : 'SIGTERM');
    } catch {
      // Process may already be gone.
    }
  }
}

async function shutdown(exitCode = 0) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  log('Stopping all services...');

  const entries = Array.from(children.entries()).reverse();

  for (const [, child] of entries) {
    await terminateChildTree(child, false);
  }

  await sleep(SHUTDOWN_GRACE_MS);

  for (const [, child] of entries) {
    if (!child.killed) {
      await terminateChildTree(child, true);
    }
  }

  children.clear();
  clearState();

  log('Shutdown complete');
  process.exit(exitCode);
}

async function up() {
  assertNoRunningSupervisor();

  process.on('SIGINT', () => {
    shutdown(0).catch((err) => {
      console.error(err);
      process.exit(1);
    });
  });

  process.on('SIGTERM', () => {
    shutdown(0).catch((err) => {
      console.error(err);
      process.exit(1);
    });
  });

  process.on('SIGHUP', () => {
    shutdown(0).catch((err) => {
      console.error(err);
      process.exit(1);
    });
  });

  try {
    for (const service of services) {
      await assertServicePortFree(service);
      const child = spawnService(service);
      await waitForService(service, child);
      log(`${service.name} is ready`);

      if (service.name === 'iac-host' && shouldOpenBrowser()) {
        openBrowser(process.env.IAC_HOST_URL || DEFAULT_HOST_URL);
      }
    }

    log('All core services are running');
  } catch (err) {
    log(`Startup failed: ${err.message}`);
    await shutdown(1);
  }
}

function readState() {
  if (!fs.existsSync(STATE_FILE)) {
    return null;
  }

  return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
}

async function down() {
  const state = readState();
  if (!state) {
    log('No running supervisor state found. Nothing to stop.');
    return;
  }

  const ownPid = process.pid;

  if (state.supervisorPid && state.supervisorPid !== ownPid) {
    try {
      process.kill(state.supervisorPid, 'SIGTERM');
      log(`Requested supervisor shutdown (pid=${state.supervisorPid})`);
      return;
    } catch {
      // Fall through to direct child cleanup.
    }
  }

  if (Array.isArray(state.services)) {
    for (const service of state.services) {
      if (!service.pid) {
        continue;
      }

      if (isWindows) {
        await new Promise((resolve) => {
          const killer = spawn('taskkill', ['/pid', String(service.pid), '/t', '/f'], { stdio: 'ignore' });
          killer.on('exit', () => resolve());
          killer.on('error', () => resolve());
        });
      } else {
        try {
          process.kill(-service.pid, 'SIGKILL');
        } catch {
          try {
            process.kill(service.pid, 'SIGKILL');
          } catch {
            // Process may already be gone.
          }
        }
      }
    }
  }

  clearState();
  log('Stopped services listed in state file');
}

async function main() {
  const command = process.argv[2] ?? 'up';

  try {
    if (command === 'up') {
      await up();
      return;
    }

    if (command === 'down') {
      await down();
      return;
    }

    throw new Error(`Unknown command: ${command}. Use "up" or "down".`);
  } catch (err) {
    console.error(`[iac-supervisor] ${err.message}`);
    process.exit(1);
  }
}

main();
