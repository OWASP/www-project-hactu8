#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawn, spawnSync } from 'node:child_process';

const ROOT = process.cwd();
const isWindows = process.platform === 'win32';
const MIN_PYTHON_MAJOR = 3;
const MIN_PYTHON_MINOR = 10;

let selectedPython = null;

function resolveCommand(name) {
  if (!isWindows) return name;
  if (name === 'npm') return 'npm.cmd';
  return name;
}

function run(command, args, cwd = ROOT) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: 'inherit',
      shell: false,
    });

    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} ${args.join(' ')} failed with exit code ${code}`));
    });
  });
}

function getPythonVersion(command) {
  const result = spawnSync(command, ['-c', 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")'], {
    cwd: ROOT,
    encoding: 'utf8',
    shell: false,
  });

  if (result.status !== 0) {
    return null;
  }

  const raw = (result.stdout || '').trim();
  const match = raw.match(/^(\d+)\.(\d+)$/);
  if (!match) {
    return null;
  }

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    raw,
  };
}

function isPythonCompatible(version) {
  if (!version) return false;
  if (version.major > MIN_PYTHON_MAJOR) return true;
  if (version.major < MIN_PYTHON_MAJOR) return false;
  return version.minor >= MIN_PYTHON_MINOR;
}

function resolvePythonCommand() {
  if (selectedPython) {
    return selectedPython;
  }

  const candidates = [
    process.env.PYTHON,
    'python3.13',
    'python3.12',
    'python3.11',
    'python3.10',
    isWindows ? 'python' : 'python3',
    'python',
  ].filter(Boolean);

  const seen = new Set();
  const tried = [];

  for (const candidate of candidates) {
    if (seen.has(candidate)) continue;
    seen.add(candidate);

    const version = getPythonVersion(candidate);
    if (!version) {
      tried.push(`${candidate}:unavailable`);
      continue;
    }

    if (isPythonCompatible(version)) {
      selectedPython = candidate;
      console.log(`[iac-bootstrap] Using Python ${version.raw} from ${candidate}`);
      return selectedPython;
    }

    tried.push(`${candidate}:${version.raw}`);
  }

  throw new Error(
    `No compatible Python found (need >= ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}). ` +
    `Tried: ${tried.join(', ') || 'none'}. Set PYTHON to a compatible interpreter and retry.`
  );
}

function venvPythonPath(serviceDir) {
  const winPath = path.join(ROOT, serviceDir, '.venv', 'Scripts', 'python.exe');
  const unixPath = path.join(ROOT, serviceDir, '.venv', 'bin', 'python');

  if (fs.existsSync(winPath)) return winPath;
  if (fs.existsSync(unixPath)) return unixPath;
  return null;
}

async function ensureVenv(serviceDir) {
  const existing = venvPythonPath(serviceDir);
  if (existing) {
    const version = getPythonVersion(existing);
    if (isPythonCompatible(version)) {
      return existing;
    }

    // Recreate incompatible virtual envs (for example, an earlier Python 3.9 attempt).
    fs.rmSync(path.join(ROOT, serviceDir, '.venv'), { recursive: true, force: true });
  }

  const preferredPython = resolvePythonCommand();
  const cwd = path.join(ROOT, serviceDir);
  await run(preferredPython, ['-m', 'venv', '.venv'], cwd);

  const created = venvPythonPath(serviceDir);
  if (!created) {
    throw new Error(`Failed to create virtual environment for ${serviceDir}`);
  }

  return created;
}

async function setupPythonService(serviceDir, requirementsFile) {
  const cwd = path.join(ROOT, serviceDir);
  const python = await ensureVenv(serviceDir);

  await run(python, ['-m', 'pip', 'install', '--upgrade', 'pip'], cwd);
  await run(python, ['-m', 'pip', 'install', '-r', requirementsFile], cwd);
}

async function setupNodeService(serviceDir, build = false) {
  const cwd = path.join(ROOT, serviceDir);
  const npm = resolveCommand('npm');

  await run(npm, ['install'], cwd);
  if (build) {
    await run(npm, ['run', 'build'], cwd);
  }
}

async function main() {
  console.log('[iac-bootstrap] Installing Node dependencies...');
  await setupNodeService('iac-host');
  await setupNodeService('iac-mfe-primary', true);

  console.log('[iac-bootstrap] Installing Python dependencies...');
  await setupPythonService('iac-dashboard', 'requirements.txt');
  await setupPythonService('iac-registry', 'requirements.txt');
  await setupPythonService('iac-console', 'requirements.txt');
  await setupPythonService('iac-copilot-api', 'requirements.txt');

  // extension_api.py runs from iac-console venv and requires Flask + CORS.
  const consolePython = await ensureVenv('iac-console');
  await run(consolePython, ['-m', 'pip', 'install', 'flask', 'flask-cors'], path.join(ROOT, 'iac-console'));

  // Optional: install bundled extension dependencies in the same runtime env.
  const bundledExtensionReqs = [
    path.join(ROOT, 'extensions', 'iac-prompt-injection-tests', 'requirements.txt'),
    path.join(ROOT, 'extensions', 'mcp-attack-vulnerability-tests', 'requirements.txt'),
  ];

  for (const req of bundledExtensionReqs) {
    if (fs.existsSync(req)) {
      await run(consolePython, ['-m', 'pip', 'install', '-r', req], path.dirname(req));
    }
  }

  console.log('[iac-bootstrap] Bootstrap complete.');
}

main().catch((err) => {
  console.error(`[iac-bootstrap] ${err.message}`);
  process.exit(1);
});
