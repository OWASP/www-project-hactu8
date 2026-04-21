#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';

const ROOT = process.cwd();
const RELEASE_ROOT = path.join(ROOT, '.release');
const RELEASE_DIR = path.join(RELEASE_ROOT, 'iac-prototype-standalone');
const INCLUDE_VENV = process.argv.includes('--with-venv');

const IGNORE_DIRS = new Set([
  '.git',
  '.github',
  '.vscode',
  '.release',
  '.iac-runtime',
  'node_modules',
  '__pycache__',
  '.pytest_cache',
]);

if (!INCLUDE_VENV) {
  IGNORE_DIRS.add('.venv');
}

const IGNORE_FILES = [
  '.DS_Store',
  '.coverage',
];

const INCLUDE_TOP_LEVEL = [
  'scripts',
  'extensions',
  'iac-console',
  'iac-copilot-api',
  'iac-dashboard',
  'iac-host',
  'iac-mfe-primary',
  'iac-registry',
  'extension_api.py',
  'iac_extension_installer.py',
  'package.json',
  'README.md',
];

function shouldIgnoreName(name) {
  if (IGNORE_DIRS.has(name)) return true;
  return IGNORE_FILES.includes(name);
}

function copyRecursive(src, dest) {
  const stat = fs.statSync(src);

  if (stat.isDirectory()) {
    const dirName = path.basename(src);
    if (shouldIgnoreName(dirName)) return;

    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dest, entry));
    }
    return;
  }

  const fileName = path.basename(src);
  if (shouldIgnoreName(fileName)) return;

  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}

function writeLaunchers() {
  const startSh = `#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -d "iac-host/node_modules" || ! -d "iac-console/.venv" ]]; then
  echo "[standalone] First run detected. Bootstrapping dependencies..."
  npm run iac:bootstrap
fi

npm run iac:up
`;

  const stopSh = `#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
npm run iac:down
`;

  const startCmd = `@echo off
setlocal
cd /d %~dp0

if not exist iac-host\\node_modules (
  echo [standalone] First run detected. Bootstrapping dependencies...
  call npm run iac:bootstrap
  if errorlevel 1 exit /b 1
)
if not exist iac-console\\.venv (
  echo [standalone] First run detected. Bootstrapping dependencies...
  call npm run iac:bootstrap
  if errorlevel 1 exit /b 1
)

call npm run iac:up
`;

  const stopCmd = `@echo off
setlocal
cd /d %~dp0
call npm run iac:down
`;

  fs.writeFileSync(path.join(RELEASE_DIR, 'start-iac.sh'), startSh);
  fs.writeFileSync(path.join(RELEASE_DIR, 'stop-iac.sh'), stopSh);
  fs.writeFileSync(path.join(RELEASE_DIR, 'start-iac.cmd'), startCmd);
  fs.writeFileSync(path.join(RELEASE_DIR, 'stop-iac.cmd'), stopCmd);

  fs.chmodSync(path.join(RELEASE_DIR, 'start-iac.sh'), 0o755);
  fs.chmodSync(path.join(RELEASE_DIR, 'stop-iac.sh'), 0o755);
}

function zipReleaseIfPossible() {
  const zipPath = path.join(RELEASE_ROOT, 'iac-prototype-standalone.zip');
  if (fs.existsSync(zipPath)) fs.rmSync(zipPath);

  if (process.platform === 'darwin') {
    const result = spawnSync('ditto', ['-c', '-k', '--sequesterRsrc', '--keepParent', RELEASE_DIR, zipPath], {
      stdio: 'inherit',
    });
    return result.status === 0;
  }

  if (process.platform === 'linux') {
    const result = spawnSync('zip', ['-r', zipPath, path.basename(RELEASE_DIR)], {
      cwd: RELEASE_ROOT,
      stdio: 'inherit',
    });
    return result.status === 0;
  }

  if (process.platform === 'win32') {
    const cmd = [
      '-NoProfile',
      '-Command',
      `Compress-Archive -Path \"${RELEASE_DIR}\" -DestinationPath \"${zipPath}\" -Force`,
    ];
    const result = spawnSync('powershell', cmd, { stdio: 'inherit' });
    return result.status === 0;
  }

  return false;
}

function main() {
  fs.mkdirSync(RELEASE_ROOT, { recursive: true });
  fs.rmSync(RELEASE_DIR, { recursive: true, force: true });
  fs.mkdirSync(RELEASE_DIR, { recursive: true });

  for (const item of INCLUDE_TOP_LEVEL) {
    const src = path.join(ROOT, item);
    if (!fs.existsSync(src)) continue;
    const dest = path.join(RELEASE_DIR, item);
    copyRecursive(src, dest);
  }

  writeLaunchers();

  const zipped = zipReleaseIfPossible();

  console.log(`[iac-package] Standalone folder created at: ${RELEASE_DIR}`);
  console.log(`[iac-package] Included .venv directories: ${INCLUDE_VENV ? 'yes' : 'no'}`);
  if (zipped) {
    console.log(`[iac-package] Zip created at: ${path.join(RELEASE_ROOT, 'iac-prototype-standalone.zip')}`);
  } else {
    console.log('[iac-package] Zip creation skipped (no platform archiver found).');
  }
}

main();
