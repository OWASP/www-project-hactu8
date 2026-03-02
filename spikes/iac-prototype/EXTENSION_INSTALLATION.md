# Extension Installation Guide (~/.iac Setup)

This guide explains how to install extensions to `~/.iac` directory with automatic zip download, SHA256 verification, and extraction.

## Architecture

```
User clicks "Install" on Extensions page
    ↓
Frontend calls POST /api/extensions/install
    ↓
Backend (Python/Flask) receives request
    ↓
Backend downloads zip from registry.zipFile URL
    ↓
Backend verifies SHA256 hash
    ↓
Backend extracts to ~/.iac/extensions/{extensionId}/
    ↓
Backend writes config.json to install directory
    ↓
Backend returns success + install path
    ↓
Frontend updates sidebar with installed extension
```

## Frontend Setup

### 1. Environment Configuration

Set the API base URL in your `.env` file:

```
VITE_API_BASE_URL=http://localhost:5000
# or for production:
# VITE_API_BASE_URL=https://api.example.com
```

### 2. ExtensionService Already Updated

The frontend is now configured to:
- Call `POST /api/extensions/install` when installing
- Wait for the backend to download/extract
- Update local state after success
- Show loading indicator during installation

### 3. Usage in Extensions Page

```tsx
// Extensions.tsx already handles this:
const handleInstall = (entry: RegistryEntry, installPath?: string) => {
  setIsInstallingId(entry.manifest.id);
  
  installExtension(entry, installPath)
    .then(() => {
      // Success - sidebar auto-updates via context
      setView({ 
        sidebarTab: 'installed', 
        mainPanel: 'detail', 
        selectedExtensionId: entry.manifest.id 
      });
    })
    .catch((err) => {
      setError(err.message);
    });
};
```

## Backend Setup

### 1. Python Installation

```bash
pip install flask  # or fastapi + uvicorn
```

### 2. Flask Implementation

```python
# app.py
from flask import Flask, request
from iac_extension_installer import setup_extension_routes

app = Flask(__name__)

# Set up the /api/extensions/install endpoint
setup_extension_routes(app)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
```

### 3. FastAPI Implementation

```python
# app.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from iac_extension_installer import setup_extension_routes_fastapi

app = FastAPI()

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

setup_extension_routes_fastapi(app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
```

## API Endpoint Reference

### POST /api/extensions/install

**Request:**
```json
{
  "extensionId": "prompt-injection-tests",
  "zipUrl": "https://github.com/OWASP/.../releases/download/.../ext.zip",
  "sha256": "abc123def456...",
  "installPath": "~/.iac/extensions",
  "hostConfig": {
    "hostVersion": "0.1.0",
    "extensionId": "prompt-injection-tests",
    "port": 8501,
    "resultsDir": "~/.iac/results/prompt-injection-tests",
    "settings": {}
  }
}
```

**Success Response (200):**
```json
{
  "success": true,
  "extensionId": "prompt-injection-tests",
  "installPath": "/home/user/.iac/extensions/prompt-injection-tests"
}
```

**Error Response (400/500):**
```json
{
  "error": "SHA256 mismatch: expected abc123..., got def456..."
}
```

## Directory Structure After Installation

```
~/.iac/
├── extensions/
│   └── prompt-injection-tests/
│       ├── app.py
│       ├── manifest.json
│       ├── requirements.txt
│       ├── config.json  ← Written by backend
│       └── tests/
└── results/
    └── prompt-injection-tests/
        └── run-001.json
```

## When to Use Custom Install Paths

You can pass a custom `installPath` when installing:

```tsx
// Install to /opt/extensions instead of ~/.iac/extensions
installExtension(entry, "/opt/extensions")
```

The full path will be: `/opt/extensions/{extensionId}`

## File Hash Verification

The backend automatically verifies SHA256 hashes from the registry:

```python
# Example: registry.json entry
{
  "manifest": { ... },
  "zipFile": "https://example.com/my-ext.zip",
  "sha256": "5f4dcc3b5aa765d61d8327deb882cf99"
}
```

If the downloaded file doesn't match, installation fails with a clear error message.

## Troubleshooting

### "Failed to download zip"
- Check registry.zipFile URL is accessible
- Verify firewall/proxy settings allow HTTP access
- Check CORS headers if frontend and backend are on different domains

### "SHA256 mismatch"
- Verify registry.json has correct hash
- Check if zip file was corrupted during download
- Regenerate hash if registry entry updated: `sha256sum file.zip`

### "Installation failed: [errno 13] Permission denied"
- Ensure `~/.iac` directory is writable by the backend process
- Check user permissions: `ls -la ~/.iac/`
- May need to run backend with `sudo` or adjust directory ownership

### Extension doesn't appear in sidebar
- Check backend returned `success: true`
- Verify `installPath` in response matches expected location
- Check browser console for network errors
- Refresh page to resync localStorage if needed

## Testing

### 1. Direct Backend Test

```bash
cd /path/to/iac-prototype
python iac_extension_installer.py
```

### 2. API Test with curl

```bash
curl -X POST http://localhost:5000/api/extensions/install \
  -H "Content-Type: application/json" \
  -d '{
    "extensionId": "test-ext",
    "zipUrl": "https://example.com/test.zip",
    "sha256": "abc123...",
    "installPath": "~/.iac/extensions"
  }'
```

### 3. From JavaScript

```javascript
const response = await fetch('http://localhost:5000/api/extensions/install', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    extensionId: 'test-ext',
    zipUrl: 'https://example.com/test.zip',
    sha256: 'abc123...',
    installPath: '~/.iac/extensions'
  })
});

const result = await response.json();
console.log(result);
```

## Next Steps

1. **Implement backend API** — Use the Flask or FastAPI template from `iac_extension_installer.py`
2. **Test installation flow** — Install an extension from the UI
3. **Verify results** — Check `~/.iac/extensions/{id}/` directory exists with files
4. **Update Streamlit extensions** — They now read from `config.json` at install path
5. **Add uninstall cleanup** — Remove directory from `~/.iac/extensions/` when uninstalling
