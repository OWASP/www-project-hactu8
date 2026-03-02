#!/usr/bin/env python3
"""
Extension Installation API Server

Provides POST /api/extensions/install endpoint for downloading and extracting extensions
to ~/.iac/extensions directory.

Run with:
    python extension_api.py
    # Server runs on http://localhost:5000

Or set environment variables:
    FLASK_ENV=development
    FLASK_DEBUG=1
    EXTENSION_API_PORT=5000
    python extension_api.py
"""

import json
import os
import sys
from pathlib import Path

from flask import Flask, request, jsonify
from flask_cors import CORS

# Add parent directory to path to import iac_extension_installer
sys.path.insert(0, str(Path(__file__).parent))
from iac_extension_installer import ExtensionInstaller

# ===== Flask App Setup =====

app = Flask(__name__)

# Enable CORS to allow requests from localhost:5173 (Vite dev server)
CORS(
    app,
    resources={
        r"/*": {
            "origins": [
                "http://localhost:5173",
                "http://localhost:3000",
                "http://127.0.0.1:5173",
                "http://127.0.0.1:3000",
            ],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True,
        }
    },
)

# Initialize installer with ~/.iac directory
installer = ExtensionInstaller(base_path="~/.iac")


# ===== Health Check =====

@app.route("/health", methods=["GET"])
def health_check():
    """Simple health check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "extension-installer",
        "baseDirectory": str(installer.base_path),
    }), 200


# ===== Serve Extension Zip Files for Local Development =====

@app.route("/extensions/<path:filename>", methods=["GET"])
def serve_extension_file(filename):
    """Serve extension zip files from the local extensions directory for development."""
    from flask import send_from_directory
    extensions_dir = Path(__file__).parent / "extensions"
    return send_from_directory(extensions_dir, filename)


# ===== Extension Installation Endpoint =====

@app.route("/api/extensions/install", methods=["POST"])
def install_extension():
    """
    Install an extension from a remote zip URL.
    
    POST /api/extensions/install
    
    Request body:
    {
        "extensionId": "my-ext",
        "zipUrl": "https://example.com/ext.zip",
        "sha256": "abc123...",
        "installPath": "~/.iac/extensions",  // optional
        "hostConfig": { ... }  // optional
    }
    
    Response on success (200):
    {
        "success": true,
        "extensionId": "my-ext",
        "installPath": "/home/user/.iac/extensions/my-ext"
    }
    
    Response on error (400/500):
    {
        "error": "Error message"
    }
    """
    try:
        # Parse request JSON
        data = request.get_json()
        
        print(f"[DEBUG] Received request data: {json.dumps(data, indent=2)}")
        
        if not data:
            print("[ERROR] Request body is empty or not JSON")
            return jsonify({"error": "Request body must be JSON"}), 400
        
        # Extract parameters
        extension_id = data.get("extensionId")
        zip_url = data.get("zipUrl")
        sha256 = data.get("sha256")
        install_path = data.get("installPath")
        host_config = data.get("hostConfig")
        
        # Validate required fields
        if not extension_id:
            print("[ERROR] Missing extensionId")
            return jsonify({"error": "Missing required field: extensionId"}), 400
        if not zip_url:
            print(f"[ERROR] Missing zipUrl for extension {extension_id}")
            return jsonify({"error": "Missing required field: zipUrl"}), 400
        if not sha256:
            print(f"[ERROR] Missing sha256 for extension {extension_id}")
            return jsonify({"error": "Missing required field: sha256"}), 400
        
        print(f"[{extension_id}] Installation requested")
        print(f"  ZIP URL: {zip_url}")
        print(f"  SHA256: {sha256}")
        print(f"  Install path: {install_path or '~/.iac/extensions'}")
        
        # Call installer
        result = installer.install(
            extension_id=extension_id,
            zip_url=zip_url,
            sha256=sha256,
            install_path=install_path,
            host_config=host_config,
        )
        
        print(f"[{extension_id}] Installation succeeded: {result['installPath']}")
        return jsonify(result), 200
        
    except ValueError as e:
        # Hash mismatch or validation error
        error_msg = str(e)
        print(f"[ERROR] Validation failed: {error_msg}")
        return jsonify({"error": error_msg}), 400
        
    except RuntimeError as e:
        # Download, extraction, or file system error
        error_msg = str(e)
        print(f"[ERROR] Runtime error: {error_msg}")
        return jsonify({"error": error_msg}), 500
        
    except Exception as e:
        # Unexpected error
        error_msg = f"Unexpected error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": error_msg}), 500


# ===== Extension Uninstallation Endpoint =====

@app.route("/api/extensions/uninstall", methods=["POST"])
def uninstall_extension():
    """
    Uninstall an extension by deleting its directory.
    
    POST /api/extensions/uninstall
    
    Request body:
    {
        "extensionId": "my-ext",
        "installPath": "~/.iac/extensions/my-ext"  // optional
    }
    
    Response on success (200):
    {
        "success": true,
        "extensionId": "my-ext",
        "deletedPath": "/home/user/.iac/extensions/my-ext"
    }
    
    Response on error (400/500):
    {
        "error": "Error message"
    }
    """
    try:
        # Parse request JSON
        data = request.get_json()
        
        print(f"[DEBUG] Received uninstall request: {json.dumps(data, indent=2)}")
        
        if not data:
            print("[ERROR] Request body is empty or not JSON")
            return jsonify({"error": "Request body must be JSON"}), 400
        
        # Extract parameters
        extension_id = data.get("extensionId")
        install_path = data.get("installPath")
        
        # Validate required fields
        if not extension_id:
            print("[ERROR] Missing extensionId")
            return jsonify({"error": "Missing required field: extensionId"}), 400
        
        print(f"[{extension_id}] Uninstallation requested")
        if install_path:
            print(f"  Install path: {install_path}")
        
        # Call uninstaller
        result = installer.uninstall(
            extension_id=extension_id,
            install_path=install_path,
        )
        
        print(f"[{extension_id}] Uninstallation succeeded: {result['deletedPath']}")
        return jsonify(result), 200
        
    except ValueError as e:
        # Path not found or validation error
        error_msg = str(e)
        print(f"[ERROR] Validation failed: {error_msg}")
        return jsonify({"error": error_msg}), 400
        
    except RuntimeError as e:
        # File system error
        error_msg = str(e)
        print(f"[ERROR] Runtime error: {error_msg}")
        return jsonify({"error": error_msg}), 500
        
    except Exception as e:
        # Unexpected error
        error_msg = f"Unexpected error: {str(e)}"
        print(f"[ERROR] {error_msg}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": error_msg}), 500


# ===== Startup & Configuration =====

def create_directories():
    """Ensure ~/.iac directories exist with correct permissions."""
    base = Path("~/.iac").expanduser()
    extensions_dir = base / "extensions"
    results_dir = base / "results"
    
    for directory in [base, extensions_dir, results_dir]:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"✓ {directory} is ready")
    
    # Check permissions
    if not os.access(extensions_dir, os.W_OK):
        print(f"⚠ WARNING: {extensions_dir} is not writable!")
        print(f"  Fix with: chmod 755 {extensions_dir}")
        return False
    
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("Extension Installation API Server")
    print("=" * 60)
    
    # Check directory setup
    print("\nChecking directory permissions...")
    if not create_directories():
        print("\n⚠ Directory permission issues detected!")
        print("Please fix permissions before starting the server.")
        sys.exit(1)
    
    # Get configuration
    port = int(os.environ.get("EXTENSION_API_PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    
    print(f"\nStarting server:")
    print(f"  URL: http://localhost:{port}")
    print(f"  Install endpoint: POST /api/extensions/install")
    print(f"  Uninstall endpoint: POST /api/extensions/uninstall")
    print(f"  Health check: GET /health")
    print(f"  Debug mode: {debug}")
    print("\nServer is ready. Frontend requests will be accepted.")
    print("=" * 60 + "\n")
    
    # Start Flask development server
    app.run(host="0.0.0.0", port=port, debug=debug)
