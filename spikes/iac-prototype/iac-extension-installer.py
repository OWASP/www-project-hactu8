"""
Extension Installer API Handler

This module provides the backend API for downloading, verifying, and extracting
extension zip files to ~/.iac directory.

Use this in your Flask/FastAPI app:

    from iac_extension_installer import setup_extension_routes
    setup_extension_routes(app)
"""

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Optional
from urllib.request import urlopen
from urllib.error import URLError


class ExtensionInstaller:
    """Handles downloading, verifying, and extracting extensions."""

    def __init__(self, base_path: str = "~/.iac"):
        self.base_path = Path(base_path).expanduser()
        self.base_path.mkdir(parents=True, exist_ok=True)

    def calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def download_zip(self, zip_url: str) -> Path:
        """Download zip file from URL to temporary location."""
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".zip", delete=False
            ) as tmp_file:
                with urlopen(zip_url) as response:
                    tmp_file.write(response.read())
                return Path(tmp_file.name)
        except URLError as e:
            raise RuntimeError(f"Failed to download zip from {zip_url}: {e}")

    def verify_sha256(self, file_path: Path, expected_sha256: str) -> bool:
        """Verify that file matches expected SHA256 hash."""
        calculated = self.calculate_sha256(file_path)
        if calculated.lower() != expected_sha256.lower():
            raise ValueError(
                f"SHA256 mismatch: expected {expected_sha256}, got {calculated}"
            )
        return True

    def extract_zip(self, zip_path: Path, extract_to: Path) -> None:
        """Extract zip file to target directory."""
        extract_to.parent.mkdir(parents=True, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)

    def write_config(self, install_path: Path, config: dict) -> None:
        """Write config.json to extension directory."""
        config_path = Path(install_path) / "config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

    def install(
        self,
        extension_id: str,
        zip_url: str,
        sha256: str,
        install_path: Optional[str] = None,
        host_config: Optional[dict] = None,
    ) -> dict:
        """
        Download, verify, and extract an extension.

        Args:
            extension_id: Extension ID (for error messages)
            zip_url: URL to the extension zip file
            sha256: Expected SHA256 hash of the zip file
            install_path: Where to extract (e.g., "~/.iac/extensions/my-ext")
            host_config: Optional config to write as config.json

        Returns:
            {"success": True, "installPath": "/home/user/.iac/extensions/my-ext"}

        Raises:
            RuntimeError: If download or extraction fails
            ValueError: If SHA256 verification fails
        """
        resolved_install_path = Path(install_path or f"{self.base_path}/extensions/{extension_id}").expanduser()
        
        # Step 1: Download zip
        print(f"[{extension_id}] Downloading from {zip_url}...")
        zip_path = self.download_zip(zip_url)

        try:
            # Step 2: Verify SHA256
            print(f"[{extension_id}] Verifying SHA256...")
            self.verify_sha256(zip_path, sha256)

            # Step 3: Extract
            print(f"[{extension_id}] Extracting to {resolved_install_path}...")
            self.extract_zip(zip_path, resolved_install_path)

            # Step 4: Write config.json if provided
            if host_config:
                print(f"[{extension_id}] Writing config.json...")
                self.write_config(resolved_install_path, host_config)

            print(f"[{extension_id}] Installation complete!")
            return {
                "success": True,
                "installPath": str(resolved_install_path),
                "extensionId": extension_id,
            }
        finally:
            # Clean up temp zip file
            zip_path.unlink(missing_ok=True)


# ===== Flask Integration Example =====

def setup_extension_routes(app):
    """Set up Flask routes for extension installation."""
    
    installer = ExtensionInstaller()

    @app.route("/api/extensions/install", methods=["POST"])
    def install_extension():
        """
        POST /api/extensions/install
        
        Body: {
            "extensionId": "my-ext",
            "zipUrl": "https://example.com/ext.zip",
            "sha256": "abc123...",
            "installPath": "~/.iac/extensions",
            "hostConfig": { ... }  # optional
        }
        """
        try:
            data = request.get_json()
            
            extension_id = data.get("extensionId")
            zip_url = data.get("zipUrl")
            sha256 = data.get("sha256")
            install_path = data.get("installPath")
            host_config = data.get("hostConfig")
            
            if not all([extension_id, zip_url, sha256]):
                return (
                    {"error": "Missing required fields: extensionId, zipUrl, sha256"},
                    400,
                )
            
            result = installer.install(
                extension_id=extension_id,
                zip_url=zip_url,
                sha256=sha256,
                install_path=install_path,
                host_config=host_config,
            )
            
            return result, 200
            
        except ValueError as e:
            return {"error": f"Verification failed: {str(e)}"}, 400
        except RuntimeError as e:
            return {"error": f"Installation failed: {str(e)}"}, 500
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}, 500

    return app


# ===== FastAPI Integration Example =====

def setup_extension_routes_fastapi(app):
    """Set up FastAPI routes for extension installation."""
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
    
    installer = ExtensionInstaller()
    
    class InstallRequest(BaseModel):
        extensionId: str
        zipUrl: str
        sha256: str
        installPath: Optional[str] = None
        hostConfig: Optional[dict] = None
    
    @app.post("/api/extensions/install")
    async def install_extension(req: InstallRequest):
        """Install an extension from a remote zip URL."""
        try:
            result = installer.install(
                extension_id=req.extensionId,
                zip_url=req.zipUrl,
                sha256=req.sha256,
                install_path=req.installPath,
                host_config=req.hostConfig,
            )
            return result
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")
        except RuntimeError as e:
            raise HTTPException(status_code=500, detail=f"Installation failed: {str(e)}")

    return app


# ===== Direct CLI Usage Example =====

if __name__ == "__main__":
    # Example: Download and install an extension directly
    installer = ExtensionInstaller(base_path="~/.iac")
    
    result = installer.install(
        extension_id="my-extension",
        zip_url="https://example.com/extensions/my-ext.zip",
        sha256="abc123def456...",
        install_path="~/.iac/extensions/my-extension",
        host_config={
            "hostVersion": "0.1.0",
            "extensionId": "my-extension",
            "port": 8501,
            "resultsDir": "~/.iac/results/my-extension",
            "settings": {},
        },
    )
    
    print(json.dumps(result, indent=2))
