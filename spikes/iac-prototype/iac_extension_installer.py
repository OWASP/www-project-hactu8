"""
Extension Installer API Handler

This module provides the backend code for downloading, verifying, and extracting
extension zip files to ~/.iac directory, and for uninstalling extensions.
"""

import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path
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
        """Write host_config.json to extension directory."""
        config_path = Path(install_path) / "host_config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

    def install(
        self,
        extension_id: str,
        zip_url: str,
        sha256: str,
        install_path: str = None,
        host_config: dict = None,
    ) -> dict:
        """
        Download, verify, and extract an extension.

        Args:
            extension_id: Extension ID (for error messages)
            zip_url: URL to the extension zip file
            sha256: Expected SHA256 hash of the zip file
            install_path: Where to extract (e.g., "~/.iac/extensions/my-ext")
            host_config: Optional config to write as host_config.json

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

            # Step 4: Write host_config.json if provided
            if host_config:
                print(f"[{extension_id}] Writing host_config.json...")
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

    def uninstall(self, extension_id: str, install_path: str = None) -> dict:
        """
        Uninstall an extension by deleting its directory.

        Args:
            extension_id: Extension ID to uninstall
            install_path: Path to the extension (e.g., "~/.iac/extensions/my-ext")
                         If not provided, uses {base_path}/extensions/{extension_id}

        Returns:
            {"success": True, "extensionId": "my-ext", "deletedPath": "/home/user/.iac/extensions/my-ext"}

        Raises:
            RuntimeError: If deletion fails
            ValueError: If path doesn't exist
        """
        resolved_path = Path(install_path or f"{self.base_path}/extensions/{extension_id}").expanduser()

        if not resolved_path.exists():
            raise ValueError(f"Extension directory not found: {resolved_path}")

        try:
            print(f"[{extension_id}] Uninstalling (deleting {resolved_path})...")
            shutil.rmtree(resolved_path)
            print(f"[{extension_id}] Uninstallation complete!")
            return {
                "success": True,
                "extensionId": extension_id,
                "deletedPath": str(resolved_path),
            }
        except Exception as e:
            raise RuntimeError(f"Failed to uninstall extension {extension_id}: {e}")


if __name__ == "__main__":
    # Example usage
    installer = ExtensionInstaller()
    print("ExtensionInstaller ready")
