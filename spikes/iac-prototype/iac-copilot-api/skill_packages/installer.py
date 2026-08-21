"""Install/discovery logic for Skill Packages — real, filesystem-backed skill
directories conforming to the agentskills.io Agent Skills specification.

Pure logic only: no FastAPI imports here. `router.py` is the HTTP layer and
translates the exceptions below into HTTP responses.

Skills are stored on disk at ``~/.iac/skills/<name>/`` (see `iac_paths.py`).
Disk is the source of truth — `list_skill_packages()` scans it directly
rather than trusting a separate index that could drift out of sync.
"""

import hashlib
import shutil
import stat
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

import yaml

from iac_paths import SKILLS_DIR
from models.skill_package import InstalledSkillPackage, SkillPackageManifest

MAX_ZIP_BYTES = 10 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_ENTRY_COUNT = 500

_SIDECAR_META_FILENAME = ".iac-meta.json"
_NAME_PATTERN_MSG = (
    "must be 1-64 lowercase alphanumeric characters and hyphens, "
    "no leading/trailing/consecutive hyphens"
)


class SkillInstallError(ValueError):
    """Any validation, zip-slip, or zip-bomb failure. Router maps this to
    HTTP 400."""


class SkillPackageAlreadyInstalled(ValueError):
    """Router maps this to HTTP 409."""

    def __init__(self, name: str):
        super().__init__(f"Skill package {name!r} is already installed")
        self.name = name


class SkillPackageNotFound(ValueError):
    """Router maps this to HTTP 404."""

    def __init__(self, name: str):
        super().__init__(f"Skill package {name!r} not found")
        self.name = name


# --------------------------------------------------------------------------- #
# Zip-slip-safe extraction — fail closed, two-pass: validate every entry
# before writing any bytes.
# --------------------------------------------------------------------------- #

def _validate_and_plan_extraction(
    zf: zipfile.ZipFile, dest_dir: Path
) -> List[Tuple[zipfile.ZipInfo, Path]]:
    dest_dir = dest_dir.resolve()
    infos = zf.infolist()
    if len(infos) > MAX_ENTRY_COUNT:
        raise SkillInstallError(f"Zip has too many entries ({len(infos)} > {MAX_ENTRY_COUNT})")

    total_uncompressed = 0
    plan: List[Tuple[zipfile.ZipInfo, Path]] = []
    for info in infos:
        name = info.filename

        if name.startswith("/") or name.startswith("\\") or (len(name) > 1 and name[1] == ":"):
            raise SkillInstallError(f"Rejected unsafe zip entry (absolute path): {name!r}")

        # Symlinks must be rejected explicitly — a safe-looking *name* can
        # still carry a symlink that resolves outside dest_dir at read time,
        # which pure ".." path-string checks do not catch.
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise SkillInstallError(f"Rejected unsafe zip entry (symlink): {name!r}")

        target = (dest_dir / name).resolve()
        if target != dest_dir and not target.is_relative_to(dest_dir):
            raise SkillInstallError(f"Rejected unsafe zip entry (path traversal): {name!r}")

        total_uncompressed += info.file_size
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise SkillInstallError("Zip exceeds maximum uncompressed size")

        plan.append((info, target))
    return plan


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        plan = _validate_and_plan_extraction(zf, dest_dir)  # nothing written until the whole archive passes
        for info, target in plan:
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)


# --------------------------------------------------------------------------- #
# SKILL.md frontmatter parsing + validation
# --------------------------------------------------------------------------- #

def _parse_skill_md_frontmatter(skill_md: Path) -> SkillPackageManifest:
    text = skill_md.read_text(encoding="utf-8")
    if not text.startswith("---"):
        raise SkillInstallError("SKILL.md must start with YAML frontmatter delimited by '---'")

    parts = text.split("---", 2)
    if len(parts) < 3:
        raise SkillInstallError("SKILL.md frontmatter is not properly delimited by '---' ... '---'")

    try:
        raw = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as exc:
        raise SkillInstallError(f"SKILL.md frontmatter is not valid YAML: {exc}")

    if not isinstance(raw, dict):
        raise SkillInstallError("SKILL.md frontmatter must be a YAML mapping")

    # Spec uses "allowed-tools"; our model field is allowed_tools.
    if "allowed-tools" in raw and "allowed_tools" not in raw:
        raw["allowed_tools"] = raw.pop("allowed-tools")

    try:
        return SkillPackageManifest(**raw)
    except Exception as exc:
        raise SkillInstallError(f"SKILL.md frontmatter failed validation: {exc}")


def _validate_manifest(manifest: SkillPackageManifest, dir_name: str) -> None:
    if not manifest.name:
        raise SkillInstallError("SKILL.md frontmatter is missing required field 'name'")
    if manifest.name != dir_name:
        raise SkillInstallError(
            f"SKILL.md 'name' ({manifest.name!r}) must match the directory name ({dir_name!r})"
        )
    if len(manifest.name) > 64 or not _is_valid_skill_name(manifest.name):
        raise SkillInstallError(f"Invalid skill name {manifest.name!r}: {_NAME_PATTERN_MSG}")
    if not manifest.description or not manifest.description.strip():
        raise SkillInstallError("SKILL.md frontmatter is missing required field 'description'")
    if len(manifest.description) > 1024:
        raise SkillInstallError("SKILL.md 'description' exceeds 1024 characters")


def _is_valid_skill_name(name: str) -> bool:
    if not name or "--" in name or name.startswith("-") or name.endswith("-"):
        return False
    return all(c.islower() or c.isdigit() or c == "-" for c in name)


# --------------------------------------------------------------------------- #
# Install
# --------------------------------------------------------------------------- #

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_sidecar_meta(skill_dir: Path, installed_at: datetime, source_filename: str, sha256: str) -> None:
    meta = {
        "installedAt": installed_at.isoformat(),
        "source": "upload",
        "sourceFilename": source_filename,
        "sha256": sha256,
    }
    import json
    (skill_dir / _SIDECAR_META_FILENAME).write_text(json.dumps(meta, indent=2), encoding="utf-8")


def _read_sidecar_meta(skill_dir: Path) -> dict:
    meta_path = skill_dir / _SIDECAR_META_FILENAME
    if not meta_path.is_file():
        return {}
    import json
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _collect_files(skill_dir: Path) -> List[str]:
    """Relative paths of everything under the skill dir except SKILL.md and
    the sidecar meta file — i.e. scripts/, references/, assets/ contents."""
    excluded = {"SKILL.md", _SIDECAR_META_FILENAME}
    files: List[str] = []
    for path in sorted(skill_dir.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(skill_dir)
        if str(rel) in excluded:
            continue
        files.append(str(rel))
    return files


def _to_installed_record(
    skill_dir: Path, manifest: SkillPackageManifest, installed_at: datetime, source_filename: str, sha256: str
) -> InstalledSkillPackage:
    return InstalledSkillPackage(
        name=manifest.name,
        install_path=str(skill_dir),
        installed_at=installed_at,
        source="upload",
        source_filename=source_filename,
        sha256=sha256,
        manifest=manifest,
        files=_collect_files(skill_dir),
    )


def install_skill_package(zip_path: Path, *, source_filename: str, overwrite: bool = False) -> InstalledSkillPackage:
    """Extract, validate, and install a `.skill` (zip) archive.

    The zip's top-level directory name isn't known until after extraction
    (spec: archive root contains `skill-name/`), so extraction happens into
    an isolated staging directory first — only a fully-validated result is
    moved into the real ~/.iac/skills/ tree, so a bad upload never leaves
    partial/invalid state next to good installs.
    """
    with tempfile.TemporaryDirectory(prefix="iac-skill-staging-") as staging_raw:
        staging = Path(staging_raw)
        safe_extract_zip(zip_path, staging)

        top_level = [p for p in staging.iterdir() if not p.name.startswith(".")]
        if len(top_level) != 1 or not top_level[0].is_dir():
            raise SkillInstallError(
                "Archive must contain exactly one top-level directory (skill-name/SKILL.md ...), "
                "per the agentskills.io spec"
            )
        skill_dir = top_level[0]
        dir_name = skill_dir.name

        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            raise SkillInstallError(f"{dir_name}/SKILL.md not found")

        manifest = _parse_skill_md_frontmatter(skill_md)
        _validate_manifest(manifest, dir_name)

        dest = SKILLS_DIR / dir_name
        if dest.exists():
            if not overwrite:
                raise SkillPackageAlreadyInstalled(dir_name)
            shutil.rmtree(dest)

        installed_at = datetime.utcnow()
        sha256 = _sha256_file(zip_path)
        _write_sidecar_meta(skill_dir, installed_at, source_filename, sha256)

        SKILLS_DIR.mkdir(parents=True, exist_ok=True)
        shutil.move(str(skill_dir), str(dest))

        return _to_installed_record(dest, manifest, installed_at, source_filename, sha256)


# --------------------------------------------------------------------------- #
# List / uninstall
# --------------------------------------------------------------------------- #

def list_skill_packages() -> List[InstalledSkillPackage]:
    if not SKILLS_DIR.is_dir():
        return []

    records: List[InstalledSkillPackage] = []
    for entry in sorted(SKILLS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        skill_md = entry / "SKILL.md"
        if not skill_md.is_file():
            continue
        try:
            manifest = _parse_skill_md_frontmatter(skill_md)
        except SkillInstallError:
            continue

        meta = _read_sidecar_meta(entry)
        installed_at = meta.get("installedAt")
        try:
            installed_at_dt = datetime.fromisoformat(installed_at) if installed_at else datetime.utcnow()
        except ValueError:
            installed_at_dt = datetime.utcnow()

        records.append(
            InstalledSkillPackage(
                name=manifest.name,
                install_path=str(entry),
                installed_at=installed_at_dt,
                source="upload",
                source_filename=meta.get("sourceFilename"),
                sha256=meta.get("sha256"),
                manifest=manifest,
                files=_collect_files(entry),
            )
        )
    return records


def uninstall_skill_package(name: str) -> None:
    if name != Path(name).name or name in (".", "..") or not name:
        raise SkillInstallError(f"Invalid skill name: {name!r}")
    target = (SKILLS_DIR / name).resolve()
    if target.parent != SKILLS_DIR.resolve():
        raise SkillInstallError(f"Refusing to remove path outside skills directory: {name!r}")
    if not target.is_dir():
        raise SkillPackageNotFound(name)
    shutil.rmtree(target)
