"""Skill runner — discovers and runs Skill Packages on behalf of agents.

Replaces the old `@skill`-decorated Python function registry
(`skills/registry.py`, retired) with three generic, spec-faithful tools —
`list_skills`, `read_skill`, `run_skill_script` — sourced from real
filesystem-backed Skill Package directories (agentskills.io spec). This
mirrors how Claude Code itself runs skills: an agent sees name+description
cheaply, reads full instructions when relevant, and may run bundled scripts,
deciding for itself what to do — not a single fixed-schema RPC per skill.

Skills are discovered from two roots, merged: HOST_SKILLS_DIR (shipped with
the product, e.g. the recon skills) and SKILLS_DIR (~/.iac/skills/,
user-installed). On a name collision, host wins.

Fail-closed scoping: a caller only ever sees/runs skills within its `scope`.
`scope` is either a phase tag (`str`, e.g. "recon" — skills tagged
`metadata.phase == scope`, used by the fixed-phase engagement agents in
`agents/`) or an explicit allowlist of skill names (`List[str]`, used by
Project runs, where a user picks specific skills rather than inheriting a
phase's whole set). Either way this is a real security boundary — a
compromised prompt can't reach for a skill outside what it was given.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel

from iac_paths import HOST_SKILLS_DIR, SKILLS_DIR
from models.skill_package import SkillPackageManifest
from skill_packages.installer import SkillInstallError, _parse_skill_md_frontmatter

logger = logging.getLogger(__name__)

RUN_SCRIPT_TIMEOUT_SECONDS = 30  # backstop — well-behaved scripts have their own shorter internal timeouts

SkillScope = Union[str, List[str]]  # str = phase tag; List[str] = explicit skill-name allowlist


class DiscoveredSkill(BaseModel):
    name: str
    description: str
    source: str  # "host" | "user"
    install_path: str
    manifest: SkillPackageManifest


class SkillRunnerError(ValueError):
    """Any discovery/scope/path-safety failure. Callers (base_agent.py)
    surface this as a tool_result error, not an exception that halts the run."""


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #

def _scan_root(root: Path, source: str) -> Dict[str, DiscoveredSkill]:
    found: Dict[str, DiscoveredSkill] = {}
    if not root.is_dir():
        return found
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        skill_md = entry / "SKILL.md"
        if not skill_md.is_file():
            continue
        try:
            manifest = _parse_skill_md_frontmatter(skill_md)
        except SkillInstallError:
            continue
        found[manifest.name] = DiscoveredSkill(
            name=manifest.name,
            description=manifest.description,
            source=source,
            install_path=str(entry),
            manifest=manifest,
        )
    return found


def _discover_all() -> Dict[str, DiscoveredSkill]:
    """All discoverable skills, host+user merged (host wins on collision) —
    unfiltered by scope."""
    host = _scan_root(HOST_SKILLS_DIR, "host")
    user = _scan_root(SKILLS_DIR, "user")

    merged: Dict[str, DiscoveredSkill] = dict(host)
    for name, skill in user.items():
        if name in merged:
            logger.warning(
                "User-installed skill %r shadowed by a host skill of the same name; ignoring user copy.", name
            )
            continue
        merged[name] = skill
    return merged


def discover_skills(scope: SkillScope) -> List[DiscoveredSkill]:
    """Discover Skill Packages within `scope` — either every skill tagged
    `metadata.phase == scope` (str) or every skill whose name is in `scope`
    (List[str])."""
    merged = _discover_all()
    if isinstance(scope, str):
        return [s for s in merged.values() if (s.manifest.metadata or {}).get("phase") == scope]
    return [s for name, s in merged.items() if name in set(scope)]


def _resolve_in_scope(scope: SkillScope, name: str) -> DiscoveredSkill:
    scoped = {s.name: s for s in discover_skills(scope)}
    if name not in scoped:
        raise SkillRunnerError(f"Skill {name!r} is not available in this scope.")
    return scoped[name]


# --------------------------------------------------------------------------- #
# Tool schemas exposed to Claude
# --------------------------------------------------------------------------- #

SKILL_RUNNER_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "list_skills",
        "description": "List the skills currently available to you by name and one-line description.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "read_skill",
        "description": "Read the full instructions (SKILL.md body) for a named skill from list_skills, before using it.",
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Skill name as returned by list_skills"}},
            "required": ["name"],
        },
    },
    {
        "name": "run_skill_script",
        "description": "Execute a script bundled with a skill (see the skill's SKILL.md) and return its stdout, stderr, and exit code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Skill name"},
                "script": {
                    "type": "string",
                    "description": "Script path relative to the skill's own directory, e.g. 'scripts/dns_lookup.py'",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Command-line arguments to pass to the script",
                },
            },
            "required": ["name", "script"],
        },
    },
]


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #

def list_skills(scope: SkillScope) -> List[Dict[str, str]]:
    return [{"name": s.name, "description": s.description} for s in discover_skills(scope)]


def read_skill(scope: SkillScope, name: str) -> str:
    skill = _resolve_in_scope(scope, name)
    skill_md = Path(skill.install_path) / "SKILL.md"
    text = skill_md.read_text(encoding="utf-8")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise SkillRunnerError(f"Skill {name!r}'s SKILL.md is not properly delimited.")
    return parts[2].lstrip("\n")


async def run_skill(scope: SkillScope, name: str, script: str, args: Optional[List[str]] = None) -> Dict[str, Any]:
    skill = _resolve_in_scope(scope, name)
    skill_dir = Path(skill.install_path).resolve()

    # Reject absolute paths / drive letters outright, before ever resolving —
    # same defense-in-depth check installer.py's zip-slip protection uses.
    if script.startswith("/") or script.startswith("\\") or (len(script) > 1 and script[1] == ":"):
        raise SkillRunnerError(f"Rejected unsafe script path (absolute): {script!r}")

    target = (skill_dir / script).resolve()
    if target != skill_dir and not target.is_relative_to(skill_dir):
        raise SkillRunnerError(f"Rejected unsafe script path (path traversal): {script!r}")
    if not target.is_file():
        raise SkillRunnerError(f"Script not found: {script!r} in skill {name!r}")

    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(target), *(args or []),
        cwd=str(skill_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=RUN_SCRIPT_TIMEOUT_SECONDS)
        timed_out = False
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        stdout, stderr, timed_out = b"", b"", True

    return {
        "exit_code": proc.returncode,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
        "timed_out": timed_out,
    }
