"""Shared filesystem locations under the user's IAC home directory."""

import os
from pathlib import Path

IAC_HOME = Path(os.path.expanduser("~/.iac"))
SKILLS_DIR = IAC_HOME / "skills"

# Skill Packages shipped with the product itself (e.g. the recon skills) —
# repo-relative, read-only from the app's perspective, distinct from
# SKILLS_DIR (user-installed, ~/.iac/skills/).
HOST_SKILLS_DIR = Path(__file__).resolve().parent / "host_skills"

# Curated ("canned") Projects — repo-relative, read-only, authored by the
# HACTU8 core team. Same "ships with the product" pattern as HOST_SKILLS_DIR.
CANNED_PROJECTS_DIR = Path(__file__).resolve().parent / "canned_projects"

# Persisted state for Project runs (a user's conversation + tool-call history
# against a curated Project) — mirrors ENGAGEMENTS_DIR's shape.
PROJECT_RUNS_DIR = IAC_HOME / "project-runs"
