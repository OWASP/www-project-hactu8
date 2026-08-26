"""Shared filesystem locations under the user's IAC home directory."""

import os
from pathlib import Path

IAC_HOME = Path(os.path.expanduser("~/.iac"))
SKILLS_DIR = IAC_HOME / "skills"

# Skill Packages shipped with the product itself (e.g. the recon skills) —
# repo-relative, read-only from the app's perspective, distinct from
# SKILLS_DIR (user-installed, ~/.iac/skills/).
HOST_SKILLS_DIR = Path(__file__).resolve().parent / "host_skills"
