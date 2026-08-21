"""Shared filesystem locations under the user's IAC home directory."""

import os
from pathlib import Path

IAC_HOME = Path(os.path.expanduser("~/.iac"))
SKILLS_DIR = IAC_HOME / "skills"
