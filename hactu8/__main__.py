import sys

# Checked before anything else is imported, so an older Python gets a clear message
# instead of a syntax error from newer code. Keep in step with requires-python in
# pyproject.toml (tests/test_python_version.py checks).
MIN_PYTHON = (3, 12)
if sys.version_info < MIN_PYTHON:
    sys.exit("HACTU8 needs Python %d.%d or later; this is Python %s."
             % (MIN_PYTHON + (sys.version.split()[0],)))

from hactu8.cli import main  # noqa: E402

raise SystemExit(main())
