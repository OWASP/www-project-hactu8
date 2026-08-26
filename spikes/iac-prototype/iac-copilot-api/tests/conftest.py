"""Shared pytest fixtures. Run from iac-copilot-api/ (or with PYTHONPATH=.)."""

import shutil

import pytest
from fastapi.testclient import TestClient

from app import app
from iac_paths import PROJECT_RUNS_DIR


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def cleanup_project_runs():
    """Project runs persist to the real ~/.iac/project-runs/ (no env-var
    override exists for IAC_HOME). Tests that create runs register the
    run_id here so its directory is removed afterwards, keeping the local
    .iac/ state clean of test artifacts."""
    created_run_ids = []
    yield created_run_ids
    for run_id in created_run_ids:
        shutil.rmtree(PROJECT_RUNS_DIR / run_id, ignore_errors=True)
