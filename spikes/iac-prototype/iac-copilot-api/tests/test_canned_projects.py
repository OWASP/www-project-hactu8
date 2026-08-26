"""Direct-Python tests for canned_projects/loader.py against the 10 real
authored directories, plus HTTP-layer tests for the router."""

import json

from canned_projects.loader import get_canned_project, list_canned_projects
from iac_paths import CANNED_PROJECTS_DIR

EXPECTED_IDS = {
    "test-prompt-injection",
    "test-training-leak",
    "test-misbehavior-monitor",
    "test-overreliance-risk",
    "test-agency-validator",
    "test-insecure-output",
    "test-supply-chain",
    "test-model-identity",
    "test-auth-context-audit",
    "test-privacy-compliance",
}


def test_lists_all_ten_authored_projects():
    projects = list_canned_projects()
    assert {p.id for p in projects} == EXPECTED_IDS


def test_summary_has_no_prose_fields():
    projects = list_canned_projects()
    for p in projects:
        assert not hasattr(p, "overview_md")
        assert not hasattr(p, "instructions_md")


def test_detail_includes_prose_and_matches_summary_fields():
    detail = get_canned_project("test-prompt-injection")
    assert detail is not None
    assert detail.name == "Prompt Injection Tester"
    assert detail.category == "Prompt Security"
    assert detail.legacy_route == "/prompt-injection"
    assert detail.default_skill_names == ["http-probe"]
    assert "Prompt Injection Tester" in detail.overview_md
    assert len(detail.instructions_md) > 0


def test_missing_project_returns_none():
    assert get_canned_project("does-not-exist") is None


def test_malformed_entry_is_skipped_not_crashed(tmp_path, monkeypatch):
    # A directory whose project.json id doesn't match the directory name
    # should be skipped (logged, not raised) — mirrors
    # skill_packages/installer.py's _validate_manifest posture.
    bad_dir = CANNED_PROJECTS_DIR / "test-prompt-injection-tmp-bad"
    bad_dir.mkdir(exist_ok=True)
    try:
        (bad_dir / "project.json").write_text(
            json.dumps({
                "id": "mismatched-id",
                "name": "Bad Project",
                "category": "X",
                "summary": "Y",
            }),
            encoding="utf-8",
        )
        (bad_dir / "overview.md").write_text("", encoding="utf-8")
        (bad_dir / "instructions.md").write_text("", encoding="utf-8")

        projects = list_canned_projects()
        assert "mismatched-id" not in {p.id for p in projects}
        assert get_canned_project("test-prompt-injection-tmp-bad") is None
    finally:
        import shutil
        shutil.rmtree(bad_dir, ignore_errors=True)


def test_get_projects_endpoint(client):
    r = client.get("/api/canned-projects")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 10
    assert {p["id"] for p in body["projects"]} == EXPECTED_IDS


def test_get_project_detail_endpoint(client):
    r = client.get("/api/canned-projects/test-supply-chain")
    assert r.status_code == 200
    assert r.json()["name"] == "Supply Chain Trust Checker"


def test_get_project_detail_endpoint_404(client):
    r = client.get("/api/canned-projects/does-not-exist")
    assert r.status_code == 404
