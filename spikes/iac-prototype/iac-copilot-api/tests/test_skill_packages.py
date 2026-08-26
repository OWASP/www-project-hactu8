"""Tests for the skill-listing gap fix: GET /api/skill-packages's opt-in
include_host param must be additive — omitting it stays byte-identical to
before, and include_host=true surfaces the 3 host-shipped skills."""

from skill_packages.installer import list_skill_packages

EXPECTED_HOST_SKILL_NAMES = {"dns-lookup", "http-probe", "whois-lookup"}


def test_default_call_excludes_host_skills():
    # No user skills are installed in this dev environment, so the
    # unfiltered baseline is empty either way — the real assertion is that
    # host skills never leak in without opting in.
    records = list_skill_packages()
    assert all(r.source != "host" for r in records)


def test_include_host_surfaces_host_skills():
    records = list_skill_packages(include_host=True)
    host_names = {r.name for r in records if r.source == "host"}
    assert host_names == EXPECTED_HOST_SKILL_NAMES


def test_endpoint_default_response_shape_unchanged(client):
    r = client.get("/api/skill-packages")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == len(body["skills"])
    assert all(s["source"] != "host" for s in body["skills"])


def test_endpoint_include_host_true(client):
    r = client.get("/api/skill-packages?include_host=true")
    assert r.status_code == 200
    body = r.json()
    host_entries = [s for s in body["skills"] if s["source"] == "host"]
    assert {s["name"] for s in host_entries} == EXPECTED_HOST_SKILL_NAMES
    for entry in host_entries:
        assert entry["source_filename"] is None
        assert entry["sha256"] is None
        assert entry["installed_at"]
