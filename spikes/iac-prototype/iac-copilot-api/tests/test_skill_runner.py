"""Regression coverage for skill_packages/runner.py's SkillScope
generalization (Decision B): the existing phase-string scope used by the
fixed-phase engagement agents must behave exactly as before, and the new
name-list scope used by Project runs must work correctly and stay
fail-closed."""

import pytest

from skill_packages.runner import (
    SkillRunnerError,
    discover_skills,
    list_skills,
    read_skill,
)


def test_phase_string_scope_returns_recon_skills():
    names = {s.name for s in discover_skills("recon")}
    assert names == {"dns-lookup", "http-probe", "whois-lookup"}


def test_phase_string_scope_empty_for_unused_phase():
    assert discover_skills("exploitation") == []


def test_name_list_scope_returns_only_named_skills():
    names = {s.name for s in discover_skills(["dns-lookup", "whois-lookup"])}
    assert names == {"dns-lookup", "whois-lookup"}


def test_name_list_scope_ignores_names_not_present():
    names = {s.name for s in discover_skills(["dns-lookup", "not-a-real-skill"])}
    assert names == {"dns-lookup"}


def test_name_list_scope_is_fail_closed_for_unlisted_skill():
    # http-probe exists on disk, but isn't in this run's allowlist — must be
    # unreachable via read_skill, matching the phase boundary's behavior.
    with pytest.raises(SkillRunnerError):
        read_skill(["dns-lookup"], "http-probe")


def test_list_skills_shape_is_name_and_description_only():
    entries = list_skills(["dns-lookup"])
    assert entries == [{"name": "dns-lookup", "description": entries[0]["description"]}]
    assert entries[0]["description"]
