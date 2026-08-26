"""Project run tests: create/status round trip against real disk
persistence, the full tool-use loop exercised with one real (harmless) DNS
lookup via a mocked LLM call boundary, and the no-API-key path as an
end-to-end smoke test through the whole SSE pipe."""

import json

from services.llm_dispatch import LLMResponse, ToolCall
from unittest.mock import patch

CREATE_BODY = {
    "target": {"name": "AgenticGoat Internal", "target_url": None},
    "skill_names": ["dns-lookup", "http-probe"],
    "model": {"provider_id": "anthropic", "model_id": "claude-3.5-sonnet"},
}


def _create_run(client, cleanup_project_runs, project_id="test-prompt-injection", body=None):
    r = client.post(f"/api/projects/{project_id}/runs", json=body or CREATE_BODY)
    assert r.status_code == 201
    run_id = r.json()["run_id"]
    cleanup_project_runs.append(run_id)
    return run_id


def test_create_run_for_missing_project_404(client, cleanup_project_runs):
    r = client.post("/api/projects/does-not-exist/runs", json=CREATE_BODY)
    assert r.status_code == 404


def test_create_get_status_round_trip(client, cleanup_project_runs):
    run_id = _create_run(client, cleanup_project_runs)

    r = client.get(f"/api/project-runs/{run_id}")
    assert r.status_code == 200
    state = r.json()
    assert state["status"] == "idle"
    assert state["scope"]["project_id"] == "test-prompt-injection"
    assert state["scope"]["skill_names"] == ["dns-lookup", "http-probe"]
    assert state["turns"] == []

    r = client.get(f"/api/project-runs/{run_id}/status")
    assert r.status_code == 200
    assert r.json()["turn_count"] == 0


def test_get_run_missing_404(client):
    r = client.get("/api/project-runs/not-a-real-run-id")
    assert r.status_code == 404


def _parse_sse_events(raw_text):
    events = []
    for block in raw_text.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        assert block.startswith("data: ")
        events.append(json.loads(block[len("data: "):]))
    return events


def test_no_api_key_surfaces_clean_error_end_to_end(client, cleanup_project_runs, monkeypatch):
    """The single cheapest full-path check available: no real Anthropic key
    is configured in this environment, so a message send should fail
    cleanly through routing -> engine -> SSE transport -> persistence,
    without ever making a network call."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    run_id = _create_run(client, cleanup_project_runs)

    r = client.post(f"/api/project-runs/{run_id}/messages", json={"content": "start the assessment"})
    assert r.status_code == 200
    events = _parse_sse_events(r.text)

    assert events[-1]["type"] == "error"
    assert "api key" in events[-1]["message"].lower()

    status = client.get(f"/api/project-runs/{run_id}/status").json()
    assert status["status"] == "failed"
    assert status["error"]


def test_message_send_while_running_returns_409(client, cleanup_project_runs):
    run_id = _create_run(client, cleanup_project_runs)

    from project_runs.router import _load_state, _save_state
    from project_runs.models import ProjectRunStatus

    state = _load_state(run_id)
    state.status = ProjectRunStatus.RUNNING
    _save_state(state)

    r = client.post(f"/api/project-runs/{run_id}/messages", json={"content": "hello"})
    assert r.status_code == 409


def test_full_tool_loop_with_real_dns_lookup(client, cleanup_project_runs):
    """Mocks only the LLM call boundary (services.llm_dispatch.call_model) —
    everything downstream of that, including the actual tool dispatch and
    one real DNS query via the dns-lookup skill's bundled script, runs for
    real."""
    run_id = _create_run(
        client,
        cleanup_project_runs,
        body={
            "target": {"name": "example.com", "target_url": "https://example.com"},
            "skill_names": ["dns-lookup"],
            "model": {"provider_id": "anthropic", "model_id": "claude-3.5-sonnet", "api_key": "sk-ant-fake"},
        },
    )

    call_count = {"n": 0}

    async def fake_call_model(messages, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return LLMResponse(
                text_blocks=["Looking up DNS records for example.com."],
                tool_calls=[
                    ToolCall(
                        id="tc1",
                        name="run_skill_script",
                        input={"name": "dns-lookup", "script": "scripts/dns_lookup.py", "args": ["example.com"]},
                    )
                ],
                stop_reason="tool_use",
            )
        return LLMResponse(
            text_blocks=["DNS lookup complete."],
            tool_calls=[],
            stop_reason="end_turn",
        )

    with patch("project_runs.engine.call_model", side_effect=fake_call_model):
        r = client.post(f"/api/project-runs/{run_id}/messages", json={"content": "start"})

    assert r.status_code == 200
    events = _parse_sse_events(r.text)
    event_types = [e["type"] for e in events]
    assert "tool_call" in event_types
    assert "tool_result" in event_types
    assert event_types[-1] == "complete"

    tool_result_event = next(e for e in events if e["type"] == "tool_result")
    assert tool_result_event["result"]["exit_code"] == 0
    assert not tool_result_event["result"]["timed_out"]

    complete_event = events[-1]
    assert complete_event["findings"], "a successful run_skill_script call should record a finding"

    final_state = client.get(f"/api/project-runs/{run_id}").json()
    assert final_state["status"] == "awaiting_input"
    assert len(final_state["turns"]) == 2
    assert final_state["findings"]
