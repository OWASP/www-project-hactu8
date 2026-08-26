"""BaseAgent — Claude tool_use loop for IAC engagement agents."""

import asyncio
import json
import os
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx

from agents.models import AgentResult, PhaseEnum
from skill_packages.runner import (
    SKILL_RUNNER_TOOLS,
    SkillRunnerError,
    discover_phase_skills,
    list_skills_in_scope,
    read_skill_body,
    run_skill_script,
)

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-4-5"
MAX_TOKENS = 4096
MAX_TOOL_ITERATIONS = 25  # recon agents may probe several endpoints; 10 was too low

# Prior context from completed phases is truncated to keep the input payload
# within a safe size.  The full findings are stored on disk — this is just the
# summary handed to the next agent for context continuity.
MAX_PRIOR_CONTEXT_CHARS = 12_000  # ~3 K tokens


class BaseAgent:
    """
    LLM agent that drives a single engagement phase using Claude's tool_use API.

    Emits a stream of SSE-compatible dict events:
      {"type": "text",         "content": "..."}
      {"type": "tool_call",    "name": "...", "input": {...}}
      {"type": "tool_result",  "name": "...", "result": {...}}
      {"type": "complete",     "result": AgentResult}
      {"type": "error",        "message": "..."}
    """

    phase: PhaseEnum
    agent_name: str
    system_prompt: str
    skill_categories: List[str]

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")

    def _build_initial_message(self, scope_summary: str, prior_context: str) -> str:
        parts = [f"Target: {scope_summary}"]
        if prior_context:
            # Truncate to avoid overwhelming the context window with prior phase output
            if len(prior_context) > MAX_PRIOR_CONTEXT_CHARS:
                prior_context = (
                    prior_context[:MAX_PRIOR_CONTEXT_CHARS]
                    + f"\n\n[... prior context truncated at {MAX_PRIOR_CONTEXT_CHARS} chars ...]"
                )
            parts.append(f"Prior findings:\n{prior_context}")
        parts.append("Begin your analysis now.")
        return "\n\n".join(parts)

    async def run(
        self,
        scope_summary: str,
        prior_context: str = "",
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Drive the tool_use loop and yield event dicts.
        Callers should collect events and extract the final 'complete' event for AgentResult.
        """
        if not self._api_key:
            yield {"type": "error", "message": "ANTHROPIC_API_KEY is not configured"}
            return

        # skill_categories is used as a single phase tag (e.g. "recon") to
        # scope which Skill Packages this agent can see/run — a real
        # server-side boundary, not just a prompt instruction. Agents with
        # no phase (KickOffAgent, RiskAssessmentAgent) stay tool-free.
        phase_tag = self.skill_categories[0] if self.skill_categories else None
        tools = SKILL_RUNNER_TOOLS if phase_tag else []

        effective_system_prompt = self.system_prompt
        if phase_tag:
            discovered = await asyncio.to_thread(discover_phase_skills, phase_tag)
            if discovered:
                sections = "\n\n".join(
                    f"## Skill: {s.name}\n\n{read_skill_body(phase_tag, s.name)}" for s in discovered
                )
                effective_system_prompt = (
                    f"{self.system_prompt}\n\n"
                    f"# Available Skills\n\n"
                    f"The following skills are available to you now — their full instructions are "
                    f"included below so you don't need to call list_skills/read_skill for these. "
                    f"Use run_skill_script to execute them. If you need a skill not listed here, "
                    f"call list_skills to check for anything else installed.\n\n{sections}"
                )

        messages: List[Dict[str, Any]] = [
            {"role": "user", "content": self._build_initial_message(scope_summary, prior_context)}
        ]

        findings: List[Dict[str, Any]] = []
        tool_calls_log: List[Dict[str, Any]] = []

        for iteration in range(MAX_TOOL_ITERATIONS):
            response_data = await self._call_claude(messages, tools, effective_system_prompt)
            if response_data is None:
                yield {"type": "error", "message": "Empty response from Claude API"}
                return

            stop_reason = response_data.get("stop_reason", "end_turn")
            content_blocks = response_data.get("content", [])

            # Emit text blocks
            for block in content_blocks:
                if block.get("type") == "text":
                    yield {"type": "text", "content": block["text"]}

            if stop_reason == "end_turn":
                # Extract final summary from last text block
                text_blocks = [b["text"] for b in content_blocks if b.get("type") == "text"]
                summary = " ".join(text_blocks).strip() or f"{self.agent_name} completed."
                result = AgentResult(
                    phase=self.phase,
                    agent_name=self.agent_name,
                    summary=summary,
                    findings=findings,
                    tool_calls=tool_calls_log,
                    completed_at=datetime.utcnow(),
                )
                yield {"type": "complete", "result": result.model_dump(mode="json")}
                return

            if stop_reason != "tool_use":
                yield {"type": "error", "message": f"Unexpected stop_reason: {stop_reason}"}
                return

            # Process tool_use blocks
            tool_results: List[Dict[str, Any]] = []
            for block in content_blocks:
                if block.get("type") != "tool_use":
                    continue

                tool_name = block["name"]
                tool_input = block.get("input", {})
                tool_id = block["id"]

                yield {"type": "tool_call", "name": tool_name, "input": tool_input}

                # TODO: no approval/protection mechanism exists yet for Skill
                # Packages. Design one before adding any skill category that
                # needs gating (e.g. an eventual active-exploitation phase).
                try:
                    if tool_name == "list_skills":
                        result_content = list_skills_in_scope(phase_tag)
                    elif tool_name == "read_skill":
                        result_content = {"body": read_skill_body(phase_tag, tool_input.get("name", ""))}
                    elif tool_name == "run_skill_script":
                        result_content = await run_skill_script(
                            phase_tag,
                            tool_input.get("name", ""),
                            tool_input.get("script", ""),
                            tool_input.get("args"),
                        )
                    else:
                        result_content = {"success": False, "error": f"Unknown tool: {tool_name}"}
                except SkillRunnerError as exc:
                    result_content = {"success": False, "error": str(exc)}
                except Exception as exc:
                    result_content = {"success": False, "error": str(exc)}

                yield {"type": "tool_result", "name": tool_name, "result": result_content}

                tool_calls_log.append({"tool": tool_name, "input": tool_input, "result": result_content})
                # run_skill_script's result shape ({exit_code, stdout, stderr,
                # timed_out}) has no top-level "success" key — the runner
                # deliberately doesn't parse a script's stdout (see
                # skill_packages/runner.py), so a finding is recorded as the
                # raw stdout text whenever the script actually ran.
                if (
                    tool_name == "run_skill_script"
                    and isinstance(result_content, dict)
                    and result_content.get("exit_code") == 0
                    and not result_content.get("timed_out")
                ):
                    findings.append({"tool": tool_name, "data": result_content.get("stdout")})
                elif isinstance(result_content, dict) and result_content.get("success"):
                    findings.append({"tool": tool_name, "data": result_content.get("data")})

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": json.dumps(result_content),
                })

            # Append assistant turn + tool results turn
            messages.append({"role": "assistant", "content": content_blocks})
            messages.append({"role": "user", "content": tool_results})

        yield {"type": "error", "message": f"Exceeded max tool iterations ({MAX_TOOL_ITERATIONS})"}

    async def _call_claude(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        system_prompt: str,
    ) -> Optional[Dict[str, Any]]:
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        payload: Dict[str, Any] = {
            "model": DEFAULT_MODEL,
            "max_tokens": MAX_TOKENS,
            "system": system_prompt,
            "messages": messages,
        }
        if tools:
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(ANTHROPIC_API_URL, json=payload, headers=headers)
            if not response.is_success:
                # Surface the actual API error body, not just the HTTP status line
                try:
                    err_body = response.json()
                    err_detail = err_body.get("error", {}).get("message") or str(err_body)
                except Exception:
                    err_detail = response.text or f"HTTP {response.status_code}"
                raise ValueError(f"Claude API {response.status_code}: {err_detail}")
            return response.json()
