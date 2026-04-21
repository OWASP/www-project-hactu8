"""BaseAgent — Claude tool_use loop for IAC engagement agents."""

import json
import os
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx

from agents.models import AgentResult, ApprovalContext, PhaseEnum
from skills.registry import skill_registry

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
      {"type": "approval_required", "context": ApprovalContext}
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

        tools = skill_registry.get_tools(categories=self.skill_categories)
        messages: List[Dict[str, Any]] = [
            {"role": "user", "content": self._build_initial_message(scope_summary, prior_context)}
        ]

        findings: List[Dict[str, Any]] = []
        tool_calls_log: List[Dict[str, Any]] = []

        for iteration in range(MAX_TOOL_ITERATIONS):
            response_data = await self._call_claude(messages, tools)
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

                # Approval gate for dangerous skills
                if skill_registry.is_approval_required(tool_name):
                    approval_ctx = ApprovalContext(
                        level="tool",
                        tool_name=tool_name,
                        tool_input=tool_input,
                        risk="high",
                        description=f"Agent wants to execute attack skill: {tool_name}",
                    )
                    yield {"type": "approval_required", "context": approval_ctx.model_dump()}
                    # In Phase A we halt — approval gates are wired in Phase B
                    yield {"type": "error", "message": f"Approval required for {tool_name}. Implement approval gate."}
                    return

                try:
                    skill_result = await skill_registry.execute(tool_name, tool_input)
                    result_content = skill_result.model_dump() if hasattr(skill_result, "model_dump") else str(skill_result)
                except Exception as exc:
                    result_content = {"success": False, "error": str(exc)}

                yield {"type": "tool_result", "name": tool_name, "result": result_content}

                tool_calls_log.append({"tool": tool_name, "input": tool_input, "result": result_content})
                if isinstance(result_content, dict) and result_content.get("success"):
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
    ) -> Optional[Dict[str, Any]]:
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        payload: Dict[str, Any] = {
            "model": DEFAULT_MODEL,
            "max_tokens": MAX_TOKENS,
            "system": self.system_prompt,
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
