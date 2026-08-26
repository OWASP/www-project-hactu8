"""ProjectRunEngine — drives one turn of a Project run's conversation.

Parallel to agents/base_agent.py's BaseAgent, but turn-based (a user can
send follow-up messages, unlike the fixed single-shot phase loop) and
multi-provider (via services.llm_dispatch.call_model) instead of
Anthropic-only. Tools are scoped to the run's user-picked skill_names
(skill_packages.runner's SkillScope = List[str] mode), not a phase tag.
"""

import json
from typing import Any, AsyncGenerator, Dict, List, Optional

from project_runs.models import ProjectRunScope, ProjectRunTurn
from services.llm_dispatch import call_model
from skill_packages.runner import SKILL_RUNNER_TOOLS, SkillRunnerError, list_skills, read_skill, run_skill

MAX_TOOL_ITERATIONS = 25


def _build_system_prompt(scope: ProjectRunScope, instructions_md: str, overview_md: str) -> str:
    target = scope.target
    target_desc = target.target_url or target.name
    parts = [
        f"You are running the IAC Project \"{scope.project_name}\" against target \"{target_desc}\".",
        f"# Overview\n\n{overview_md}" if overview_md else "",
        f"# Instructions\n\n{instructions_md}" if instructions_md else "",
        (
            f"# Target\n\nName: {target.name}\n"
            + (f"URL: {target.target_url}\n" if target.target_url else "No URL provided yet — ask the user for one if you need it.\n")
            + (f"Notes: {target.risk_notes}\n" if target.risk_notes else "")
        ),
        (
            f"# Available skills\n\nYou have access to these skills: {', '.join(scope.skill_names)}.\n"
            "Call list_skills for descriptions, read_skill for full instructions on one, "
            "and run_skill_script to execute a skill's bundled script."
        ),
    ]
    return "\n\n".join(p for p in parts if p)


def _turns_to_messages(turns: List[ProjectRunTurn]) -> List[Dict[str, Any]]:
    return [{"role": t.role, "content": t.content} for t in turns]


async def run_turn(
    scope: ProjectRunScope,
    prior_turns: List[ProjectRunTurn],
    user_message: str,
    instructions_md: str,
    overview_md: str,
) -> AsyncGenerator[Dict[str, Any], None]:
    """Yields the same event vocabulary as BaseAgent.run:
      {"type": "text", "content": "..."}
      {"type": "tool_call", "name": "...", "input": {...}}
      {"type": "tool_result", "name": "...", "result": {...}}
      {"type": "complete", "content": "...", "findings": [...]}
      {"type": "error", "message": "..."}
    """
    # No pre-flight API-key guard here (unlike BaseAgent.run's early exit) —
    # call_model() already falls back to server-side env vars per provider
    # when no key is supplied, so a client-side-only check would incorrectly
    # reject requests that would actually succeed. If no key resolves
    # anywhere, call_model() raises a clear ValueError, caught below.
    system_prompt = _build_system_prompt(scope, instructions_md, overview_md)
    messages = _turns_to_messages(prior_turns)
    messages.append({"role": "user", "content": user_message})

    findings: List[Dict[str, Any]] = []

    for _iteration in range(MAX_TOOL_ITERATIONS):
        try:
            result = await call_model(
                messages,
                provider_id=scope.model.provider_id,
                model_id=scope.model.model_id,
                api_key=scope.model.api_key,
                base_url=scope.model.base_url,
                system_prompt=system_prompt,
                tools=SKILL_RUNNER_TOOLS,
            )
        except Exception as exc:
            yield {"type": "error", "message": str(exc)}
            return

        for text in result.text_blocks:
            if text:
                yield {"type": "text", "content": text}

        if result.stop_reason != "tool_use" or not result.tool_calls:
            final_text = "".join(result.text_blocks).strip()
            yield {"type": "complete", "content": final_text, "findings": findings}
            return

        assistant_content = "".join(result.text_blocks) or None
        messages.append({
            "role": "assistant",
            "content": assistant_content,
            "tool_calls": [{"id": tc.id, "name": tc.name, "input": tc.input} for tc in result.tool_calls],
        })

        for tc in result.tool_calls:
            yield {"type": "tool_call", "name": tc.name, "input": tc.input}

            try:
                if tc.name == "list_skills":
                    tool_result: Any = list_skills(scope.skill_names)
                elif tc.name == "read_skill":
                    tool_result = {"body": read_skill(scope.skill_names, tc.input.get("name", ""))}
                elif tc.name == "run_skill_script":
                    tool_result = await run_skill(
                        scope.skill_names, tc.input.get("name", ""), tc.input.get("script", ""), tc.input.get("args")
                    )
                else:
                    tool_result = {"success": False, "error": f"Unknown tool: {tc.name}"}
            except SkillRunnerError as exc:
                tool_result = {"success": False, "error": str(exc)}
            except Exception as exc:
                tool_result = {"success": False, "error": str(exc)}

            yield {"type": "tool_result", "name": tc.name, "result": tool_result}

            if (
                tc.name == "run_skill_script"
                and isinstance(tool_result, dict)
                and tool_result.get("exit_code") == 0
                and not tool_result.get("timed_out")
            ):
                findings.append({"tool": tc.name, "skill": tc.input.get("name"), "data": tool_result.get("stdout")})

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(tool_result),
            })

    yield {"type": "error", "message": f"Exceeded max tool iterations ({MAX_TOOL_ITERATIONS})"}
