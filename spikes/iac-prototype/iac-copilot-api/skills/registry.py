"""Skill registry — @skill decorator and SkillRegistry for agent tool dispatch."""

import functools
import inspect
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel


class SkillResult(BaseModel):
    success: bool
    data: Any = None
    error: Optional[str] = None


# Module-level registry: skill_name -> entry dict
_registry: Dict[str, Dict[str, Any]] = {}

# Python type annotation -> JSON Schema type
_TYPE_MAP = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
}


def _build_input_schema(fn: Callable) -> Dict[str, Any]:
    """Generate a JSON Schema input_schema from a function's type annotations."""
    sig = inspect.signature(fn)
    properties: Dict[str, Any] = {}
    required: List[str] = []

    for param_name, param in sig.parameters.items():
        annotation = param.annotation
        json_type = _TYPE_MAP.get(annotation, "string")
        properties[param_name] = {"type": json_type}
        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    return {"type": "object", "properties": properties, "required": required}


def skill(
    name: str,
    description: str,
    category: str,
    requires_approval: bool = False,
):
    """Decorator that registers a function as an IAC skill and builds its Claude tool schema."""

    def decorator(fn: Callable) -> Callable:
        tool_schema = {
            "name": name,
            "description": description,
            "input_schema": _build_input_schema(fn),
        }

        _registry[name] = {
            "fn": fn,
            "schema": tool_schema,
            "category": category,
            "requires_approval": requires_approval,
        }

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await fn(*args, **kwargs)

        wrapper.skill_name = name  # type: ignore[attr-defined]
        wrapper.skill_schema = tool_schema  # type: ignore[attr-defined]
        wrapper.requires_approval = requires_approval  # type: ignore[attr-defined]
        return wrapper

    return decorator


class SkillRegistry:
    """Provides tool schema lists and dispatches tool_use calls to registered skills."""

    def get_tools(self, categories: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Return Claude tool schemas, optionally filtered by category."""
        return [
            entry["schema"]
            for entry in _registry.values()
            if categories is None or entry["category"] in categories
        ]

    async def execute(self, tool_name: str, tool_input: Dict[str, Any]) -> Any:
        """Invoke a registered skill by name with the given inputs."""
        if tool_name not in _registry:
            raise ValueError(f"Unknown skill: {tool_name}")
        fn = _registry[tool_name]["fn"]
        return await fn(**tool_input)

    def is_approval_required(self, tool_name: str) -> bool:
        return _registry.get(tool_name, {}).get("requires_approval", False)

    def list_skills(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": name,
                "category": entry["category"],
                "requires_approval": entry["requires_approval"],
                "schema": entry["schema"],
            }
            for name, entry in _registry.items()
        ]


# Singleton used throughout the agents system
skill_registry = SkillRegistry()
