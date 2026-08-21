"""Skill registry — @skill decorator and SkillRegistry for agent tool dispatch."""

import functools
import hashlib
import inspect
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel


class SkillResult(BaseModel):
    success: bool
    data: Any = None
    error: Optional[str] = None


# Module-level registry: skill_name -> entry dict
_registry: Dict[str, Dict[str, Any]] = {}

# Skills registered without an explicit version are assumed to be this
# version for digest purposes. Per-skill versioning (mirroring the frontend
# SkillManifest.version semver field) can be added later without changing
# the digest scheme itself.
DEFAULT_SKILL_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Integrity / signing
#
# Mirrors the frontend digest scheme in `iac-host/src/services/skillService.ts`
# (`computeDigest`): sha256(f"{id}@{version}:{content}"). There, `content` is
# a skill's full SKILL.md text. Here, a "skill" is a Python function rather
# than a markdown package, so `content` is the function's own source code
# (via `inspect.getsource`) — the most direct, deterministic stand-in for
# "what this skill actually does." A docstring/schema-only digest would miss
# changes to the implementation itself, which is exactly what an integrity
# check needs to catch.
# ---------------------------------------------------------------------------


def compute_skill_digest(skill_id: str, version: str, content: str) -> str:
    """sha256 digest of a skill's identity + content, same payload shape as the
    frontend's `computeDigest()` so the two systems are conceptually aligned
    even though they hash different kinds of "content"."""
    payload = f"{skill_id}@{version}:{content}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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
    protected: bool = False,
    expected_digest: Optional[str] = None,
    version: str = DEFAULT_SKILL_VERSION,
):
    """Decorator that registers a function as an IAC skill and builds its Claude tool schema.

    Integrity (protected skills):
      `protected=True` marks a skill as one whose content should be verified
      before every execution, not just gated on human approval. At import
      time we compute this skill's digest from its own source
      (`compute_skill_digest`). If the caller supplies `expected_digest`
      (a hash a maintainer reviewed and pinned into the source alongside the
      code — analogous to the frontend's curator-signed `SkillSignature`),
      that pinned value is what execution-time checks are compared against;
      if the function body is later edited without updating the pin, the
      mismatch is caught on the next run. If no `expected_digest` is given,
      the skill self-pins to whatever digest it computes right now
      ("trust on first registration") — this at least catches *runtime*
      tampering (e.g. something monkey-patching the registered function
      object after import) even though it can't catch tampering to the
      source file that happened before the process started. See
      `SkillRegistry.verify_integrity`.
    """

    def decorator(fn: Callable) -> Callable:
        tool_schema = {
            "name": name,
            "description": description,
            "input_schema": _build_input_schema(fn),
        }

        try:
            source = inspect.getsource(fn)
        except (OSError, TypeError):
            # Can't introspect source (e.g. dynamically generated function) —
            # fall back to the schema as the digested content so registration
            # doesn't hard-fail; protected skills relying on this are weaker
            # (schema drift is far coarser than source drift) but still get
            # *some* signal.
            source = str(tool_schema)

        registered_digest = compute_skill_digest(name, version, source)

        _registry[name] = {
            "fn": fn,
            "schema": tool_schema,
            "category": category,
            "requires_approval": requires_approval,
            "protected": protected,
            "version": version,
            "registered_digest": registered_digest,
            "expected_digest": (expected_digest or registered_digest) if protected else None,
        }

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await fn(*args, **kwargs)

        wrapper.skill_name = name  # type: ignore[attr-defined]
        wrapper.skill_schema = tool_schema  # type: ignore[attr-defined]
        wrapper.requires_approval = requires_approval  # type: ignore[attr-defined]
        wrapper.protected = protected  # type: ignore[attr-defined]
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

    def is_protected(self, tool_name: str) -> bool:
        return _registry.get(tool_name, {}).get("protected", False)

    def verify_integrity(self, tool_name: str) -> Dict[str, Any]:
        """Recompute a registered skill's digest from its *current* function
        object and compare it to the digest recorded at registration time.

        Skills not marked `protected=True` are not subject to this check —
        `passed` is `True` and `protected` is `False` for them, so callers
        should gate on `protected` before treating a mismatch as meaningful.

        A mismatch means either: (a) the registered function object was
        replaced at runtime (e.g. monkey-patched by a compromised import),
        or (b) the skill was registered with an explicit `expected_digest`
        that no longer matches the function's current source — i.e. the
        implementation drifted from what a maintainer reviewed and pinned.
        """
        entry = _registry.get(tool_name)
        if entry is None:
            return {
                "passed": False,
                "protected": False,
                "message": f"Unknown skill: {tool_name!r} is not registered.",
            }

        if not entry.get("protected"):
            return {"passed": True, "protected": False, "message": "Skill is not protected; integrity check skipped."}

        fn = entry["fn"]
        try:
            current_source = inspect.getsource(fn)
        except (OSError, TypeError) as exc:
            return {
                "passed": False,
                "protected": True,
                "expected_digest": entry.get("expected_digest"),
                "actual_digest": None,
                "message": f"Could not read source for {tool_name!r} to verify integrity: {exc}",
            }

        actual_digest = compute_skill_digest(tool_name, entry.get("version", DEFAULT_SKILL_VERSION), current_source)
        expected_digest = entry.get("expected_digest")
        passed = actual_digest == expected_digest

        message = (
            "Integrity verified — content matches signed digest."
            if passed
            else (
                f"Integrity check FAILED for protected skill {tool_name!r}: "
                f"expected digest {expected_digest}, computed {actual_digest}. "
                "The skill's content does not match what was recorded/signed at "
                "registration — treating as tampered."
            )
        )

        return {
            "passed": passed,
            "protected": True,
            "expected_digest": expected_digest,
            "actual_digest": actual_digest,
            "message": message,
        }

    def list_skills(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": name,
                "category": entry["category"],
                "requires_approval": entry["requires_approval"],
                "protected": entry.get("protected", False),
                "schema": entry["schema"],
            }
            for name, entry in _registry.items()
        ]


# Singleton used throughout the agents system
skill_registry = SkillRegistry()
