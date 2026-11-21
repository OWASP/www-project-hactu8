"""Lab lessons: load, validate and expose ``<skill dir>/LESSON.md`` (AG-60).

A lesson lives inside the skill folder, so the lab stays self-contained and
copyable. Its format is fixed (``demos/_template/TEMPLATE.md``, section 16):
an optional H1 title and intro, then exactly the seven H2 sections in
``SECTIONS``, in that order, each non-empty. "Check yourself" holds 2 or 3
top-level numbered questions. Headings inside fenced code blocks are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

FILENAME = "LESSON.md"

SECTIONS = (
    "What it is",
    "Why it works",
    "Try it",
    "The defense, and why it holds",
    "Where the defense stops working",
    "Check yourself",
    "References",
)
QUESTIONS_SECTION = "Check yourself"
MIN_QUESTIONS, MAX_QUESTIONS = 2, 3

_FENCE = re.compile(r"^\s*(```|~~~)")
_H1 = re.compile(r"^#\s+(.+?)\s*#*\s*$")
_H2 = re.compile(r"^##\s+(.+?)\s*#*\s*$")
_QUESTION = re.compile(r"^\d+[.)]\s+(.+)$")


class LessonError(ValueError):
    """A LESSON.md that does not follow the fixed format. ``problems`` lists every fault found."""

    def __init__(self, problems: List[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass
class Lesson:
    title: str
    sections: Dict[str, str]
    questions: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"title": self.title, "sections": dict(self.sections), "questions": list(self.questions)}


def lesson_path(skill_dir: Union[str, Path]) -> Path:
    return Path(skill_dir) / FILENAME


def has_lesson(skill_dir: Union[str, Path]) -> bool:
    return lesson_path(skill_dir).is_file()


def _split(text: str):
    """Return (title, [(h2 title, body)]), skipping headings inside fenced code."""
    title = ""
    parts: List[list] = []
    in_fence = False
    for line in text.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
        if not in_fence:
            h2 = _H2.match(line)
            if h2:
                parts.append([h2.group(1), []])
                continue
            h1 = _H1.match(line)
            if h1 and not parts and not title:
                title = h1.group(1)
                continue
        if parts:
            parts[-1][1].append(line)
    return title, [(name, "\n".join(body).strip()) for name, body in parts]


def questions(body: str) -> List[str]:
    """Top-level numbered list items (not indented, outside code fences)."""
    found: List[str] = []
    in_fence = False
    for line in body.splitlines():
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        match = None if in_fence else _QUESTION.match(line)
        if match:
            found.append(match.group(1).strip())
    return found


def parse(text: str) -> Lesson:
    """Validate a lesson's text and return it as structured data, or raise LessonError."""
    title, parts = _split(text)
    problems: List[str] = []
    names = [name for name, _ in parts]
    missing = [name for name in SECTIONS if name not in names]
    if missing:
        problems.append("missing section(s): " + ", ".join(missing))
    unknown = [name for name in names if name not in SECTIONS]
    if unknown:
        problems.append("unknown section(s): " + ", ".join(unknown))
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        problems.append("duplicate section(s): " + ", ".join(duplicates))
    known = [name for name in names if name in SECTIONS]
    if not missing and not duplicates and known != list(SECTIONS):
        problems.append("sections out of order: expected " + ", ".join(SECTIONS))
    empty = [name for name, body in parts if name in SECTIONS and not body]
    if empty:
        problems.append("empty section(s): " + ", ".join(empty))
    sections = {name: body for name, body in parts if name in SECTIONS}
    asked = questions(sections.get(QUESTIONS_SECTION, ""))
    if QUESTIONS_SECTION in sections and not MIN_QUESTIONS <= len(asked) <= MAX_QUESTIONS:
        problems.append(f"'{QUESTIONS_SECTION}' needs {MIN_QUESTIONS} or {MAX_QUESTIONS} numbered questions, "
                        f"found {len(asked)}")
    if problems:
        raise LessonError(problems)
    return Lesson(title=title, sections={name: sections[name] for name in SECTIONS}, questions=asked)


def load(skill_dir: Union[str, Path]) -> Optional[Lesson]:
    """The skill's lesson, None when it has none yet. Raises LessonError when it is malformed."""
    path = lesson_path(skill_dir)
    if not path.is_file():
        return None
    return parse(path.read_text(encoding="utf-8"))
