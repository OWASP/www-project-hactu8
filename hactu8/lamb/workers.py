"""Lazy, isolated lab workers behind the Lamb gateway."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from hactu8 import catalog
from hactu8.catalog import Skill


class WorkerError(RuntimeError):
    pass


class LabWorkerManager:
    def __init__(self, root: Optional[Path] = None, skills: Optional[Iterable[Skill]] = None,
                 startup_timeout: float = 8.0) -> None:
        discovered = list(skills) if skills is not None else catalog.discover(root)
        self.skills: Dict[str, Skill] = {skill.id: skill for skill in discovered}
        self.startup_timeout = startup_timeout
        self._processes: Dict[str, subprocess.Popen] = {}
        self._logs = {}
        self._lock = threading.RLock()
        self._log_dir = tempfile.TemporaryDirectory(prefix="hactu8-lamb-")

    def describe(self, public_base: str) -> list:
        rows = []
        with self._lock:
            for skill in sorted(self.skills.values(), key=lambda item: item.id):
                proc = self._processes.get(skill.id)
                state = "running" if proc and proc.poll() is None else "stopped"
                rows.append({
                    "id": skill.id,
                    "owasp": skill.owasp,
                    "risk": skill.risk,
                    "metric": skill.metric,
                    "worker_port": int(skill.port),
                    "url": f"{public_base}/labs/{skill.id}",
                    "state": state,
                })
        return rows

    def ensure_started(self, skill_id: str) -> Skill:
        skill = self._skill(skill_id)
        with self._lock:
            proc = self._processes.get(skill_id)
            if proc and proc.poll() is None:
                return skill
            if self._port_open(int(skill.port)):
                raise WorkerError(f"{skill_id}: worker port {skill.port} is already in use")
            script = Path(skill.skill_dir) / "vulnerable_app.py"
            if not script.is_file():
                raise WorkerError(f"{skill_id}: no vulnerable_app.py at {script}")
            log_path = Path(self._log_dir.name) / f"{skill_id}.log"
            log = open(log_path, "w+", encoding="utf-8")
            env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
            prefix = skill.id.upper()
            env[f"{prefix}_PORT"] = skill.port
            env.setdefault(f"{prefix}_BACKEND", "echo")
            proc = subprocess.Popen(
                [sys.executable, str(script)],
                cwd=skill.skill_dir,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self._processes[skill_id] = proc
            self._logs[skill_id] = log
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise WorkerError(f"{skill_id}: worker exited during startup: {self._log_tail(skill_id)}")
            try:
                status, _, _ = self._request(skill, "GET", "/health", {}, b"", timeout=0.5)
                if status == 200:
                    return skill
            except (OSError, WorkerError):
                pass
            time.sleep(0.05)
        self.stop(skill_id)
        raise WorkerError(f"{skill_id}: worker did not answer within {self.startup_timeout:g}s")

    def request(self, skill_id: str, method: str, path: str, headers: dict, body: bytes,
                timeout: float = 30.0) -> Tuple[int, dict, bytes]:
        skill = self.ensure_started(skill_id)
        return self._request(skill, method, path, headers, body, timeout)

    def reset(self, skill_ids: Optional[Iterable[str]] = None) -> dict:
        wanted = list(skill_ids) if skill_ids is not None else self.running_ids()
        reset, errors = [], {}
        for skill_id in wanted:
            try:
                status, _, body = self.request(
                    skill_id, "POST", "/api/reset",
                    {"Content-Type": "application/json"}, b"{}", timeout=10.0)
                if status != 200:
                    raise WorkerError(f"reset returned HTTP {status}: {body[:300].decode(errors='replace')}")
                reset.append(skill_id)
            except (OSError, WorkerError) as exc:
                errors[skill_id] = str(exc)
        return {"reset": reset, "errors": errors}

    def running_ids(self) -> list:
        with self._lock:
            return sorted(skill_id for skill_id, proc in self._processes.items() if proc.poll() is None)

    def stop(self, skill_id: str) -> None:
        with self._lock:
            proc = self._processes.pop(skill_id, None)
            log = self._logs.pop(skill_id, None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        if log:
            log.close()

    def close(self) -> None:
        for skill_id in list(self._processes):
            self.stop(skill_id)
        self._log_dir.cleanup()

    def _skill(self, skill_id: str) -> Skill:
        try:
            return self.skills[skill_id.lower()]
        except KeyError:
            raise WorkerError(f"unknown Lamb lab {skill_id!r}") from None

    @staticmethod
    def _port_open(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            return False

    @staticmethod
    def _request(skill: Skill, method: str, path: str, headers: dict, body: bytes,
                 timeout: float) -> Tuple[int, dict, bytes]:
        if not path.startswith("/"):
            path = "/" + path
        url = f"http://127.0.0.1:{skill.port}{path}"
        forwarded = {
            key: value for key, value in headers.items()
            if key.lower() in {"accept", "content-type"}
        }
        req = urllib.request.Request(
            url,
            data=body if method not in ("GET", "HEAD") else None,
            headers=forwarded,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.status, dict(response.headers.items()), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read()

    def _log_tail(self, skill_id: str) -> str:
        log = self._logs.get(skill_id)
        if not log:
            return "no worker log"
        log.flush()
        log.seek(0)
        return log.read()[-1000:].strip() or "worker produced no output"

