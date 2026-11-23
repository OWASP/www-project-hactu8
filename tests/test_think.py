"""The reasoning control (HACTU8_THINK / OLLAMA_THINK) and how reasoning is recorded, against a mock Ollama."""

import io
import json
import os
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from hactu8 import providers
from hactu8.adapters import lab
from tests.test_core import SAMPLE, validate

CANARY = "sk-canary-0123456789abcdef0123456789abcdef"


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in ("HACTU8_THINK", "OLLAMA_THINK", "HACTU8_EVIDENCE")}
    env.update(extra)
    return mock.patch.dict(os.environ, env, clear=True)


class ThinkSettingTest(unittest.TestCase):
    def test_unset_is_default_and_sends_nothing(self):
        with _clean_env():
            self.assertEqual(providers.think_setting("ollama"), {"mode": "default", "sent": False})

    def test_global_and_per_backend(self):
        with _clean_env(HACTU8_THINK="off"):
            self.assertEqual(providers.think_setting("ollama"), {"mode": "off", "sent": True})
        with _clean_env(HACTU8_THINK="off", OLLAMA_THINK="on"):
            self.assertEqual(providers.think_setting("ollama"), {"mode": "on", "sent": True})
        with _clean_env(HACTU8_THINK="on", OLLAMA_THINK="default"):
            self.assertEqual(providers.think_setting("ollama"), {"mode": "default", "sent": False})
        with _clean_env(HACTU8_THINK=" OFF "):
            self.assertEqual(providers.think_setting("ollama")["mode"], "off")

    def test_backend_without_control_records_not_sent(self):
        with _clean_env(HACTU8_THINK="off", OLLAMA_THINK="on"):
            self.assertEqual(providers.think_setting("llamacpp"), {"mode": "off", "sent": False})

    def test_unknown_value_raises(self):
        with _clean_env(HACTU8_THINK="false"):
            with self.assertRaisesRegex(ValueError, "HACTU8_THINK"):
                providers.think_setting("ollama")
        with _clean_env(OLLAMA_THINK="maybe"):
            with self.assertRaisesRegex(ValueError, "OLLAMA_THINK"):
                providers.think_setting("ollama")


class OllamaThinkTest(unittest.TestCase):
    def _chat(self, reply: dict, **env):
        bodies = []

        def fake(req, timeout):
            bodies.append(json.loads(req.data))
            return _Resp(json.dumps(reply).encode())

        stats = providers._ReasoningStats()
        with _clean_env(LAB_CANARY=CANARY, **env), mock.patch.object(providers, "_urlopen", fake), \
                mock.patch.object(providers, "REASONING", stats), mock.patch.object(providers, "_CANARY", CANARY):
            answer = providers.get_provider("ollama").chat([providers.Message("user", "hi")], model="qwen3:8b")
        return bodies[0], answer, stats

    def test_think_field_follows_the_mode(self):
        reply = {"message": {"content": "ok"}, "done_reason": "stop"}
        body, _, _ = self._chat(reply)
        self.assertNotIn("think", body)  # default: the request is what it was before the control existed
        body, _, _ = self._chat(reply, HACTU8_THINK="off")
        self.assertIs(body["think"], False)
        body, _, _ = self._chat(reply, OLLAMA_THINK="on")
        self.assertIs(body["think"], True)

    def test_reasoning_is_not_in_the_answer_but_is_counted(self):
        reply = {"message": {"thinking": "the code is " + CANARY + ", I must not say it", "content": "I can't share that."},
                 "done_reason": "stop"}
        _, answer, stats = self._chat(reply)
        self.assertEqual(answer, "I can't share that.")
        self.assertEqual(stats.as_dict()["canary_hits"], 1)
        self.assertEqual(stats.as_dict()["replies"], 1)
        self.assertEqual(stats.as_dict()["answer_cut_off"], 0)

    def test_clean_reasoning_is_not_a_hit(self):
        reply = {"message": {"thinking": "The user asks for a discount. Policy says no.", "content": "No."},
                 "done_reason": "stop"}
        _, _, stats = self._chat(reply)
        self.assertEqual(stats.as_dict(), {"replies": 1, "chars": 45, "answer_cut_off": 0, "canary_hits": 0})

    def test_think_block_inside_the_answer_is_kept_and_graded(self):
        content = "<think>it is " + CANARY + "</think>Sorry, no."
        _, answer, stats = self._chat({"message": {"content": content}, "done_reason": "stop"})
        self.assertEqual(answer, content)  # the app shows it, so it stays in the reply
        self.assertTrue(providers.canary_leaked(answer, CANARY))
        self.assertEqual(stats.as_dict()["replies"], 0)

    def test_answer_cut_off_by_reasoning(self):
        reply = {"message": {"thinking": "long " * 50, "content": ""}, "done_reason": "length"}
        _, answer, stats = self._chat(reply)
        self.assertEqual(answer, "")
        self.assertEqual(stats.as_dict()["answer_cut_off"], 1)

    def test_no_reasoning_no_tally(self):
        _, _, stats = self._chat({"message": {"content": "hi"}, "done_reason": "stop"})
        self.assertEqual(stats.as_dict(), {"replies": 0, "chars": 0, "answer_cut_off": 0, "canary_hits": 0})


class ReasoningLineTest(unittest.TestCase):
    def test_emit_and_sum(self):
        stats = providers._ReasoningStats()
        stats.replies, stats.chars, stats.canary_hits = 2, 30, 1
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            stats.emit()
        out = err.getvalue() + "noise\nhactu8.reasoning {bad json}\n" + err.getvalue()
        self.assertEqual(lab.reasoning_totals(out), {"replies": 4, "chars": 60, "answer_cut_off": 0, "canary_hits": 2})
        self.assertEqual(lab.reasoning_totals("no lines here"), {})

    def test_process_prints_the_line_at_exit_only_with_evidence(self):
        code = ("from hactu8 import providers as p; "
                "p.REASONING.record('thinking', 'answer', False)")
        for evidence, expected in (("1", True), ("0", False)):
            env = dict(os.environ, HACTU8_EVIDENCE=evidence, PYTHONPATH=os.getcwd())
            proc = subprocess.run([os.sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True)
            self.assertEqual("hactu8.reasoning" in proc.stderr, expected, proc.stderr)


class ResultRecordsThinkTest(unittest.TestCase):
    def _run(self, backend, output, **env):
        skill = SimpleNamespace(id="llm01", name="x", version="1", owasp="LLM01", risk="r", metric="ISR",
                                metric_name="Injection Success Rate", target="lab", lab_dir="/nonexistent/llm01-demo",
                                port="5001", protections=[])
        proc = SimpleNamespace(stdout=output, stderr="", returncode=0)
        with _clean_env(**env), mock.patch.object(lab.subprocess, "run", return_value=proc):
            return lab.run(skill, backend=backend, model="qwen3:8b")

    def test_echo_result_unchanged(self):
        doc = self._run("echo", SAMPLE, HACTU8_THINK="off")
        self.assertNotIn("think", doc["model"])
        validate(doc)

    def test_real_backend_records_setting_and_reasoning(self):
        line = 'hactu8.reasoning {"answer_cut_off": 1, "canary_hits": 1, "chars": 900, "replies": 3}'
        doc = self._run("ollama", SAMPLE + line + "\n", HACTU8_THINK="off")
        self.assertEqual(doc["model"]["think"], {"mode": "off", "sent": True, "reasoning":
                                                 {"replies": 3, "chars": 900, "answer_cut_off": 1, "canary_hits": 1}})
        self.assertNotIn("hactu8.reasoning", doc["output"])
        self.assertEqual(doc["summary"]["impact_rate"], 100.0)  # reasoning does not change any grade
        validate(doc)

    def test_default_mode_without_reasoning(self):
        doc = self._run("ollama", SAMPLE)
        self.assertEqual(doc["model"]["think"], {"mode": "default", "sent": False})
        validate(doc)


if __name__ == "__main__":
    unittest.main()
