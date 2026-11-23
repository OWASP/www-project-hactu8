"""scripts/vendor.py web sync: every lab gets the full template console, nothing escapes --check."""

import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("vendor_script", ROOT / "scripts" / "vendor.py")
vendor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vendor)

TEMPLATE = {"index.html": "<html>", "app.js": "// app", "styles.css": "/* css */", "img/logo.svg": "<svg/>"}


class VendorWebSyncTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "hactu8").mkdir()
        for name, text in TEMPLATE.items():
            self.write(f"demos/_template/web/{name}", text)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_vendor(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vendor.main(list(argv), root=self.root)
        return rc, out.getvalue()

    def complete_lab(self, lab):
        for name, text in TEMPLATE.items():
            self.write(f"{lab}/web/{name}", text)

    def test_complete_labs_pass(self):
        self.complete_lab("demos/a-demo/a-skill")
        self.write("demos/a-demo/a-skill/vulnerable_app.py", "")
        self.assertEqual(self.run_vendor("--check")[0], 0)

    def test_web_without_app_js_is_checked(self):
        self.write("demos/b-demo/b-skill/web/index.html", "<html>")
        self.write("demos/b-demo/b-skill/web/styles.css", "/* old */")
        rc, out = self.run_vendor("--check")
        self.assertEqual(rc, 1)
        self.assertIn("missing: demos/b-demo/b-skill/web/app.js", out)
        self.assertIn("drift: demos/b-demo/b-skill/web/styles.css", out)

    def test_new_template_file_reaches_every_lab(self):
        self.complete_lab("demos/a-demo/a-skill")
        self.write("demos/_template/web/help.js", "// new")
        rc, out = self.run_vendor("--check")
        self.assertEqual(rc, 1)
        self.assertIn("missing: demos/a-demo/a-skill/web/help.js", out)
        self.assertEqual(self.run_vendor()[0], 0)
        self.assertEqual((self.root / "demos/a-demo/a-skill/web/help.js").read_text(), "// new")
        self.assertEqual(self.run_vendor("--check")[0], 0)

    def test_lab_without_web_is_flagged_and_filled(self):
        self.write("demos/c-demo/c-skill/vulnerable_app.py", "")
        rc, out = self.run_vendor("--check")
        self.assertEqual(rc, 1)
        self.assertIn("missing: demos/c-demo/c-skill/web/index.html", out)
        self.run_vendor()
        self.assertEqual(self.run_vendor("--check")[0], 0)
        self.assertTrue((self.root / "demos/c-demo/c-skill/web/img/logo.svg").is_file())

    def test_intended_no_console_lab_is_skipped(self):
        self.write("demos/c-demo/c-skill/vulnerable_app.py", "")
        original = vendor.NO_CONSOLE
        vendor.NO_CONSOLE = frozenset({"demos/c-demo/c-skill"})
        try:
            self.assertEqual(self.run_vendor("--check")[0], 0)
        finally:
            vendor.NO_CONSOLE = original

    def test_extra_lab_file_is_reported_not_deleted(self):
        self.complete_lab("demos/a-demo/a-skill")
        self.write("demos/a-demo/a-skill/web/extra.js", "x")
        rc, out = self.run_vendor("--check")
        self.assertEqual(rc, 1)
        self.assertIn("extra (not in demos/_template/web, not removed): demos/a-demo/a-skill/web/extra.js", out)
        self.run_vendor()
        self.assertTrue((self.root / "demos/a-demo/a-skill/web/extra.js").exists())


if __name__ == "__main__":
    unittest.main()
