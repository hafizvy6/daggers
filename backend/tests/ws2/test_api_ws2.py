"""HTTP-level tests for the WS2 routers. Require fastapi + httpx (TestClient);
skipped — and reported as skipped — when those are not installed."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from backend.tests.ws2 import helpers

import sys  # noqa: E402

_COMPAT = str(helpers.ROOT / "backend" / "tests" / "_compat")
if importlib.util.find_spec("fastapi") is None and _COMPAT not in sys.path:
    sys.path.insert(0, _COMPAT)  # test harness (see backend/tests/_compat/fastapi)
HAVE_STACK = all(importlib.util.find_spec(m) for m in ("fastapi", "httpx"))


@unittest.skipUnless(HAVE_STACK, "fastapi/httpx not installed")
class TestWs2Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from backend.app.config import Settings
        from backend.app.main import create_app

        cls.tmp = Path(tempfile.mkdtemp())
        settings = Settings(
            db_path=cls.tmp / "d.db", evidence_dir=cls.tmp / "ev", gallery_dir=cls.tmp / "g",
            web_dir=cls.tmp / "web", mode="live", environment="dev", cors_origins=[], heartbeat_interval_s=1,
        )
        cls.app = create_app(settings)
        cls.ctx = TestClient(cls.app)
        cls.client = cls.ctx.__enter__()
        from backend.tests.conftest import login_as

        login_as(cls.client, cls.app, "investigator")

    @classmethod
    def tearDownClass(cls):
        cls.ctx.__exit__(None, None, None)

    def test_routers_mounted(self):
        paths = {getattr(r, "path", "") for r in self.app.router.routes}
        self.assertIn("/api/sweep", paths)
        self.assertIn("/api/guard/blocklist.txt", paths)

    def test_sweep_post_and_get(self):
        r = self.client.post("/api/sweep?wait=true", json={"channel": "web", "query_id": "web-adpolice-fines"})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        # Fresh live install, no provider configured: an honest failed run, never sample results.
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["results"], [])
        self.assertEqual(self.client.get(f"/api/sweep/{body['id']}").json()["results"], body["results"])
        self.assertEqual(self.client.get("/api/sweep/987654").status_code, 404)
        self.assertEqual(self.client.post("/api/sweep", json={"channel": "web", "query": "free text"}).status_code, 403)
        self.assertEqual(self.client.post("/api/sweep", json={"channel": "sms"}).status_code, 422)

    def test_guard_endpoints(self):
        r = self.client.get("/api/guard/blocklist.txt")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("0.0.0.0 ", r.text)  # fresh live install: nothing confirmed yet
        status = self.client.get("/api/guard/sync-status").json()
        self.assertEqual(status["source"], "guard_feed")
        self.assertFalse(status["nextdns"]["block_events_measured"])
        # The engine's Guard endpoints still answer.
        self.assertEqual(self.client.get("/api/guard/feed").status_code, 200)


if __name__ == "__main__":
    unittest.main()
