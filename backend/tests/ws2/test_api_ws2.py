"""HTTP-level tests for the WS2 routers in a fresh, adapter-disabled live install."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from backend.tests.ws2 import helpers

HAVE_STACK = all(importlib.util.find_spec(module) for module in ("fastapi", "httpx"))


@unittest.skipUnless(HAVE_STACK, "fastapi/httpx not installed")
class TestWs2Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from backend.app.config import Settings
        from backend.app.main import create_app

        cls.tmp = Path(tempfile.mkdtemp())
        settings = Settings(
            db_path=cls.tmp / "d.db",
            evidence_dir=cls.tmp / "ev",
            gallery_dir=cls.tmp / "gallery",
            web_dir=cls.tmp / "web",
            mode="live",
            environment="production",
            cors_origins=[],
            heartbeat_interval_s=1,
            ai_state="template",
        )
        cls.app = create_app(settings)
        cls.ctx = TestClient(cls.app)
        cls.client = cls.ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.ctx.__exit__(None, None, None)

    def test_routers_mounted(self):
        states = self.app.state.runtime.optional_routers
        self.assertEqual(states["backend.app.api.sweep"], "mounted")
        self.assertEqual(states["backend.app.api.guard"], "mounted")

    def test_sweep_is_empty_and_honest_when_unconfigured(self):
        response = self.client.post("/api/sweep", json={"channel": "web", "query_id": "web-adpolice-fines"})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["source_kind"], "unconfigured")
        self.assertEqual(body["results"], [])
        self.assertEqual(body["store"], "sqlite")
        self.assertEqual(self.client.get(f"/api/sweep/{body['id']}").json()["results"], body["results"])
        self.assertEqual(self.client.get("/api/sweep/987654").status_code, 404)
        self.assertEqual(self.client.post("/api/sweep", json={"channel": "web", "query": "free text"}).status_code, 403)
        self.assertEqual(self.client.post("/api/sweep", json={"channel": "sms"}).status_code, 422)

    def test_guard_endpoints_are_empty_and_official_domains_are_safe(self):
        blocklist = self.client.get("/api/guard/blocklist.txt")
        self.assertEqual(blocklist.status_code, 200)
        self.assertNotIn("0.0.0.0 ", blocklist.text)
        self.assertNotIn("adcb-giveaway-1m.top", blocklist.text)
        status = self.client.get("/api/guard/sync-status").json()
        self.assertEqual(status["source"], "guard_feed")
        self.assertFalse(status["nextdns"]["block_events_measured"])
        config = self.client.get("/api/guard/config").json()
        self.assertIsNone(config["hostname"])
        self.assertFalse(config["configured"])
        self.assertEqual(self.client.get("/api/guard/feed").status_code, 200)


if __name__ == "__main__":
    unittest.main()
