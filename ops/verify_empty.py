#!/usr/bin/env python3
"""Boot a fresh live installation and prove it contains no product data."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import fastapi  # noqa: F401
except ImportError:  # test harness only (real FastAPI is installed in every deployment)
    sys.path.insert(0, str(ROOT / "backend" / "tests" / "_compat"))
from fastapi.testclient import TestClient  # noqa: E402

from backend.app.config import Settings
from backend.app.main import create_app


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="daggers-empty-") as directory:
        root = Path(directory)
        settings = Settings.from_env(
            {
                "DB_PATH": str(root / "daggers.db"),
                "EVIDENCE_DIR": str(root / "evidence"),
                "GALLERY_DIR": str(root / "gallery"),
                "WEB_DIR": str(ROOT / "web"),
                "CORS_ORIGINS": "",
                "AI_STATE": "template",
            }
        )
        app = create_app(settings)
        with TestClient(app) as client:
            status = client.get("/api/status").json()
            health = client.get("/api/healthz").json()
            feed = client.get("/api/feed").json()
            reports_status = client.get("/api/reports").status_code        # portal data: login required
            portal_status = client.get("/api/portal/findings").status_code
            stored_reports = app.state.runtime.repo.list_reports() if hasattr(app.state.runtime.repo, "list_reports") else []
            guard = client.get("/api/guard/feed").text
            examples = client.get("/api/examples").json()

            assert status["mode"] == "live", status
            assert status["counts"] == {"domains": 0, "findings": 0, "evidence": 0}, status
            assert feed == [], feed
            assert reports_status == 401 and portal_status == 401, (reports_status, portal_status)
            assert stored_reports == [], stored_reports
            assert guard.strip() == "", guard
            assert examples["check"] == [] and examples["numbers"] == [], examples
            external = {k: v for k, v in health["adapters"].items() if k != "guard"}
            assert all(not adapter["enabled"] for adapter in external.values()), health
            guard = health["adapters"]["guard"]
            assert guard["configured"] is False and guard["hostname"] == "" and guard["manual_sync"] is True, guard
            ai = health["adapters"]["ai"]
            assert ai["state"] == "template" and ai["enabled"] is False, ai
            assert client.get("/api/evidence/1.jpg").status_code == 404
            print(json.dumps({"ok": True, "status": status, "adapters": health["adapters"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
