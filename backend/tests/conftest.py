from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:  # Real FastAPI is required in production; the harness exists only for tests.
    import fastapi  # noqa: F401
    FASTAPI_HARNESS = False
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "_compat"))
    FASTAPI_HARNESS = True

from fastapi.testclient import TestClient  # noqa: E402
from backend.app.catalog import load_catalogs  # noqa: E402
from backend.app.config import Settings  # noqa: E402
from backend.app.main import create_app  # noqa: E402

# A tiny, valid JPEG used only as an isolated test double for a real capture.
ONE_PIXEL_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
    "2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCAABAAEDASIAAhEBAxEB/"
    "8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/"
    "9oADAMBAAIRAxEAPwCdABmX/9k="
)


@pytest.fixture(scope="session")
def catalog():
    return load_catalogs()


@pytest.fixture(scope="session")
def scoring_kwargs(catalog):
    return catalog.scoring_kwargs()


@pytest.fixture
def api_env(tmp_path, monkeypatch):
    """A fresh, empty live-mode installation. External adapters are disabled."""
    for name in (
        "CRT_ENABLED", "FEEDS_ENABLED", "ENRICH_ENABLED", "RENDER_ENABLED",
        "SEARCH_LIVE_ENABLED", "MAPS_LIVE_ENABLED", "SERPER_API_KEY",
        "GOOGLE_PLACES_API_KEY", "GEMINI_KEY", "GROQ_KEY", "AI_STATE",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = Settings(
        db_path=tmp_path / "daggers.db",
        evidence_dir=tmp_path / "evidence",
        gallery_dir=tmp_path / "gallery",
        web_dir=ROOT / "web",
        mode="live",
        environment="production",
        cors_origins=[],
        heartbeat_interval_s=1,
        crt_poll_interval_s=20,
        feed_poll_interval_s=20,
        pipeline_poll_interval_s=1,
        ai_state="template",
    )
    app = create_app(settings)
    with TestClient(app) as client:
        yield client, settings, app


@pytest.fixture
def insert_test_finding(api_env):
    """Insert one synthetic finding into the test-only SQLite DB on demand."""
    _, settings, app = api_env
    repo = app.state.runtime.repo

    def _insert(
        *,
        domain: str = "unit-test-malicious.example",
        verdict: str = "MALICIOUS",
        score: float = 0.91,
        reasons: list[str] | None = None,
        evidence: bool = False,
    ) -> dict:
        finding = repo.insert_finding(
            domain=domain,
            source="unit_test",
            score=score,
            verdict=verdict,
            reasons=reasons or ["unit-test-only deterministic signal"],
            clone_score=0.0,
            rendered=False,
        )
        if evidence:
            path = settings.evidence_dir / f"{finding['id']}.jpg"
            path.write_bytes(ONE_PIXEL_JPEG)
            finding = repo.set_finding_evidence(finding["id"], f"/evidence/{finding['id']}.jpg") or finding
        return finding

    return _insert


TEST_PASSWORD = "correct-horse-battery-1"


def login_as(client, app, role: str = "admin", username: str | None = None) -> str:
    """Create (if needed) and sign in a portal user; sets the CSRF header on the client."""
    from backend.app import security

    username = username or f"test-{role}"
    repo = app.state.runtime.repo
    if not repo.get_user(username):
        repo.create_user(username, security.hash_password(TEST_PASSWORD), role)
    response = client.post("/api/auth/login", json={"username": username, "password": TEST_PASSWORD})
    assert response.status_code == 200, response.text
    csrf = response.json()["csrf_token"]
    client.headers["X-CSRF-Token"] = csrf
    return csrf


@pytest.fixture
def admin_env(api_env):
    client, settings, app = api_env
    login_as(client, app, "admin")
    return client, settings, app
