from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.catalog import load_catalogs  # noqa: E402
from backend.app.config import Settings  # noqa: E402
from backend.app.main import create_app  # noqa: E402

SEED_DIR = Path(__file__).resolve().parents[1] / "seed"


@pytest.fixture(scope="session")
def catalog():
    return load_catalogs()


@pytest.fixture(scope="session")
def scoring_kwargs(catalog):
    return catalog.scoring_kwargs()


@pytest.fixture
def api_env(tmp_path):
    settings = Settings(
        db_path=tmp_path / "daggers.db",
        evidence_dir=tmp_path / "evidence",
        gallery_dir=tmp_path / "gallery",
        seed_dir=SEED_DIR,
        web_dir=tmp_path / "web",
        mode="demo",
        demo_mode=True,
        environment="demo",
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
