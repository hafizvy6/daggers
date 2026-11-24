"""Shared helpers for WS2 tests. Everything here is SYNTHETIC TEST FIXTURE data."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.catalog import load_catalogs  # noqa: E402
from backend.app.channels.official.extract import Lexicon  # noqa: E402
from backend.app.channels.official.models import OfficialRecord  # noqa: E402
from backend.app.channels.official.registry import Registry  # noqa: E402
from backend.app.channels.scoring import ShieldScorer  # noqa: E402

OFFICIAL_FIXTURES = ROOT / "backend" / "app" / "channels" / "official" / "fixtures"
CHANNEL_FIXTURES = ROOT / "backend" / "app" / "channels" / "fixtures"
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)

_CATALOG = None


def catalog():
    global _CATALOG
    if _CATALOG is None:
        _CATALOG = load_catalogs()
    return _CATALOG


def synthetic_registry() -> Registry:
    return Registry.load(OFFICIAL_FIXTURES / "synthetic_registry.yaml", allow_synthetic=True)


def lexicon() -> Lexicon:
    return Lexicon.load()


def synthetic_records(exclude: tuple[str, ...] = ()) -> list[OfficialRecord]:
    payload = json.loads((OFFICIAL_FIXTURES / "synthetic_records.json").read_text(encoding="utf-8"))
    return [OfficialRecord.from_dict(r) for r in payload["records"] if r["record_id"] not in exclude]


def scorer(records: list[OfficialRecord] | None = None, registry: Registry | None = None) -> ShieldScorer:
    recs = synthetic_records() if records is None else records
    return ShieldScorer(
        catalog=catalog(),
        registry=registry or synthetic_registry(),
        lexicon=lexicon(),
        record_provider=lambda entries: [r for r in recs if r.entry_id in {e.id for e in entries}],
        clock=lambda: NOW,
    )


def models_now():
    """Real wall-clock time (approvals made by the CLI are stamped with it)."""
    from backend.app.channels.official.models import utc_now

    return utc_now()
