"""Shared WS2 unit-test doubles. None of this data is reachable from the product runtime."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.catalog import load_catalogs  # noqa: E402
from backend.app.channels import urls  # noqa: E402
from backend.app.channels.maps import Listing  # noqa: E402
from backend.app.channels.official.extract import Lexicon  # noqa: E402
from backend.app.channels.official.models import OfficialRecord  # noqa: E402
from backend.app.channels.official.registry import Registry  # noqa: E402
from backend.app.channels.scoring import ShieldScorer  # noqa: E402
from backend.app.channels.search import RawResult  # noqa: E402

DATA_DIR = Path(__file__).resolve().with_name("data")
# Backwards-compatible aliases for older unit tests; all point under tests/.
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)

_CATALOG = None


def catalog():
    global _CATALOG
    if _CATALOG is None:
        _CATALOG = load_catalogs()
    return _CATALOG


def synthetic_registry() -> Registry:
    """Load a unit-test-only registry; production default never permits synthetic entries."""
    return Registry.load(DATA_DIR / "official_registry.yaml", allow_synthetic=True)


def lexicon() -> Lexicon:
    return Lexicon.load()


def synthetic_records(exclude: tuple[str, ...] = ()) -> list[OfficialRecord]:
    payload = json.loads((DATA_DIR / "official_records.json").read_text(encoding="utf-8"))
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


class TestSearchProvider:
    """Unit-test double that replays synthetic results from backend/tests/ws2/data."""

    name, source_kind = "unit_test", "fixture"

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DATA_DIR / "search_results.json"

    def search(self, query: str, lang: str, limit: int) -> list[RawResult]:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        key = urls.normalize_query(query).casefold()
        bucket = payload["queries"].get(key) or payload["queries"]["_default"]
        return [RawResult(r["url"], r.get("title", ""), r.get("snippet", "")) for r in bucket[:limit]]


class TestMapsProvider:
    """Unit-test double that replays synthetic listings from backend/tests/ws2/data."""

    name, source_kind = "unit_test_maps", "fixture"

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DATA_DIR / "maps_listings.json"

    def search(self, query: str, lang: str, limit: int) -> list[Listing]:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        key = urls.normalize_query(query).casefold()
        bucket = payload["queries"].get(key) or payload["queries"]["_default"]
        return [
            Listing(
                "unit_test_maps",
                item["place_id"],
                item["name"],
                item.get("address", ""),
                item.get("website"),
                item.get("phone"),
                item.get("category", ""),
                item.get("business_status", ""),
                synthetic=True,
                source_kind="fixture",
            )
            for item in bucket[:limit]
        ]


def models_now():
    """Real wall-clock time (approvals made by the CLI are stamped with it)."""
    from backend.app.channels.official.models import utc_now

    return utc_now()
