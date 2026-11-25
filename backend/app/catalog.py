from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

CORE_DIR = Path(__file__).resolve().with_name("core")


def _read_structured(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - JSON-compatible catalog is the fallback
            raise RuntimeError(f"Cannot read {path.name} without PyYAML") from exc
        return yaml.safe_load(text)


def _make_suffix_resolver() -> Callable[[str], str | None] | None:
    """Use tldextract's offline snapshot when present; never fetch a suffix list at runtime."""
    try:
        from tldextract import TLDExtract  # type: ignore[import-not-found]

        extractor = TLDExtract(suffix_list_urls=())
    except Exception:
        return None

    def resolve(host: str) -> str | None:
        try:
            extracted = extractor(host)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}".lower()
        except Exception:
            return None
        return None

    return resolve


@dataclass(frozen=True)
class Catalog:
    brands: tuple[dict, ...]
    lures: Mapping[str, tuple[str, ...]]
    suffix_resolver: Callable[[str], str | None] | None

    @property
    def official_domains(self) -> tuple[str, ...]:
        domains: list[str] = []
        for brand in self.brands:
            domains.append(str(brand["official_domain"]).lower())
            domains.extend(str(d).lower() for d in brand.get("official_domains", []))
        return tuple(dict.fromkeys(d for d in domains if d))

    @property
    def radar_terms(self) -> tuple[str, ...]:
        """High-signal CT/DNS terms. Short brand tokens are never emitted raw."""
        candidates: list[str] = []
        for brand in self.brands:
            official = str(brand["official_domain"]).strip().lower().rstrip(".")
            first = official.split(".", 1)[0]
            explicit = brand.get("radar_terms") or []
            generated = [first, str(brand["token"]).lower()]
            for alias in brand.get("aliases", []):
                generated.append("".join(ch for ch in str(alias).casefold() if ch.isalnum()))
            if first.startswith("bank") and len(first) > 4:
                generated.append(first[4:] + "bank")
            if first.endswith("bank") and len(first) > 4:
                generated.append("bank" + first[:-4])
            for term in [*explicit, *generated]:
                compact = "".join(ch for ch in str(term).casefold() if ch in "abcdefghijklmnopqrstuvwxyz0123456789")
                if len(compact) >= 4:
                    candidates.append(compact)
        return tuple(dict.fromkeys(candidates))

    @property
    def brand_tokens(self) -> tuple[str, ...]:
        tokens: list[str] = []
        for brand in self.brands:
            tokens.append(str(brand["token"]).lower())
            tokens.extend(str(alias).lower() for alias in brand.get("aliases", []))
        return tuple(dict.fromkeys(tokens))

    @property
    def lure_terms(self) -> tuple[str, ...]:
        terms: list[str] = []
        for group in self.lures.values():
            terms.extend(str(term).lower() for term in group)
        return tuple(dict.fromkeys(terms))

    def scoring_kwargs(self) -> dict:
        return {
            "brands": list(self.brands),
            "lures": {key: list(value) for key, value in self.lures.items()},
            "suffix_resolver": self.suffix_resolver,
        }


def load_catalogs(core_dir: Path | None = None) -> Catalog:
    core_dir = core_dir or CORE_DIR
    brands_raw = _read_structured(core_dir / "brands.yaml")
    lures_raw = _read_structured(core_dir / "lures.yaml")

    if not isinstance(brands_raw, list) or len(brands_raw) < 30:
        raise RuntimeError("brands.yaml must contain at least 30 brand records")
    if not isinstance(lures_raw, dict):
        raise RuntimeError("lures.yaml must be a mapping of language groups")

    brands: list[dict] = []
    for item in brands_raw:
        if not isinstance(item, dict) or not item.get("token") or not item.get("official_domain"):
            raise RuntimeError("Every brand needs token and official_domain")
        brands.append(
            {
                "token": str(item["token"]).lower(),
                "official_domain": str(item["official_domain"]).lower(),
                "official_domains": [str(d).lower() for d in item.get("official_domains", []) if str(d).strip()],
                "aliases": [str(alias).lower() for alias in item.get("aliases", [])],
                "radar_terms": [str(term).lower() for term in item.get("radar_terms", [])],
            }
        )

    lures = {
        str(group): tuple(str(term).lower() for term in terms)
        for group, terms in lures_raw.items()
        if isinstance(terms, list)
    }
    return Catalog(
        brands=tuple(brands),
        lures=lures,
        suffix_resolver=_make_suffix_resolver(),
    )
