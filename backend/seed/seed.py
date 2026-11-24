from __future__ import annotations

import argparse
import json

from backend.app.catalog import load_catalogs
from backend.app.config import Settings
from backend.app.db.repo import Repository
from backend.app.vision.gallery import generate_gallery_images


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed the Daggers WS1 database and offline evidence assets")
    parser.add_argument("--seed-only", action="store_true", help="seed database/evidence without changing the committed gallery index")
    parser.add_argument("--force", action="store_true", help="re-run idempotent seed inserts")
    parser.add_argument("--gallery", action="store_true", help="generate the 60 runtime gallery reference shots")
    parser.add_argument("--gallery-index", action="store_true", help="regenerate the committed gallery_index.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = Settings.from_env()
    repo = Repository(settings)
    repo.initialize()
    result = repo.seed(force=args.force)
    cases_path = settings.seed_dir / "casefiles" / "cases.json"
    result["casefiles"] = len(json.loads(cases_path.read_text(encoding="utf-8"))) if cases_path.exists() else 0
    settings.gallery_dir.mkdir(parents=True, exist_ok=True)
    existing_shots = list(settings.gallery_dir.glob("*.jpg"))
    if args.gallery or args.gallery_index or len(existing_shots) < 60:
        catalog = load_catalogs()
        runtime_index = settings.gallery_dir / "gallery_index.json"
        entries = generate_gallery_images(catalog.brands[:30], settings.gallery_dir, runtime_index, count=30)
        if args.gallery_index:
            committed = settings.seed_dir / "gallery_index.json"
            committed.write_text(json.dumps(entries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result["gallery"] = len(entries)
    repo.close()
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
