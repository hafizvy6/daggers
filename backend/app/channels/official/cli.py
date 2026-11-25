"""Registry administration CLI.

    python -m backend.app.channels.official.cli list [--status pending]
    python -m backend.app.channels.official.cli show <id>
    python -m backend.app.channels.official.cli validate
    python -m backend.app.channels.official.cli approve <id> [--reviewer NAME]
    python -m backend.app.channels.official.cli revoke <id> --reason TEXT
    python -m backend.app.channels.official.cli authenticate <url>
    python -m backend.app.channels.official.cli verify "<claim text>" [--records FILE]
    python -m backend.app.channels.official.cli discover --html FILE --source-url URL [--write]
    python -m backend.app.channels.official.cli fetch <id>           # live; approved entries only

Approval is a human act: the reviewer must have confirmed the domains, class,
jurisdiction and authority scope against the entity's own official channels.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .discover import candidates_to_entries, merge_candidates, parse_directory
from .extract import Lexicon
from .models import OfficialRecord, utc_now
from .registry import DEFAULT_REGISTRY_PATH, Registry, RegistryError, validate_entries, write_registry_atomic
from .snapshots import SnapshotStore
from .verify import verify_claim


def _load(args) -> Registry:
    return Registry.load(args.registry, allow_synthetic=args.allow_synthetic)


def cmd_list(args) -> int:
    registry = _load(args)
    now = utc_now()
    for entry in registry.entries:
        if args.status and entry.status != args.status:
            continue
        trusted = "trusted" if entry.is_trusted(now) else "untrusted"
        print(f"{entry.id:28} {entry.status:9} {trusted:9} class={entry.source_class} "
              f"{entry.jurisdiction:15} {','.join(entry.domains)}")
    print(f"# registry version {registry.version}")
    return 0


def cmd_show(args) -> int:
    entry = _load(args).by_id.get(args.id)
    if not entry:
        print(f"unknown id {args.id}", file=sys.stderr)
        return 2
    print(json.dumps(entry.as_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_validate(args) -> int:
    path = Path(args.registry or DEFAULT_REGISTRY_PATH)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    report = validate_entries(data.get("entries") or [], allow_synthetic=args.allow_synthetic)
    for warning in report.warnings:
        print(f"WARNING {warning}")
    for error in report.errors:
        print(f"ERROR   {error}")
    print("OK" if report.ok else f"{len(report.errors)} error(s)")
    return 0 if report.ok else 1


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        return input(f"{prompt} Type 'yes' to continue: ").strip().lower() == "yes"
    except EOFError:
        return False


def cmd_approve(args) -> int:
    registry = _load(args)
    entry = registry.by_id.get(args.id)
    if not entry:
        print(f"unknown id {args.id}", file=sys.stderr)
        return 2
    print(json.dumps({k: v for k, v in entry.as_dict().items() if k in (
        "id", "organization", "domains", "subdomain_policy", "allowed_subdomains", "source_class",
        "jurisdiction", "authority_scope", "source_urls", "provenance")}, ensure_ascii=False, indent=2))
    if not _confirm(
        f"Approve '{entry.id}'? You confirm you verified these domains, "
        "class, jurisdiction and scope against the entity's own official channels.",
        args.yes,
    ):
        print("aborted")
        return 1
    try:
        data = registry.approved_mapping(args.id, args.reviewer, utc_now())
        write_registry_atomic(registry.path or DEFAULT_REGISTRY_PATH, data, allow_synthetic=args.allow_synthetic)
    except RegistryError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"approved {args.id}")
    return 0


def cmd_approve_verified(args) -> int:
    """Approve every PENDING entry whose provenance records a completed verification
    ('verified <date>: <evidence>'). The list comes from the registry's own data, not from code.
    Entries marked 'partially checked' (or without evidence) are left pending."""
    registry = _load(args)
    ids = [e.id for e in registry.entries if e.status == "pending"
           and str(e.provenance or "").strip().lower().startswith("verified ")]
    if not ids:
        print("no pending entries with recorded verification evidence")
        return 0
    for entry_id in ids:
        entry = registry.by_id[entry_id]
        print(f"- {entry_id}: {', '.join(entry.domains)} ({entry.source_class}) — {entry.provenance[:160]}")
    if not _confirm(f"Approve these {len(ids)} entries? You confirm you checked the "
                    "evidence above.", args.yes):
        print("aborted")
        return 1
    try:
        for entry_id in ids:
            data = registry.approved_mapping(entry_id, args.reviewer, utc_now())
            registry = write_registry_atomic(registry.path or DEFAULT_REGISTRY_PATH, data,
                                             allow_synthetic=args.allow_synthetic)
    except RegistryError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"approved {len(ids)} entries")
    return 0


def cmd_revoke(args) -> int:
    registry = _load(args)
    try:
        data = registry.revoked_mapping(args.id, args.reviewer, args.reason, utc_now())
        write_registry_atomic(registry.path or DEFAULT_REGISTRY_PATH, data, allow_synthetic=args.allow_synthetic)
    except RegistryError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    print(f"revoked {args.id}")
    return 0


def cmd_authenticate(args) -> int:
    print(json.dumps(_load(args).authenticate(args.url, utc_now()).as_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_verify(args) -> int:
    registry = _load(args)
    records: list[OfficialRecord] = []
    if args.records:
        payload = json.loads(Path(args.records).read_text(encoding="utf-8"))
        records = [OfficialRecord.from_dict(item) for item in payload.get("records", payload)]
    elif args.snapshots:
        records = SnapshotStore(args.snapshots).latest_records(e.id for e in registry.entries)
    result = verify_claim(args.text, registry=registry, lexicon=Lexicon.load(), records=records, now=utc_now())
    print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    return 0


def cmd_discover(args) -> int:
    html = Path(args.html).read_text(encoding="utf-8")
    candidates = parse_directory(html)
    entries = candidates_to_entries(candidates, source_url=args.source_url, discovered_at=utc_now())
    path = Path(args.registry or DEFAULT_REGISTRY_PATH)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    merged, added, skipped = merge_candidates(data, entries)
    print(f"parsed {len(candidates)} candidate(s); new pending: {len(added)}; already present: {len(skipped)}")
    for entry_id in added:
        print(f"  + {entry_id} (pending)")
    if args.write and added:
        try:
            write_registry_atomic(path, merged, allow_synthetic=args.allow_synthetic)
        except RegistryError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 1
        print("registry updated (all new entries are pending)")
    elif added:
        print("dry run — re-run with --write to add them as pending")
    return 0


def cmd_fetch(args) -> int:  # pragma: no cover - live network
    from .fetch import SecureFetcher

    registry = _load(args)
    store = SnapshotStore(args.snapshots)
    fetcher = SecureFetcher(registry)
    for record in fetcher.fetch_records(args.id):
        row = store.record(record)
        print(json.dumps(row, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="official-registry", description=__doc__.split("\n\n")[0])
    parser.add_argument("--registry", help="registry YAML (default: channels/official/registry.yaml)")
    parser.add_argument("--allow-synthetic", action="store_true", help="allow SYNTHETIC test entries")
    parser.add_argument("--snapshots", help="snapshot store directory")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("list"); p.add_argument("--status", choices=["pending", "approved", "revoked"]); p.set_defaults(func=cmd_list)
    p = sub.add_parser("show"); p.add_argument("id"); p.set_defaults(func=cmd_show)
    p = sub.add_parser("validate"); p.set_defaults(func=cmd_validate)
    p = sub.add_parser("approve"); p.add_argument("id"); p.add_argument("--reviewer", default=None, help="optional")
    p.add_argument("--yes", action="store_true", help="skip the interactive confirmation"); p.set_defaults(func=cmd_approve)
    p = sub.add_parser("approve-verified", help="approve every pending entry whose provenance records a verification")
    p.add_argument("--reviewer", default=None, help="optional")
    p.add_argument("--yes", action="store_true", help="skip the interactive confirmation")
    p.set_defaults(func=cmd_approve_verified)
    p = sub.add_parser("revoke"); p.add_argument("id"); p.add_argument("--reviewer", default=None, help="optional")
    p.add_argument("--reason", required=True); p.set_defaults(func=cmd_revoke)
    p = sub.add_parser("authenticate"); p.add_argument("url"); p.set_defaults(func=cmd_authenticate)
    p = sub.add_parser("verify"); p.add_argument("text"); p.add_argument("--records"); p.set_defaults(func=cmd_verify)
    p = sub.add_parser("discover"); p.add_argument("--html", required=True); p.add_argument("--source-url", required=True)
    p.add_argument("--write", action="store_true"); p.set_defaults(func=cmd_discover)
    p = sub.add_parser("fetch"); p.add_argument("id"); p.set_defaults(func=cmd_fetch)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RegistryError, FileNotFoundError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
