#!/usr/bin/env python3
"""Daggers hackathon demo seeder.

Populates the local SQLite DB with realistic, clearly-fake demo findings,
reports, sweep runs, and generated evidence images so the full demo story
can be shown without live adapters/keys.

This is for hackathon presentation only. It does NOT fake live adapter state;
it inserts data the same way the real pipeline would.

Usage:
    cd /home/user/daggers
    PYTHONPATH=. python ops/seed_demo.py          # seed if empty
    PYTHONPATH=. python ops/seed_demo.py --force   # clear findings/reports/sweeps and reseed
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.db.repo import Repository  # noqa: E402


def utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def make_evidence_image(path: Path, *, domain: str, verdict: str, score: float,
                        brand: str, real_domain: str, clone: int, reasons: list[str]) -> None:
    """Generate a simple but projector-friendly side-by-side evidence image."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception as exc:  # pragma: no cover
        print(f"  [warn] Pillow not available, skipping evidence image: {exc}")
        return

    W, H = 1280, 720
    img = Image.new("RGB", (W, H), "#F7F4EE")
    draw = ImageDraw.Draw(img)

    # fonts - fall back to default
    def font(size: int):
        for name in [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
        ]:
            if os.path.exists(name):
                try:
                    return ImageFont.truetype(name, size)
                except Exception:
                    pass
        return ImageFont.load_default()

    def bold(size: int):
        for name in [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]:
            if os.path.exists(name):
                try:
                    return ImageFont.truetype(name, size)
                except Exception:
                    pass
        return ImageFont.load_default()

    # header bar
    draw.rectangle([0, 0, W, 64], fill="#1A1A18")
    draw.text((28, 18), "DAGGERS  ·  EVIDENCE CAPTURE", fill="#F7F4EE", font=bold(24))
    verdict_color = "#DC2626" if verdict == "MALICIOUS" else "#D97706" if verdict == "SUSPICIOUS" else "#EA580C"
    tag_text = {"MALICIOUS": "FAKE", "SUSPICIOUS": "WARNING", "MISLEADING": "MISLEADING"}.get(verdict, verdict)
    draw.rectangle([W - 220, 12, W - 24, 52], fill=verdict_color)
    draw.text((W - 200, 20), tag_text, fill="#FFFFFF", font=bold(24))

    # panels
    pad = 24
    gap = 20
    panel_w = (W - pad * 2 - gap) // 2
    top = 88
    panel_h = 430

    # left: fake
    lx = pad
    draw.rectangle([lx, top, lx + panel_w, top + panel_h], fill="#FFFFFF", outline="#DC2626", width=3)
    draw.rectangle([lx, top, lx + panel_w, top + 44], fill="#FEE2E2")
    draw.text((lx + 14, top + 10), f"SUSPECT  ·  {domain}", fill="#991B1B", font=bold(20))
    # fake page mock
    draw.rectangle([lx + 16, top + 64, lx + panel_w - 16, top + 120], fill="#F3F4F6")
    draw.text((lx + 28, top + 80), brand.upper(), fill="#374151", font=bold(26))
    draw.text((lx + 28, top + 140), "Sign in to continue", fill="#111827", font=bold(28))
    draw.rectangle([lx + 28, top + 190, lx + panel_w - 28, top + 230], outline="#D1D5DB", width=2, fill="#FFFFFF")
    draw.text((lx + 40, top + 200), "Username / Email", fill="#9CA3AF", font=font(18))
    draw.rectangle([lx + 28, top + 246, lx + panel_w - 28, top + 286], outline="#D1D5DB", width=2, fill="#FFFFFF")
    draw.text((lx + 40, top + 256), "Password", fill="#9CA3AF", font=font(18))
    draw.rectangle([lx + 28, top + 310, lx + panel_w - 28, top + 356], fill="#DC2626")
    draw.text((lx + panel_w // 2 - 40, top + 322), "LOGIN", fill="#FFFFFF", font=bold(22))
    draw.text((lx + 28, top + 380), f"⚠ clone score: {clone}%", fill="#DC2626", font=bold(22))

    # right: real
    rx = lx + panel_w + gap
    draw.rectangle([rx, top, rx + panel_w, top + panel_h], fill="#FFFFFF", outline="#059669", width=3)
    draw.rectangle([rx, top, rx + panel_w, top + 44], fill="#D1FAE5")
    draw.text((rx + 14, top + 10), f"OFFICIAL  ·  {real_domain}", fill="#065F46", font=bold(20))
    draw.rectangle([rx + 16, top + 64, rx + panel_w - 16, top + 120], fill="#ECFDF5")
    draw.text((rx + 28, top + 80), brand.upper(), fill="#065F46", font=bold(26))
    draw.text((rx + 28, top + 140), "Welcome back", fill="#111827", font=bold(28))
    draw.rectangle([rx + 28, top + 190, rx + panel_w - 28, top + 230], outline="#D1D5DB", width=2, fill="#FFFFFF")
    draw.text((rx + 40, top + 200), "Email or username", fill="#9CA3AF", font=font(18))
    draw.rectangle([rx + 28, top + 246, rx + panel_w - 28, top + 286], outline="#D1D5DB", width=2, fill="#FFFFFF")
    draw.text((rx + 40, top + 256), "Password", fill="#9CA3AF", font=font(18))
    draw.rectangle([rx + 28, top + 310, rx + panel_w - 28, top + 356], fill="#059669")
    draw.text((rx + panel_w // 2 - 50, top + 322), "Sign in", fill="#FFFFFF", font=bold(22))
    draw.text((rx + 28, top + 380), "✓ verified official domain", fill="#059669", font=bold(22))

    # bottom reasons strip
    by = top + panel_h + 20
    draw.rectangle([pad, by, W - pad, H - 24], fill="#FFFFFF", outline="#E5E7EB", width=2)
    draw.text((pad + 16, by + 14), f"Score {score:.2f}  ·  {len(reasons)} signals", fill="#111827", font=bold(22))
    reason_text = "  |  ".join(reasons[:4])
    if len(reason_text) > 110:
        reason_text = reason_text[:107] + "..."
    draw.text((pad + 16, by + 52), reason_text, fill="#374151", font=font(18))

    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, "JPEG", quality=92)


def seed(force: bool = False) -> None:
    settings = Settings.from_env()
    repo = Repository(settings)
    repo.initialize()

    existing = repo.counts().get("findings", 0)
    if existing and not force:
        print(f"DB already has {existing} findings. Use --force to reseed demo data.")
        return

    if force:
        with repo._lock, repo.conn:
            repo.conn.execute("DELETE FROM sweep_results")
            repo.conn.execute("DELETE FROM sweep_runs")
            repo.conn.execute("DELETE FROM reports")
            repo.conn.execute("DELETE FROM findings")
            repo.conn.execute("DELETE FROM domains")
            repo.conn.execute("DELETE FROM guard_hits")
            repo.conn.execute("DELETE FROM feed_labels")
            repo.conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('domains','findings','reports','sweep_runs','sweep_results')")
        # clean old evidence
        for f in settings.evidence_dir.glob("*.jpg"):
            try:
                f.unlink()
            except Exception:
                pass
        print("Cleared existing demo data.")

    now = datetime.now(timezone.utc)

    findings_data = [
        {
            "domain": "adcb-secure-login.xyz",
            "verdict": "MALICIOUS",
            "score": 0.93,
            "reasons": [
                "brand typo/name 'adcb' (distance 0) outside adcb.ae",
                "risky low-cost TLD .xyz",
                "TLS certificate issued 42 minutes ago",
                "form posts to foreign host",
                "visual clone 97% match to adcb.ae/login",
            ],
            "source": "crt.sh",
            "brand": "ADCB",
            "real_domain": "adcb.com",
            "clone": 97,
            "gallery_match": "adcb.com/login",
            "age_minutes": 42,
        },
        {
            "domain": "enbd-verification-ae.com",
            "verdict": "MALICIOUS",
            "score": 0.91,
            "reasons": [
                "brand typo/name 'emirates nbd' outside official domain",
                "recently registered domain (2 days)",
                "lure keyword 'verification' in domain",
                "form posts to foreign host",
                "visual clone 94% match to emiratesnbd.com",
            ],
            "source": "crt.sh",
            "brand": "Emirates NBD",
            "real_domain": "emiratesnbd.com",
            "clone": 94,
            "gallery_match": "emiratesnbd.com/login",
            "age_minutes": 60 * 48,
        },
        {
            "domain": "xn--mazon-3ve.ae",
            "verdict": "MALICIOUS",
            "score": 0.96,
            "reasons": [
                "mixed-script IDN / confusable brand spoof of amazon.ae",
                "punycode xn-- domain",
                "brand exact-fold match outside official domain",
                "TLS certificate issued 3 hours ago",
            ],
            "source": "crt.sh",
            "brand": "Amazon",
            "real_domain": "amazon.ae",
            "clone": 88,
            "gallery_match": "amazon.ae/login",
            "age_minutes": 180,
        },
        {
            "domain": "adnoc-ae-prize.xyz",
            "verdict": "MISLEADING",
            "score": 0.72,
            "reasons": [
                "giveaway/prize lure targeting 'ADNOC'",
                "claim not found on official adnoc.ae domain",
                "risky low-cost TLD .xyz",
                "recently registered domain",
            ],
            "source": "feeds",
            "brand": "ADNOC",
            "real_domain": "adnoc.ae",
            "clone": 0,
            "gallery_match": None,
            "age_minutes": 60 * 24,
        },
        {
            "domain": "etisalat-bill-payment-secure.top",
            "verdict": "MALICIOUS",
            "score": 0.89,
            "reasons": [
                "brand token 'etisalat' outside official domain",
                "risky TLD .top",
                "lure keywords 'bill payment secure'",
                "TLS certificate issued 6 hours ago",
            ],
            "source": "crt.sh",
            "brand": "Etisalat",
            "real_domain": "etisalat.ae",
            "clone": 91,
            "gallery_match": "etisalat.ae/login",
            "age_minutes": 360,
        },
        {
            "domain": "uae-pass-verify.net",
            "verdict": "SUSPICIOUS",
            "score": 0.58,
            "reasons": [
                "brand token 'uae pass' outside official domain",
                "lure keyword 'verify'",
                "recently registered domain (5 days)",
            ],
            "source": "crt.sh",
            "brand": "UAE PASS",
            "real_domain": "uaepass.ae",
            "clone": 0,
            "gallery_match": None,
            "age_minutes": 60 * 24 * 5,
        },
        {
            "domain": "dubai-police-fine-check.info",
            "verdict": "MISLEADING",
            "score": 0.67,
            "reasons": [
                "impersonates government entity 'Dubai Police'",
                "claim/payment lure outside official domain",
                "risky TLD .info",
            ],
            "source": "feeds",
            "brand": "Dubai Police",
            "real_domain": "dubaipolice.gov.ae",
            "clone": 0,
            "gallery_match": None,
            "age_minutes": 60 * 72,
        },
        {
            "domain": "aramex-redelivery-ae.click",
            "verdict": "MALICIOUS",
            "score": 0.87,
            "reasons": [
                "brand token 'aramex' outside official domain",
                "delivery lure 'redelivery'",
                "risky TLD .click",
                "confirmed by phishing feed",
            ],
            "source": "openphish",
            "brand": "Aramex",
            "real_domain": "aramex.com",
            "clone": 0,
            "gallery_match": None,
            "age_minutes": 90,
        },
    ]

    created_findings = []
    for i, item in enumerate(findings_data):
        created_at = now - timedelta(minutes=max(5, 240 - i * 25))
        first_seen = created_at - timedelta(minutes=2)
        cert_issued = now - timedelta(minutes=item["age_minutes"])
        domain_id = repo.upsert_domain(
            item["domain"],
            source=item["source"],
            first_seen=utc(first_seen),
            tls_issued=utc(cert_issued),
            enqueued=True,
        )
        _ = domain_id
        finding = repo.insert_finding(
            domain=item["domain"],
            score=item["score"],
            verdict=item["verdict"],
            reasons=item["reasons"],
            source=item["source"],
            first_seen=utc(first_seen),
            cert_issued=utc(cert_issued),
            created_at=utc(created_at),
            clone_score=float(item["clone"]) if item["clone"] else None,
            gallery_match=item["gallery_match"],
            is_case_file=item["verdict"] == "MALICIOUS" and (item["clone"] >= 90 or item["source"] in ("openphish", "feeds")),
        )
        fid = finding["id"]
        # evidence image for high-signal findings
        if item["verdict"] in ("MALICIOUS", "MISLEADING") or item["clone"] > 0:
            rel = f"/evidence/{fid}.jpg"
            abs_path = settings.evidence_dir / f"{fid}.jpg"
            make_evidence_image(
                abs_path,
                domain=item["domain"],
                verdict=item["verdict"],
                score=item["score"],
                brand=item["brand"],
                real_domain=item["real_domain"],
                clone=int(item["clone"]),
                reasons=item["reasons"],
            )
            if abs_path.exists():
                finding = repo.set_finding_evidence(fid, rel) or finding
        # feed label for confirmed
        if item["source"] in ("openphish", "feeds"):
            with repo._lock, repo.conn:
                repo.conn.execute(
                    "INSERT OR REPLACE INTO feed_labels(domain, source, confirmed, updated_at) VALUES(?, ?, 1, ?)",
                    (item["domain"], item["source"], utc(now)),
                )
        created_findings.append((item, finding))
        print(f"  finding #{finding['id']:>2} {finding['verdict']:<11} {finding['domain']}")

    # Reports: file a few
    report_specs = [
        # (finding domain, status, auto, blocked_hits)
        ("adcb-secure-login.xyz", "SUBMITTED", True, 47),
        ("enbd-verification-ae.com", "SUBMITTED", True, 23),
        ("xn--mazon-3ve.ae", "QUEUED", True, 12),
        ("etisalat-bill-payment-secure.top", "SEEN", False, 31),
        ("aramex-redelivery-ae.click", "QUEUED", True, 8),
    ]
    for domain, status, auto, hits in report_specs:
        match = next((f for _, f in created_findings if f["domain"] == domain), None)
        if not match:
            continue
        filed_at = utc(now - timedelta(minutes=30)) if status in ("SUBMITTED", "SEEN") else None
        report = repo.insert_report(
            finding_id=match["id"],
            evidence=match,
            status=status,
            auto=auto,
            filed_at=filed_at,
            blocked_hits=hits,
        )
        print(f"  report  #{report['id']:>2} {report['status']:<10} {domain}  hits={hits}")

    # Guard hits
    for domain, count in [
        ("adcb-secure-login.xyz", 47),
        ("enbd-verification-ae.com", 23),
        ("etisalat-bill-payment-secure.top", 31),
        ("xn--mazon-3ve.ae", 12),
        ("aramex-redelivery-ae.click", 8),
    ]:
        for _ in range(count):
            repo.record_guard_hit(domain)

    # Sweep runs (web + maps) for demo
    web_run = repo.create_sweep_run(
        query="ADCB customer care UAE", lang="en", channel="web", engine="demo-seed", cached=True,
    )
    def _web(url, title, snippet, verdict, score, reasons, tag, finding_id=None):
        return {
            "position": 0, "url": url, "title": title, "snippet": snippet,
            "verdict": verdict, "score": score, "reasons": reasons, "finding_id": finding_id,
            "tag": tag, "manual_review": tag in ("WARNING", "MISLEADING"),
            "domain_auth": "official" if tag == "SAFE" else ("lookalike" if tag == "FAKE" else "unknown"),
            "gov_verification": None, "trust_reasons": reasons[:1],
            "blockable": tag == "FAKE", "source_kind": "demo", "maps": None,
        }

    repo.add_sweep_results(web_run["id"], [
        _web("https://www.adcb.com/en/personal/support", "ADCB Customer Support | Official",
             "Contact ADCB through official channels. Call 600 50 2030.",
             "UNKNOWN", 0.02, ["official domain adcb.com"], "SAFE"),
        _web("https://adcb-secure-login.xyz/login", "ADCB Secure Login - Verify Account",
             "Verify your ADCB account now to avoid suspension.",
             "MALICIOUS", 0.93, ["brand impersonation of ADCB", "risky TLD .xyz", "TLS cert < 1 hour old"], "FAKE"),
        _web("https://www.adcb.com/en/personal/ways-to-bank/mobile-banking", "ADCB Mobile Banking",
             "Download the ADCB Mobile Banking app.",
             "UNKNOWN", 0.01, ["official domain adcb.com"], "SAFE"),
        _web("https://adcb-helpdesk-support.com/contact", "ADCB Helpdesk Support 24/7",
             "Get immediate ADCB support. Enter your card details to verify.",
             "MALICIOUS", 0.88, ["brand token 'adcb' outside official domain", "lure: 'enter your card details'"], "FAKE"),
        _web("https://en.wikipedia.org/wiki/Abu_Dhabi_Commercial_Bank", "Abu Dhabi Commercial Bank - Wikipedia",
             "ADCB is a bank in the UAE...",
             "UNKNOWN", 0.0, ["known reference domain"], "SAFE"),
    ])
    # attach finding ids where we have them
    with repo._lock, repo.conn:
        for dom, fid in [(f["domain"], f["id"]) for _, f in created_findings]:
            repo.conn.execute(
                "UPDATE sweep_results SET finding_id = ? WHERE run_id = ? AND url LIKE ?",
                (fid, web_run["id"], f"%{dom}%"),
            )

    def _maps(position, title, snippet, verdict, score, reasons, tag, listing, finding_id=None):
        return {
            "position": position,
            "url": listing.get("website") or f"maps:demo:{position}",
            "title": title, "snippet": snippet, "verdict": verdict, "score": score,
            "reasons": reasons, "finding_id": finding_id,
            "tag": tag, "manual_review": tag in ("WARNING", "MISLEADING"),
            "domain_auth": "official" if tag == "SAFE" else ("lookalike" if tag == "FAKE" else "unknown"),
            "gov_verification": None, "trust_reasons": reasons[:1],
            "blockable": tag == "FAKE", "source_kind": "demo",
            "maps": {"listing": listing, "checks": {"website": {"verdict": verdict, "score": score}, "phone": {"verdict": "UNKNOWN", "score": 0.0}}},
        }

    maps_run = repo.create_sweep_run(
        query="ADCB branch Abu Dhabi", lang="en", channel="maps", engine="demo-seed", cached=True,
    )
    repo.add_sweep_results(maps_run["id"], [
        _maps(1, "ADCB Head Office Branch", "Official ADCB branch · Sheikh Zayed St",
              "UNKNOWN", 0.01, ["matches official listing"], "SAFE",
              {"phone": "+971 600 50 2030", "website": "https://www.adcb.com"}),
        _maps(2, "ADCB Customer Care Center", "24/7 support line · Claims to be ADCB",
              "MALICIOUS", 0.91, ["listing phone not on official domain", "website is a clone"], "FAKE",
              {"phone": "+971 52 000 0000", "website": "https://adcb-secure-login.xyz"}),
        _maps(3, "ADCB ATM - Khalidiya Mall", "ATM · Official location",
              "UNKNOWN", 0.0, ["official listing"], "SAFE",
              {"phone": "+971 600 50 2030", "website": "https://www.adcb.com"}),
    ])
    with repo._lock, repo.conn:
        repo.conn.execute(
            "UPDATE sweep_results SET finding_id = ? WHERE run_id = ? AND url LIKE ?",
            (next(f["id"] for _, f in created_findings if f["domain"] == "adcb-secure-login.xyz"), maps_run["id"], "%cid=222%"),
        )

    repo.close()

    print()
    print(f"Seeded {len(created_findings)} findings, {len(report_specs)} reports, 2 sweep runs.")
    print(f"DB: {settings.db_path}")
    print(f"Evidence: {settings.evidence_dir}")
    print()
    print("Start the app:  make dev")
    print("Open:           http://localhost:8000/#/feed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed Daggers with hackathon demo data")
    parser.add_argument("--force", action="store_true", help="Clear existing demo data and reseed")
    args = parser.parse_args()
    seed(force=args.force)
