#!/usr/bin/env python3
"""Offline labeled evaluation for the Radar candidate gate and risk scorer.

This is an internal regression/evaluation harness, not a claim of real-world
accuracy. Add labeled cases from analyst decisions, phishing feeds, and brand-owner
reports. Use --json for machine-readable output.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.catalog import load_catalogs
from backend.app.core import scorer
from backend.app.radar.candidates import admit_candidate

CASES = Path(__file__).with_name("evaluation") / "radar_cases.json"


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return round(precision, 4), round(recall, 4), round(f1, 4)


def evaluate() -> dict:
    catalog = load_catalogs()
    kwargs = catalog.scoring_kwargs()
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    rows = []
    candidate_tp = candidate_fp = candidate_fn = candidate_tn = 0
    risk_tp = risk_fp = risk_fn = risk_tn = 0

    for case in cases:
        domain = str(case["domain"])
        admission = admit_candidate(domain, catalog.radar_terms, catalog.official_domains)
        result = scorer.score_request("url", f"https://{domain}/", "en", **kwargs)
        predicted_admit = bool(admission["admitted"])
        predicted_risk = result["verdict"] != "UNKNOWN"
        expected_admit = bool(case["expected_admit"])
        expected_risk = bool(case["expected_risk"])

        candidate_tp += predicted_admit and expected_admit
        candidate_fp += predicted_admit and not expected_admit
        candidate_fn += not predicted_admit and expected_admit
        candidate_tn += not predicted_admit and not expected_admit
        risk_tp += predicted_risk and expected_risk
        risk_fp += predicted_risk and not expected_risk
        risk_fn += not predicted_risk and expected_risk
        risk_tn += not predicted_risk and not expected_risk
        rows.append({
            "domain": domain,
            "category": case["category"],
            "admit": admission,
            "verdict": result["verdict"],
            "score": result["score"],
            "expected_admit": expected_admit,
            "expected_risk": expected_risk,
        })

    candidate_precision, candidate_recall, candidate_f1 = prf(candidate_tp, candidate_fp, candidate_fn)
    risk_precision, risk_recall, risk_f1 = prf(risk_tp, risk_fp, risk_fn)
    return {
        "cases": len(rows),
        "candidate": {
            "tp": int(candidate_tp), "fp": int(candidate_fp), "fn": int(candidate_fn), "tn": int(candidate_tn),
            "precision": candidate_precision, "recall": candidate_recall, "f1": candidate_f1,
        },
        "offline_risk": {
            "tp": int(risk_tp), "fp": int(risk_fp), "fn": int(risk_fn), "tn": int(risk_tn),
            "precision": risk_precision, "recall": risk_recall, "f1": risk_f1,
        },
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args()
    report = evaluate()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    print(f"cases: {report['cases']}")
    for name in ("candidate", "offline_risk"):
        metrics = report[name]
        print(
            f"{name}: precision={metrics['precision']:.2f} recall={metrics['recall']:.2f} "
            f"f1={metrics['f1']:.2f} (tp={metrics['tp']} fp={metrics['fp']} "
            f"fn={metrics['fn']} tn={metrics['tn']})"
        )
    misses = [row for row in report["rows"] if row["admit"]["admitted"] != row["expected_admit"]]
    print(f"candidate misses: {len(misses)}")
    for row in misses:
        print(f"  {row['domain']:34} admitted={row['admit']['admitted']} expected={row['expected_admit']} {row['category']}")
    print("Note: offline_risk uses the deterministic scorer only; live CT/feed/clone evidence is not simulated here.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
