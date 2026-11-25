"""Established-website rule (pure). Thresholds are data: core/rules.yaml → established_site.

Works on the plain dicts stored with a finding (``live_evidence`` + ``signals``), so the same decision
is made live and when stored findings are re-evaluated later (no re-fetching, nothing invented).
"""
from __future__ import annotations

from ..core.rules import rules
from ..intel import psl as psl_mod


def _cfg() -> dict:
    return rules()["established_site"]


def evaluate(live: dict | None, signals: list[dict], ws1_verdict: str, content_flags=(),
             *, host: str) -> tuple[dict | None, str]:
    """→ (established facts or None, reason it is / is not established)."""
    if not live:
        return None, "no live evidence (domain age / page) was gathered"
    cfg = _cfg()
    age = live.get("domain_age") or {}
    used = live.get("in_use_since") or {}
    page = live.get("page") or {}
    feeds = live.get("feeds") or {}
    # ---- age: registration first; in-use history only where the registry publishes no date
    basis, days, since = None, None, None
    if age.get("status") == "ok" and isinstance(age.get("age_days"), int):
        if age["age_days"] < int(cfg["min_registration_age_days"]):
            return None, f"domain registered {age['age_days']} day(s) ago — not established"
        basis, days, since = "registration (RDAP)", age["age_days"], age.get("registered_at")
    elif age.get("status") in set(cfg["rdap_statuses_allowing_in_use_history"]):
        if used.get("status") == "ok" and isinstance(used.get("age_days"), int):
            if used["age_days"] < int(cfg["min_in_use_days"]):
                return None, f"HTTPS in use for {used['age_days']} day(s) — not established"
            basis, days, since = "HTTPS in use (Certificate Transparency)", used["age_days"], used.get("first_seen")
        else:
            return None, "domain age unknown (no registration date, no certificate history)"
    else:
        return None, "domain age unknown"
    # ---- live HTTPS page on the same site
    if page.get("status") != "ok":
        return None, "the page could not be retrieved"
    hops = page.get("hops") or []
    if not hops or hops[-1].get("scheme") != "https":
        return None, "the page is not served over HTTPS"
    psl = psl_mod.default()
    final = page.get("final_host") or host
    if (psl.site(final) or final) != (psl.site(host) or host):
        return None, "the link redirects to another site"
    # ---- no threat-feed listing
    if feeds.get("url_listed") or feeds.get("host_listed"):
        return None, "listed in a threat feed"
    # ---- no warning sign at all (only structural ones allowed)
    allowed = set(cfg["allowed_signals"])
    blocking = [s for s in signals if float(s.get("weight") or 0) > 0 and str(s.get("name")) not in allowed]
    if blocking or ws1_verdict != "UNKNOWN" or content_flags:
        return None, "warning signs were found"
    facts = {"basis": basis, "age_days": days, "since": since, "years": days // 365, "final_host": final}
    return facts, (f"established website: {basis} {days // 365} year(s) (since {str(since)[:10]}), served over "
                   "HTTPS, no warning signs — not a government source")
