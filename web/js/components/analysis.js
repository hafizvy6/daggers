/* Daggers · analysis — the ONE renderer for a stored finding's full analysis.
   Used by the Checker result and by the Police Portal finding page, so both
   always show exactly the same verdict, signals and evidence for the same finding.
   Every value shown comes from the backend; nothing is computed or invented here. */
import { t, hasKey, fmtDateTime } from "../i18n/i18n.js";
import { tagFor } from "../api.js";
import { el, tagChip } from "./tag.js";

const CATEGORY_ORDER = [
  "government_impersonation", "brand_impersonation", "homograph", "phishing", "known_phishing",
  "fraudulent_offer", "suspicious_message", "suspicious_url", "suspicious_infrastructure", "other",
];

const label = (key, fallback) => (hasKey(key) ? t(key) : fallback);

function section(title, kicker, ...body) {
  const s = el("section", { class: "card" });
  s.append(el("div", { class: "card-title" }, el("span", { text: title }),
    kicker ? el("span", { class: "card-kicker", text: kicker }) : null));
  body.filter(Boolean).forEach((b) => s.append(b));
  return s;
}

function kvList(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const p of pairs) {
    if (!p) continue;
    const [k, v] = p;
    if (v === null || v === undefined || v === "") continue;
    dl.append(el("dt", { text: k }), typeof v === "object" ? el("dd", {}, v) : el("dd", { text: String(v) }));
  }
  return dl;
}

const ltrSpan = (text, cls = "ltr mono") => el("span", { class: cls, dir: "ltr", text });

/* ---------------- summary ---------------------------------------- */
export function summaryCard(f) {
  const tagKey = tagFor(f);
  const head = el("div", { class: "verdict-hero" },
    tagChip(tagKey, { size: "xl" }),
    el("div", { class: "vh-body" },
      el("p", { class: "vh-why", text: t(tagKey === "safe" && f.domain_auth && f.domain_auth.status === "ESTABLISHED_SITE"
        ? "analysis.tagBody_safe_established"
        : tagKey === "safe" && f.domain_auth && f.domain_auth.status === "REPUTABLE_SITE"
        ? "analysis.tagBody_safe_popular"
        : tagKey === "safe" && f.domain_auth && f.domain_auth.legitimate_site
          ? "analysis.tagBody_safe_site" : `analysis.tagBody_${tagKey}`) }),
      f.manual_review ? el("span", { class: "chip", text: t("trust.manualReview") }) : null));
  const score = typeof f.risk_score === "number" ? f.risk_score : f.score;
  const pct = Math.round((score || 0) * 100);
  const bar = el("div", { class: "score-bar", style: "min-width:200px" },
    el("div", { class: "track" }, el("div", { class: `fill fill-${tagKey}`, style: `--w:${pct}%` })),
    el("span", { class: "val ltr", text: `${pct}/100` }));
  const submitted = f.submitted_input || f.submitted_url || f.domain;
  return section(t("analysis.summaryTitle"), f.id ? t("analysis.findingId", { id: f.id }) : t("analysis.notSaved"),
    head,
    kvList([
      [t("analysis.submitted"), el("span", { dir: "auto", class: "pre-wrap", text: submitted || "—" })],
      [t("analysis.inputType"), t(`analysis.type_${f.input_type || "domain"}`)],
      f.normalized_url ? [t("analysis.normalizedUrl"), ltrSpan(f.normalized_url)] : null,
      f.analyzed_url && f.analyzed_url !== f.normalized_url ? [t("analysis.analyzedUrl"), ltrSpan(f.analyzed_url)] : null,
      f.domain ? [t("common.domain"), ltrSpan(f.domain)] : null,
      [t("analysis.verdict"), t(`common.tag${tagKey[0].toUpperCase()}${tagKey.slice(1)}`)],
      [t("analysis.riskScore"), bar],
      [t("analysis.confidence"), t("analysis.confidenceNA")],
      f.scam_type ? [t("analysis.scamType"), ltrSpan(f.scam_type, "mono")] : null,
      [t("analysis.scannedAt"), fmtDateTime(f.scanned_at || f.created_at || f.first_seen)],
      f.cached ? [t("analysis.storedResult"), t("analysis.storedResultNote", { at: fmtDateTime(f.cached_at || f.scanned_at) })] : null,
      [t("analysis.status"), f.scan_status ? t(`analysis.scan_${f.scan_status}`) : "—"],
      f.engine_version ? [t("analysis.engine"), ltrSpan(f.engine_version)] : null,
      f.policy_version ? [t("trust.policyVersion"), ltrSpan(f.policy_version)] : null,
    ]),
    f.redactions && Object.keys(f.redactions).length
      ? el("p", { class: "muted", style: "font-size:var(--fs-xs); margin-block-start:var(--s3)", text: t("analysis.redacted") })
      : null);
}

/* ---------------- checks (what ran, what could not) ---------------- */
export function checksCard(f) {
  const checks = Array.isArray(f.checks) ? f.checks : [];
  if (!checks.length) return null;
  const list = el("ul", { class: "check-list" });
  for (const c of checks) {
    list.append(el("li", { class: `check-item is-${c.status}` },
      el("span", { class: "check-status", text: t(`analysis.st_${c.status}`) }),
      el("span", { class: "check-name", text: t(`analysis.check_${c.id}`) }),
      el("span", { class: "check-detail ltr mono", dir: "auto", text: c.detail || "" })));
  }
  return section(t("analysis.checksTitle"), "", list);
}

/* ---------------- detection signals (expandable) -------------------- */
export function signalsCard(f) {
  const signals = Array.isArray(f.signals) ? f.signals : [];
  if (!signals.length) {
    return section(t("analysis.signalsTitle"), "0",
      el("p", { class: "muted", text: t("analysis.noSignals") }));
  }
  const groups = new Map();
  for (const s of signals) {
    const cat = s.category || "other";
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat).push(s);
  }
  const ordered = [...groups.keys()].sort((a, b) => CATEGORY_ORDER.indexOf(a) - CATEGORY_ORDER.indexOf(b));
  const wrap = el("div", { class: "stack", style: "gap:var(--s2)" });
  for (const cat of ordered) {
    wrap.append(el("div", { class: "signal-group-title", text: label(`analysis.cat_${cat}`, cat) }));
    for (const s of groups.get(cat)) wrap.append(signalItem(s));
  }
  return section(t("analysis.signalsTitle"), String(signals.length), wrap);
}

function signalItem(s) {
  const name = String(s.name || "");
  const title = label(`sig.${name}`, s.reason || name);
  const d = el("details", { class: "signal" });
  d.append(el("summary", {},
    el("span", { class: "signal-title", text: title }),
    el("span", { class: "signal-weight ltr mono", text: `+${Math.round((Number(s.weight) || 0) * 100)}` })));
  d.append(kvList([
    [t("analysis.detected"), title],
    [t("analysis.why"), el("span", { dir: "auto", text: s.reason || "—" })],
    [t("analysis.triggeredBy"), s.part ? t(`analysis.part_${s.part}`) : "—"],
    s.excerpt ? [t("analysis.excerpt"), el("q", { dir: "auto", class: "pre-wrap", text: s.excerpt })] : null,
    [t("analysis.signalId"), ltrSpan(name)],
  ]));
  return d;
}

/* ---------------- why this verdict -------------------------------- */
export function trustCard(f) {
  if (!Array.isArray(f.trust_reasons) || !f.trust_reasons.length) return null;
  return section(t("trust.whyTag"), f.manual_review ? t("trust.manualReview") : "",
    el("ul", { class: "stack", style: "gap:var(--s1); margin:0; padding-inline-start:var(--s4)" },
      ...f.trust_reasons.map((r, i) => el("li", { dir: "auto" }, el("span", { text: r }),
        Array.isArray(f.reason_codes) && f.reason_codes[i]
          ? el("span", { class: "muted mono", dir: "ltr", style: "font-size:var(--fs-xs); margin-inline-start:var(--s2)",
            text: f.reason_codes[i] })
          : null))));
}

/* ---------------- evidence checked (sources, result, freshness) ------ */
export function evidenceCard(f) {
  const recs = Array.isArray(f.evidence) ? f.evidence : [];
  if (!recs.length) return null;
  const page = (f.live_evidence && f.live_evidence.page) || null;
  const age = (f.live_evidence && f.live_evidence.domain_age) || null;
  const rows = recs.map((r) => el("li", { class: "card tight", style: "list-style:none" },
    el("div", { class: "row", style: "justify-content:space-between" },
      el("strong", { text: label(`analysis.ev_${r.id}`, r.id) }),
      el("span", { class: "chip ltr mono", dir: "ltr", text: String(r.status || "—") })),
    r.summary ? el("p", { dir: "auto", style: "margin-block:var(--s1)", text: r.summary }) : null,
    el("p", { class: "muted", style: "font-size:var(--fs-xs); margin:0",
      text: [r.source,
        r.checked_at ? `${t("analysis.evCheckedAt")}: ${fmtDateTime(r.checked_at)}` : null,
        r.data_updated_at ? `${t("analysis.evDataUpdated")}: ${fmtDateTime(r.data_updated_at)}` : null,
        r.expires_at ? `${t("analysis.expiresOn")}: ${fmtDateTime(r.expires_at)}` : null,
        r.stale ? t("analysis.evStale") : null].filter(Boolean).join(" · ") })));
  return section(t("analysis.evidenceTitle"), String(recs.length),
    el("p", { class: "muted", style: "font-size:var(--fs-sm); margin:0", text: t("analysis.evidenceNote") }),
    kvList([
      age && age.status === "ok" ? [t("analysis.registered"),
        ltrSpan(t("analysis.ageValue", { date: fmtDateTime(age.registered_at), days: age.age_days }))] : null,
      page && page.final_host && page.redirected ? [t("analysis.landsOn"), ltrSpan(page.final_host)] : null,
    ]),
    el("ul", { class: "stack", style: "padding:0; margin:0" }, ...rows));
}

/* ---------------- domain authentication --------------------------- */
export function authCard(f) {
  const a = f.domain_auth;
  if (!a) return section(t("trust.authTitle"), "", el("p", { class: "muted", text: t("trust.auth_NOT_CHECKABLE") }));
  return section(t("trust.authTitle"), a.authenticated ? t(`trust.class_${a.source_class}`) : "", kvList([
    a.host ? [t("common.domain"), ltrSpan(a.host)] : null,
    [t("analysis.result"), label(`trust.auth_${a.status}`, a.status)],
    a.reason ? [t("analysis.why"), el("span", { dir: "auto", text: a.reason })] : null,
    a.organization ? [t("trust.entity"), a.organization] : null,
    a.reviewer ? [t("analysis.reviewer"), a.reviewer] : null,
    a.verified_at ? [t("analysis.approvedOn"), fmtDateTime(a.verified_at)] : null,
    a.expires_at ? [t("analysis.expiresOn"), fmtDateTime(a.expires_at)] : null,
    a.reputation && a.reputation.trusted
      ? [t("analysis.worldRank"), ltrSpan(t("analysis.rankValue", { rank: Number(a.reputation.rank).toLocaleString(),
          list: a.reputation.list_id || "—", date: a.reputation.list_date || "—" }))]
      : null,
    a.established && a.established.status === "established"
      ? [t("analysis.establishedBasis"), el("span", { dir: "auto",
          text: t("analysis.establishedValue", { basis: a.established.basis, years: a.established.years,
            since: String(a.established.since || "").slice(0, 10) }) })]
      : null,
    a.established && a.established.status === "not_established"
      ? [t("analysis.establishedCheck"), el("span", { dir: "auto", text: a.established.reason })]
      : null,
    a.reputation && !a.reputation.trusted
      ? [t("analysis.reputationCheck"), label(`trust.rep_${a.reputation.status}`, a.reputation.status)]
      : null,
    a.registry_version ? [t("trust.registryVersion"), ltrSpan(a.registry_version)] : null,
  ]));
}

/* ---------------- verdict history (registry / policy re-evaluation) ---- */
export function historyCard(f) {
  const h = Array.isArray(f.verdict_history) ? f.verdict_history : [];
  if (!h.length) return null;
  return section(t("analysis.historyTitle"), String(h.length),
    el("p", { class: "muted", style: "font-size:var(--fs-sm)", text: t("analysis.historyNote") }),
    el("ul", { class: "stack", style: "gap:var(--s1); margin:0; padding-inline-start:var(--s4)" },
      ...h.map((x) => el("li", {},
        el("span", { class: "mono ltr", text: fmtDateTime(x.at) }), " · ",
        t("analysis.historyWas", { tag: x.tag || "—", auth: label(`trust.auth_${x.domain_auth_status}`, x.domain_auth_status || "—") }),
        x.registry_version ? el("span", { class: "muted mono ltr", text: ` (${x.registry_version})` }) : null))));
}

/* ---------------- official-source verification -------------------- */
export function govCard(f) {
  const g = f.gov_verification;
  if (!g) return section(t("trust.govTitle"), "", el("p", { class: "muted", text: t("analysis.govNone") }));
  const c = g.claim || {};
  const items = (g.evidence || []).map((e) => el("li", { class: "card tight", style: "list-style:none" },
    el("div", { class: "row", style: "justify-content:space-between" },
      el("strong", { text: e.organization || e.entry_id || "—" }),
      el("span", { class: "chip", text: `${label(`trust.class_${e.source_class}`, e.source_class)} · ${label(`trust.role_${e.role}`, e.role)}` })),
    /^https:\/\//.test(e.source_url || "")
      ? el("a", { class: "ltr mono", href: e.source_url, rel: "noopener noreferrer nofollow", target: "_blank", text: e.source_url })
      : el("span", { class: "ltr mono", text: e.source_url || "—" }),
    e.excerpt ? el("p", { dir: "auto", style: "margin-block:var(--s2)" }, el("q", { text: e.excerpt })) : null,
    el("p", { class: "muted", style: "font-size:var(--fs-xs); margin:0",
      text: `${t("trust.published")}: ${e.published_at ? fmtDateTime(e.published_at) : t("trust.dateNotGiven")} · ${t("trust.retrieved")}: ${e.retrieved_at ? fmtDateTime(e.retrieved_at) : "—"}${e.detail ? " · " + e.detail : ""}` }),
    e.attributes ? el("div", { class: "row", style: "gap:var(--s1); flex-wrap:wrap" },
      ...["authority", "jurisdiction", "service", "amount", "effective_date"]
        .filter((k) => e.attributes[k] && e.attributes[k] !== "not_compared")
        .map((k) => el("span", { class: "chip", text: `${t(`trust.attr_${k}`)}: ${label(`trust.attrv_${e.attributes[k]}`, e.attributes[k])}` }))) : null,
    e.synthetic ? el("span", { class: "chip", title: t("trust.syntheticNote"), text: t("trust.synthetic") }) : null));
  return section(t("trust.govTitle"), label(`trust.gov_${g.status}`, g.status), kvList([
    [t("analysis.result"), label(`trust.gov_${g.status}`, g.status)],
    [t("trust.claim"), el("span", { dir: "auto", text: c.canonical || "—" })],
    [t("trust.entity"), (c.entity_names || []).join(", ") || "—"],
    [t("trust.category"), (c.categories || []).join(", ") || "—"],
    g.coverage ? [t("trust.coverage"), label(`trust.cov_${g.coverage}`, g.coverage)] : null,
    [t("trust.checked"), (g.checked_sources || []).join(", ") || t("trust.noneYet")],
    [t("trust.unchecked"), (g.unchecked_sources || []).join(", ") || t("trust.noneYet")],
    g.evidence_id ? [t("trust.evidenceId"), ltrSpan(g.evidence_id)] : null,
  ]),
  items.length
    ? el("div", {}, el("div", { class: "card-title", style: "font-size:var(--fs-sm)" }, el("span", { text: t("trust.evidenceTitle") })),
      el("ul", { class: "stack", style: "padding:0; margin:0" }, ...items))
    : el("p", { class: "muted", style: "font-size:var(--fs-sm)", text: t("analysis.noOfficialEvidence") }),
  (g.notes || []).length
    ? el("ul", { style: "margin:0; padding-inline-start:var(--s4)" }, ...g.notes.map((n) => el("li", { class: "muted", dir: "auto", text: n })))
    : null);
}

/* ---------------- links analysed ---------------------------------- */
export function urlsCard(f) {
  const urls = Array.isArray(f.urls) ? f.urls : [];
  if (urls.length < 2) return null;
  return section(t("analysis.urlsTitle"), String(urls.length),
    el("ul", { class: "stack", style: "gap:var(--s1); margin:0; padding-inline-start:var(--s4)" },
      ...urls.map((u) => el("li", {},
        ltrSpan(u.url), " ",
        el("span", { class: "muted mono", text: `${Math.round((u.score || 0) * 100)}/100 · ${u.verdict}` })))));
}

/* ---------------- precautions -------------------------------------- */
export function precautionsCard(f) {
  const codes = Array.isArray(f.precautions) ? f.precautions : [];
  if (!codes.length) return null;
  return section(t("analysis.precautionsTitle"), "",
    el("ul", { class: "stack", style: "gap:var(--s1); margin:0; padding-inline-start:var(--s4)" },
      ...codes.map((c) => el("li", { text: label(`analysis.pre_${c}`, c) }))));
}

/** Human label for where a finding came from (checker, investigation, sweep, radar…). */
export function sourceLabel(f) {
  const raw = String((f && f.source) || "radar").toLowerCase();
  const key = raw.startsWith("crt") ? "crt"
    : /^(feeds|phishtank|openphish|urlhaus)/.test(raw) ? "feeds"
    : raw.split(/[:.]/)[0];
  return label(`analysis.src_${key}`, raw);
}

/** Full analysis, in reading order. */
export function analysisView(f) {
  return el("div", { class: "stack analysis" },
    ...[summaryCard(f), checksCard(f), signalsCard(f), trustCard(f), authCard(f), evidenceCard(f), govCard(f), urlsCard(f),
      historyCard(f), precautionsCard(f)]
      .filter(Boolean));
}
