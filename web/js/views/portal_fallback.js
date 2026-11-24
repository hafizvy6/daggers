/* Daggers · template fallback for the AI panel (identical UI shape).
   Used when the stream dies mid-way — the UI shape stays intact.
   All prose lives in the catalogs (portal.fallback.*); this file only fills slots.
   The backend template (backend/app/ai/fallback.py) is the other half of the same rule. */
import { t, localized, reasonsOf } from "../i18n/i18n.js";

export async function getFallback(reportId) {
  const { getReports } = await import("../api.js");
  const reports = await getReports().catch(() => []);
  const r = reports.find((x) => String(x.id) === String(reportId)) || {};
  const ev = r.evidence || {};
  const domain = r.domain || ev.domain || t("letter.unknownDomain");
  const reasons = reasonsOf(ev).slice(0, 3);
  const p1 = String(ev.verdict).toUpperCase() === "MALICIOUS";
  const priority = t(p1 ? "portal.fallback.priorityP1" : "portal.fallback.priorityP2");
  const body = reasons.length
    ? reasons.map((x) => `• ${x}`).join("\n")
    : `• ${t("portal.fallback.noReasons")}`;

  return {
    summary_en: t("portal.fallback.template", {
      domain,
      verdict: t(p1 ? "common.tagFake" : "common.tagWarning"),
      score: (ev.score ?? 0).toFixed(2),
      reasons: body,
      priority,
    }),
    summary_ar: t("portal.fallback.templateAr", {
      domain,
      verdict: t(p1 ? "common.tagFake" : "common.tagWarning"),
      score: (ev.score ?? 0).toFixed(2),
      reasons: body,
      priority,
    }),
    provider: "template",
    fallback: true,
  };
}
