/* Daggers · evidence frame — honest status + real side-by-side when captured */
import { t } from "../i18n/i18n.js";
import { el } from "./tag.js";

export function evidenceFrame(finding, { compact = false } = {}) {
  const url = finding?.evidence_url;
  const frame = el("figure", { class: "evidence-frame", style: "margin:0" });

  if (!url) {
    frame.append(capturePending(finding));
    if (!compact) frame.append(cloneFootnote(finding));
    return frame;
  }

  const reference = finding?.gallery_match || t("common.unknown");
  const head = el("div", { class: "ev-head" });
  head.append(
    el("span", { class: "ev-label" }, el("span", { class: "ev-pip real" }), t("finding.official", { brand: reference })),
    el("span", { class: "ev-label", style: "margin-inline-start:auto" }, el("span", { class: "ev-pip clone" }), t("finding.suspect")),
  );
  const img = el("img", {
    src: url,
    alt: t("finding.suspect") + " — " + (finding?.domain || ""),
    loading: compact ? "lazy" : "eager", decoding: "async",
  });
  img.addEventListener("error", () => {
    img.replaceWith(capturePending(finding, t("finding.captureFailed")));
  });
  frame.append(head, img);
  if (!compact) frame.append(cloneFootnote(finding));
  return frame;
}

function capturePending(finding, detail = null) {
  return el("div",
    { class: "ev-pending", role: "status", style: "padding:var(--s6); display:grid; place-items:center; gap:var(--s3); background:var(--paper); min-height:260px; text-align:center" },
    el("div", { class: "mono ltr", style: "font-size:var(--fs-sm); color:var(--ink-muted)", text: finding?.domain || "" }),
    el("div", { style: "font-size:var(--fs-lg); font-weight:600", text: t("finding.noCaptureTitle") }),
    el("div", { class: "muted", style: "max-width:42rem", text: detail || t("finding.noCaptureBody") }),
  );
}

function cloneFootnote(finding) {
  const clone = Number.isFinite(Number(finding?.clone)) ? Number(finding.clone) : null;
  const known = clone !== null && clone > 0;
  return el("figcaption", { class: "ev-foot" },
    el("span", { class: "mono", text: known ? `${Math.round(clone)}%` : "—" }),
    " ",
    t(known ? "finding.cloneMatch" : "finding.noCloneMatch", { n: known ? Math.round(clone) : 0 }),
  );
}
