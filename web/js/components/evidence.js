/* Daggers · evidence frame — official vs suspect side-by-side + caption */
import { t } from "../i18n/i18n.js";
import { el } from "./tag.js";

export function evidenceFrame(finding, { compact = false } = {}) {
  const url = finding?.evidence_url;
  const frame = el("figure", { class: "evidence-frame", style: "margin:0" });

  const head = el("div", { class: "ev-head" });
  head.append(
    el("span", { class: "ev-label" }, el("span", { class: "ev-pip real" }), t("finding.official", { brand: finding?.brand || t("common.unknown") })),
    el("span", { class: "ev-label", style: "margin-inline-start:auto" }, el("span", { class: "ev-pip clone" }), t("finding.suspect")),
  );
  frame.append(head);

  if (url) {
    const img = el("img", {
      src: url, alt: t("finding.suspect") + " — " + (finding?.domain || ""),
      loading: compact ? "lazy" : "eager", decoding: "async",
    });
    img.addEventListener("error", () => { img.replaceWith(placeholder(finding)); });
    frame.append(img);
  } else {
    frame.append(placeholder(finding));
  }

  if (!compact) {
    frame.append(el("figcaption", { class: "ev-foot" },
      el("span", { class: "mono", text: `${finding?.clone ?? 0}%` }), " ",
      t("finding.cloneMatch", { n: finding?.clone ?? 0 }), " · ",
      t("finding.overlay"),
    ));
  }
  return frame;
}

function placeholder(finding) {
  const d = el("div", { style: "padding:var(--s6); display:grid; place-items:center; gap:var(--s3); background:var(--paper); min-height:220px" },
    el("div", { class: "mono ltr", style: "font-size:var(--fs-sm); color:var(--ink-muted)", text: finding?.domain || "" }),
    el("div", { style: "font-size:var(--fs-sm); color:var(--ink-muted); text-align:center", text: t("finding.offlineNote") }),
  );
  return d;
}
