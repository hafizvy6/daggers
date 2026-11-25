/* Daggers · Police Portal sign-in (session cookie + CSRF; see backend/app/security.py). */
import { t } from "../i18n/i18n.js";
import { login, logout, state } from "../api.js";
import { el } from "../components/tag.js";
import { pageHead, card } from "./_shared.js";

export default async function Login(ctx) {
  const root = el("div");
  const next = ctx.param && ctx.param.startsWith("portal") ? `#/${ctx.param}` : "#/portal";
  root.append(pageHead({ kicker: t("nav.groupPolice"), title: t("auth.title"), subtitle: t("auth.subtitle") }));

  if (state.user && state.user.local) {
    root.append(card(null, "",
      el("div", { class: "note note-teal" }, el("span", { text: "i" }), el("span", { text: t("auth.localAccess") })),
      el("div", { class: "row" }, el("a", { class: "btn btn-primary", href: "#/portal", text: t("nav.portal") }))));
    return root;
  }
  if (state.user) {
    const out = el("button", { class: "btn", type: "button", text: t("auth.signOut") });
    out.addEventListener("click", async () => { await logout(); location.hash = "#/login"; });
    root.append(card(null, "",
      el("p", { text: t("auth.signedInAs", { user: state.user.username, role: t(`auth.role_${state.user.role}`) }) }),
      el("div", { class: "row" }, el("a", { class: "btn btn-primary", href: "#/portal", text: t("nav.portal") }), out)));
    return root;
  }

  const user = el("input", { class: "input", id: "loginUser", autocomplete: "username", dir: "ltr", required: true, maxlength: "64" });
  const pass = el("input", { class: "input", id: "loginPass", type: "password", autocomplete: "current-password", dir: "ltr", required: true, maxlength: "256" });
  const msg = el("p", { class: "field-hint", role: "alert" });
  const submit = el("button", { class: "btn btn-primary btn-block", type: "submit", text: t("auth.submit") });
  const form = el("form", { class: "stack", novalidate: true },
    el("div", { class: "field" }, el("label", { for: "loginUser", text: t("auth.username") }), user),
    el("div", { class: "field" }, el("label", { for: "loginPass", text: t("auth.password") }), pass),
    submit, msg);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!user.value.trim() || !pass.value) return;
    submit.disabled = true;
    submit.textContent = t("auth.signingIn");
    msg.textContent = "";
    try {
      await login(user.value.trim(), pass.value);
      pass.value = "";
      location.hash = next;
    } catch (err) {
      msg.textContent = err?.status === 429 ? t("auth.locked") : t("auth.failed");
      submit.disabled = false;
      submit.textContent = t("auth.submit");
    }
  });
  root.append(card(null, "", form), el("p", { class: "muted", style: "font-size:var(--fs-xs)", text: t("auth.disclaimer") }));
  return root;
}
