/* Daggers · entry point (external file: the CSP forbids inline scripts). */
import { boot } from "./app.js";

boot().catch((err) => {
  console.error(err);
  const fallback = document.getElementById("bootError");
  if (fallback) fallback.hidden = false;
});
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => { /* fine without SW */ });
  });
}
