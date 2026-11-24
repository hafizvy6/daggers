/* ============================================================
   Daggers · deploy configuration — the ONLY edit at deploy time.
   "" = same origin (FastAPI static mount, local `make dev`).
   For a static Pages frontend, set the API origin, e.g.
     window.API_BASE = "https://daggers-api.hf.space";
   Configure CORS_ORIGINS / CORS_ORIGIN_REGEX on that backend too.
   ============================================================ */
window.API_BASE = "";
