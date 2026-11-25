# Daggers Shield — Chrome extension (Manifest V3)

Labels **organic** Google results with the Daggers backend's tag:
`SAFE` (green) · `WARNING` (amber) · `MISLEADING` (purple) · `FAKE` (red) · `NOT CHECKED` (grey).

> Unofficial hackathon prototype. **Not** an Abu Dhabi Police, UAE Police or government product.
> **Not published** on the Chrome Web Store.

## Install (local development)

1. Start the backend: `make dev` (serves `http://localhost:8000`).
2. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this `extension/` folder.
3. Search on `www.google.com` or `www.google.ae`. Each organic result gets a label; hover for reasons.
4. Popup: change the backend URL (HTTPS required except `localhost`/`127.0.0.1`; Chrome asks for
   permission for that one origin), toggle labelling, clear the cache.

## Behaviour guarantees

* **No local verdicts.** The label is the backend `tag`. SAFE is shown only if the backend returns
  `tag: "SAFE"` **and** `domain_auth.authenticated: true`.
* **Fail safe.** Timeout (6 s), network error, HTTP error, malformed reply or a worker that never answers →
  grey `NOT CHECKED`. Never green.
* **Integrated backend:** the label always equals the `tag` returned by `/api/scan` (verified in the
  browser end-to-end test). A backend without a `tag` field: `UNKNOWN` is shown as `UNVERIFIED` (amber), never SAFE.
* SAFE needs an **approved** registry entry; with the shipped registry (all pending) official sites show WARNING.
* **Skipped:** ads (`#tads`, sponsored blocks), Maps/local packs, carousels, and all Google-internal links.
* **Dynamic results** are handled with a debounced `MutationObserver`; each link is labelled once.

## Privacy & permissions

* Permissions: `storage` only. Host access: `localhost`/`127.0.0.1` by default; any other backend origin is
  requested at runtime for that single origin.
* Sends only the result URL **without its query string or fragment** to the configured backend.
  No search terms, page content, cookies or history are read or sent.
* Cache: `chrome.storage.session` (memory, cleared when the browser closes): 30 min for answers,
  60 s for failures.
* No API keys in the extension. Labels are built with `textContent`; no backend HTML is injected.

## Tests

```bash
node --test extension/tests/core.test.js
```

Covers result eligibility (ads/maps/internal excluded), URL sanitization, label mapping, the
never-SAFE-on-failure rule (with a mocked service worker and `fetch`), caching, and permission minimality.
Not covered: real Google DOM (selectors may drift when Google changes markup) and a real browser run.
