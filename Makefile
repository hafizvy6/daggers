PYTHON ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)
BOOTSTRAP_PYTHON ?= $(shell for p in python3.11 python3.12 python3.13 python3.14 python3; do command -v $$p >/dev/null 2>&1 && { echo $$p; break; }; done)
NUMPY_PIN = $(shell $(PYTHON) -c 'import sys; print("numpy==2.5.5" if sys.version_info >= (3, 12) else "numpy==2.1.3")')
NODE ?= node
PORT ?= 8000
HOST ?= 0.0.0.0
ENV_FILE_ARG = $(if $(wildcard .env),--env-file .env,)
# Use a different package index, e.g. when a machine's pip.conf points at a private mirror:
#   make bootstrap PIP_INDEX=https://pypi.org/simple
PIP_INDEX_ARG = $(if $(PIP_INDEX),--index-url $(PIP_INDEX),)
# Registry file used by the CLI targets (same variable the app reads; default = shipped registry)
REGISTRY_ARG = $(if $(OFFICIAL_REGISTRY_PATH),--registry $(OFFICIAL_REGISTRY_PATH),)
export PYTHONPATH := $(CURDIR)
# make dev: a browser on THIS computer opens the Police Portal without signing in (local admin).
# Turn it off with: make dev LOCAL_OPEN_ACCESS=0   (always off with APP_ENV=production)
LOCAL_OPEN_ACCESS ?= 1

OPTIONAL_RENDER_PKGS = imagehash==4.3.2 $(NUMPY_PIN) opencv-python-headless==5.1.0.95 playwright==1.65.2 pytesseract==0.3.13

.PHONY: e2e-guard guard-sync e2e-restore setup-trust why doctor reset-checker-store reset-local-data trust-status e2e-rep reputation-update approve-verified e2e-gov help bootstrap reinstall install install-render dev run prod user registry test test-ext gates e2e check verify-empty clean snapshot

help:
	@echo "Daggers (live only)"
	@echo "  make bootstrap                 create .venv (kept if it exists) and install pinned dependencies"
	@echo "  make dev                       run on :$(PORT); this computer opens the portal without login"
	@echo "  make user U=alice R=admin      create a Police Portal account (for other computers / production)"
	@echo "  make prod                      APP_ENV=production (Secure cookies: needs HTTPS)"
	@echo "  make registry ARGS='list'      official-source registry CLI"
	@echo "  make check                     compile + backend tests + extension tests + gates"
	@echo "  make e2e PORTAL_USER=… PORTAL_PASS=…   real-browser acceptance test against a running server"
	@echo "  make setup-trust                  ONE step: approve verified entries + download ranking list + clear stored results + doctor"
	@echo "  make why URL=\"https://…\"          why does the Checker give this verdict (every reason + evidence source)"
	@echo "  make doctor                       can this machine do live checks (registry, ranking list, internet)"
	@echo "  make reset-checker-store          forget the Checker's stored results (next checks are analysed fresh)"
	@echo "  make reset-local-data CONFIRM=yes  DELETE all local data (Portal findings, users, Checker store) and start empty"
	@echo "  make trust-status                 what the Checker can use: approved registry entries + ranking list"
	@echo "  make reputation-update            download the latest Tranco top-sites list (SAFE path for widely used sites)"
	@echo "  make e2e-rep PORTAL_USER=… PORTAL_PASS=… REPUTATION_FILE=<new path>   reputation SAFE browser test"
	@echo "  make e2e-gov PORTAL_USER=… PORTAL_PASS=… REGISTRY_FILE=<copy>   government SAFE browser test (server started with OFFICIAL_REGISTRY_PATH=<copy>)"

bootstrap:
	@test -n "$(BOOTSTRAP_PYTHON)" || { echo "Python 3.11+ is required"; exit 1; }
	@$(BOOTSTRAP_PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11+ is required")'
	@test -x .venv/bin/python || $(BOOTSTRAP_PYTHON) -m venv .venv
	.venv/bin/pip install --disable-pip-version-check $(PIP_INDEX_ARG) -r requirements.txt

reinstall:
	rm -rf .venv
	$(MAKE) bootstrap

install:
	$(PYTHON) -m pip install --disable-pip-version-check $(PIP_INDEX_ARG) -r requirements.txt

install-render:
	$(PYTHON) -m pip install --disable-pip-version-check $(PIP_INDEX_ARG) $(OPTIONAL_RENDER_PKGS)
	$(PYTHON) -m playwright install chromium

dev:
	LOCAL_OPEN_ACCESS=$(LOCAL_OPEN_ACCESS) $(PYTHON) -m uvicorn backend.app.main:app --host $(HOST) --port $(PORT) --reload $(ENV_FILE_ARG)

run:
	$(PYTHON) -m uvicorn backend.app.main:app --host $(HOST) --port $(PORT) $(ENV_FILE_ARG)

prod:
	APP_ENV=production $(PYTHON) -m uvicorn backend.app.main:app --host $(HOST) --port $(PORT) --proxy-headers $(ENV_FILE_ARG)

# Police Portal account: make user U=alice R=investigator   (R = viewer | investigator | admin;
# the password is asked for afterwards, it is never typed on the command line)
user:
	@test -n "$(U)" || { echo "usage: make user U=<username> R=<viewer|investigator|admin>"; exit 2; }
	$(PYTHON) -m backend.app.admin_cli create-user --username $(U) --role $(or $(R),viewer)

# Official-source registry: make registry ARGS="list --status pending"
registry:
	$(PYTHON) -m backend.app.channels.official.cli $(REGISTRY_ARG) $(ARGS)

# Approve every pending entry whose provenance records a completed verification:  make approve-verified
# Independent site reputation: the server also downloads this automatically when it is missing or
# older than 7 days (REPUTATION_AUTO_UPDATE=1, default). Needs network.
reputation-update:
	$(PYTHON) -m backend.app.channels.reputation update
	$(PYTHON) -m backend.app.channels.reputation status

# Stored Checker results are also dropped automatically whenever the code / rules / registry change.
CHECKER_STORE = $(or $(CHECKER_STORE_PATH),backend/data/checker-store.db)
LOCAL_DB = $(or $(DB_PATH),backend/data/daggers.db)
reset-checker-store:
	rm -f "$(CHECKER_STORE)" "$(CHECKER_STORE)-wal" "$(CHECKER_STORE)-shm"
	@echo "Checker result store cleared: $(CHECKER_STORE) (restart 'make dev' if it is running)"

# Full local reset: Portal database (findings, reports, users, sessions), Checker store, evidence images,
# RDAP cache. Keeps the code, the official registry and the downloaded ranking list. NOT reversible.
reset-local-data:
	@test "$(CONFIRM)" = "yes" || { echo 'This DELETES all local data (Portal findings, users, Checker store).'; \
		echo 'Stop the server first, then run: make reset-local-data CONFIRM=yes'; exit 2; }
	rm -f "$(LOCAL_DB)" "$(LOCAL_DB)-wal" "$(LOCAL_DB)-shm" "$(CHECKER_STORE)" "$(CHECKER_STORE)-wal" "$(CHECKER_STORE)-shm"
	rm -f backend/data/rdap-bootstrap-dns.json
	find backend/data/evidence backend/data/gallery -type f -delete 2>/dev/null || true
	@echo "Local data reset. Create a Portal user again:  make user U=<name> R=admin"

# ONE command to make genuine sites able to be SAFE on this machine.
setup-trust:
	$(PYTHON) -m backend.app.channels.official.cli $(REGISTRY_ARG) approve-verified --yes
	-$(PYTHON) -m backend.app.channels.reputation update
	rm -f "$(CHECKER_STORE)" "$(CHECKER_STORE)-wal" "$(CHECKER_STORE)-shm"
	-$(PYTHON) ops/doctor.py
	@echo "Done. Restart the server (make dev) so it reloads everything."

why:
	@test -n "$(URL)" || { echo 'usage: make why URL="https://example.com/"'; exit 2; }
	@$(PYTHON) ops/why.py "$(URL)"

doctor:
	@$(PYTHON) ops/doctor.py

# Why is a genuine site not SAFE? Check these two first.
trust-status:
	@echo "== Official registry (SAFE for listed organisations needs status 'approved') =="
	@$(PYTHON) -m backend.app.channels.official.cli $(REGISTRY_ARG) list
	@echo; echo "== Worldwide ranking list (SAFE for widely used sites needs loaded=true, stale=false) =="
	@$(PYTHON) -m backend.app.channels.reputation status

approve-verified:
	$(PYTHON) -m backend.app.channels.official.cli $(REGISTRY_ARG) approve-verified --yes
	$(PYTHON) -m backend.app.channels.official.cli $(REGISTRY_ARG) list

test:
	PYTHONWARNINGS=ignore::DeprecationWarning $(PYTHON) -m pytest backend/tests -q

test-ext:
	$(NODE) --test extension/tests/core.test.js

gates:
	$(PYTHON) ops/check_i18n.py
	$(NODE) ops/check_syntax.mjs

# Real-browser acceptance test (Playwright + Chrome) against a RUNNING live server:
#   make dev   (other terminal)   then:   make e2e PORTAL_USER=… PORTAL_PASS=…
e2e:
	BASE=$(or $(BASE),http://127.0.0.1:$(PORT)) PORTAL_USER=$(PORTAL_USER) PORTAL_PASS=$(PORTAL_PASS) $(NODE) ops/e2e_portal.mjs

# Government SAFE browser test. Needs a server started with OFFICIAL_REGISTRY_PATH pointing at a COPY
# of the registry (the test approves/revokes entries in that copy; it refuses the shipped file).
e2e-gov:
	BASE=$(or $(BASE),http://127.0.0.1:$(PORT)) PORTAL_USER=$(PORTAL_USER) PORTAL_PASS=$(PORTAL_PASS) REGISTRY_FILE=$(REGISTRY_FILE) $(NODE) ops/e2e_government.mjs

verify-empty:
	$(PYTHON) ops/verify_empty.py

check:
	$(PYTHON) -m compileall -q backend
	$(MAKE) test
	$(MAKE) test-ext
	$(MAKE) gates

clean:
	rm -f backend/data/*.db backend/data/*.db-wal backend/data/*.db-shm
	rm -f backend/data/evidence/*.jpg backend/data/evidence/*.png backend/data/gallery/*.jpg backend/data/gallery/*.png

snapshot:
	mkdir -p snapshot
	cp backend/data/daggers.db snapshot/daggers.db 2>/dev/null || true
	cp -r backend/data/evidence snapshot/evidence 2>/dev/null || true
	@echo "Snapshot written to ./snapshot (not committed)."

# Reputation SAFE browser test. Needs a server started with REPUTATION_LIST_PATH=$(REPUTATION_FILE) (a path
# that does NOT exist yet) and REPUTATION_AUTO_UPDATE=0; the test writes and then deletes a TEST list there.
# Guard browser test (live list, SSE, test bar, verdict page EN/AR) against a running server.
e2e-guard:
	BASE=$(or $(BASE),http://127.0.0.1:$(PORT)) $(NODE) ops/e2e_guard.mjs

# AdGuard Home sidecar (VPS, Path B): dry run by default; APPLY=1 to change AdGuard Home.
guard-sync:
	DAGGERS_API=$(or $(BASE),http://127.0.0.1:$(PORT)) $(PYTHON) guard/sync.py --once $(if $(APPLY),--apply,)

e2e-rep:
	BASE=$(or $(BASE),http://127.0.0.1:$(PORT)) PORTAL_USER=$(PORTAL_USER) PORTAL_PASS=$(PORTAL_PASS) REPUTATION_FILE=$(REPUTATION_FILE) $(NODE) ops/e2e_reputation.mjs

# Checker restore after closing the browser and restarting the program (two phases, restart in between):
#   make e2e-restore PHASE=1 ; (restart make dev) ; make e2e-restore PHASE=2
e2e-restore:
	BASE=$(or $(BASE),http://127.0.0.1:$(PORT)) PHASE=$(or $(PHASE),1) PROFILE=$(or $(PROFILE),/tmp/daggers-restore-profile) $(NODE) ops/e2e_restore.mjs
