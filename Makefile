PYTHON ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)
BOOTSTRAP_PYTHON ?= $(shell for p in python3.11 python3.12 python3.13 python3.14 python3; do command -v $$p >/dev/null 2>&1 && { echo $$p; break; }; done)
NUMPY_PIN = $(shell $(PYTHON) -c 'import sys; print("numpy==2.5.5" if sys.version_info >= (3, 12) else "numpy==2.1.3")')
NODE ?= node
PORT ?= 8000
HOST ?= 0.0.0.0
ENV_FILE_ARG = $(if $(wildcard .env),--env-file .env,)
export PYTHONPATH := $(CURDIR)

OPTIONAL_RENDER_PKGS = imagehash==4.3.2 $(NUMPY_PIN) opencv-python-headless==5.1.0.95 playwright==1.65.2 pytesseract==0.3.13

.PHONY: help bootstrap install install-render run dev test check clean snapshot deploy verify-empty

help:
	@echo "Daggers live app: bootstrap · run/dev · test · check · clean · deploy"
	@echo "  make bootstrap    create .venv and install pinned dependencies"
	@echo "  make dev          start live FastAPI app with optional .env"
	@echo "  make check        compile + Python/JS tests + i18n/design gates"

bootstrap:
	@test -n "$(BOOTSTRAP_PYTHON)" || { echo "Python 3.11+ is required"; exit 1; }
	@$(BOOTSTRAP_PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11+ is required")'
	@echo "Bootstrapping with $(BOOTSTRAP_PYTHON)"
	rm -rf .venv
	$(BOOTSTRAP_PYTHON) -m venv .venv
	.venv/bin/pip install --disable-pip-version-check -r requirements.txt

install:
	$(PYTHON) -m pip install --disable-pip-version-check -r requirements.txt

install-render:
	$(PYTHON) -m pip install --disable-pip-version-check $(OPTIONAL_RENDER_PKGS)
	$(PYTHON) -m playwright install chromium

run:
	$(PYTHON) -m uvicorn backend.app.main:app --host $(HOST) --port $(PORT) $(ENV_FILE_ARG)

dev:
	$(PYTHON) -m uvicorn backend.app.main:app --host $(HOST) --port $(PORT) --reload $(ENV_FILE_ARG)

test:
	PYTHONWARNINGS=ignore::DeprecationWarning $(PYTHON) -m pytest backend/tests -q

check:
	$(PYTHON) -m compileall -q backend
	$(PYTHON) ops/check_i18n.py
	$(NODE) ops/check_syntax.mjs
	$(NODE) --test extension/tests/core.test.js
	$(MAKE) test

verify-empty:
	$(PYTHON) ops/verify_empty.py

clean:
	rm -f backend/data/*.db backend/data/*.db-wal backend/data/*.db-shm
	rm -f backend/data/evidence/*.jpg backend/data/evidence/*.png backend/data/gallery/*.jpg backend/data/gallery/*.png

snapshot:
	mkdir -p snapshot
	cp backend/data/daggers.db snapshot/daggers.db 2>/dev/null || true
	cp -r backend/data/evidence snapshot/evidence 2>/dev/null || true
	@echo "Snapshot written to ./snapshot (not committed)."

deploy: check
	@echo "Deploy is a git push to the configured Hugging Face Space remote."
	@echo "Run: git push origin $(shell git branch --show-current)"
