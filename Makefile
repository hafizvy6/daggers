PYTHON ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)
BOOTSTRAP_PYTHON ?= $(shell for p in python3.11 python3.12 python3.13 python3.14 python3; do command -v $$p >/dev/null 2>&1 && { echo $$p; break; }; done)
NUMPY_PIN = $(shell $(PYTHON) -c 'import sys; print("numpy==2.5.5" if sys.version_info >= (3, 12) else "numpy==2.1.3")')
PORT ?= 8000
HOST ?= 0.0.0.0
export PYTHONPATH := $(CURDIR)

OPTIONAL_RENDER_PKGS = imagehash==4.3.2 $(NUMPY_PIN) opencv-python-headless==5.1.0.95 playwright==1.65.2 pytesseract==0.3.13

.PHONY: help bootstrap install install-render seed gallery dev demo test check clean deploy snapshot

help:
	@echo "Daggers: bootstrap · seed · dev · demo · test · check · gallery · deploy"

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

seed:
	$(PYTHON) -m backend.seed.seed --seed-only

gallery:
	$(PYTHON) -m backend.seed.seed --gallery --gallery-index

dev: seed
	MODE=live DEMO_MODE=0 CRT_ENABLED=0 FEEDS_ENABLED=0 ENRICH_ENABLED=0 RENDER_ENABLED=0 \
	$(PYTHON) -m uvicorn backend.app.main:app --host $(HOST) --port $(PORT) --reload

demo: seed
	MODE=demo DEMO_MODE=1 CRT_ENABLED=0 FEEDS_ENABLED=0 ENRICH_ENABLED=0 RENDER_ENABLED=0 \
	SWEEP_ALLOW_ARBITRARY=1 AI_PROVIDER=template \
	$(PYTHON) -m uvicorn backend.app.main:app --host $(HOST) --port $(PORT)

test:
	PYTHONWARNINGS=ignore::DeprecationWarning $(PYTHON) -m pytest backend/tests -q

check:
	$(PYTHON) -m compileall -q backend
	$(MAKE) test

clean:
	rm -f backend/data/*.db backend/data/*.db-wal backend/data/*.db-shm
	rm -f backend/data/evidence/*.jpg backend/data/gallery/*.jpg backend/data/gallery/gallery_index.json

snapshot:
	mkdir -p snapshot
	cp backend/data/daggers.db snapshot/daggers.db 2>/dev/null || true
	cp -r backend/data/evidence snapshot/evidence 2>/dev/null || true
	@echo "Snapshot written to ./snapshot (not committed)."

deploy: check
	@echo "Deploy is a git push to the configured Hugging Face Space remote."
	@echo "Run: git push origin $(shell git branch --show-current)"
