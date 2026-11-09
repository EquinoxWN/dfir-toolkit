.PHONY: setup lint test audit bench triage ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -e ".[dev,vol]"

# ruff, ruff format and mypy --strict, then the artifact gate.
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy && dfir artifacts check artifacts

# Unit, property and CLI tests; the `vol` tests run the installed Volatility 3.
test:
	$(PY) -m pytest -q -rs

# Known vulnerabilities in the installed Python dependencies.
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

# Stack a synthetic 10,000-host ProcessSnapshot hunt export.
bench:
	dfir hunt synth --hosts 10000 --seed 0 --out .tmp/bench/fleet-10000.jsonl
	dfir hunt stack .tmp/bench/fleet-10000.jsonl --artifact Custom.DFIR.Generic.ProcessSnapshot --json .tmp/bench/stack-10000.json

# Memory triage on the synthetic Volatility 3 fixtures.
triage:
	dfir memory triage tests/fixtures/memory/injected --md .tmp/triage-injected.md

ci: setup lint test audit
