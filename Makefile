# One command: `make eval` (or `docker build -t gravit-eval . && docker run --rm gravit-eval`)
VERIFIER_TAG := v0.5.0
GROVER_REF   := 4ad9e5ca1c53548ccaefb91647905ad8945c0da1
# First interpreter >= 3.10 found (macOS ships python3 3.9); override with `make eval PYTHON=...`.
PYTHON ?= $(firstword $(foreach p,python3 python3.13 python3.12 python3.11 python3.10,$(if $(shell $(p) -c 'import sys; print(sys.version_info >= (3, 10))' 2>/dev/null | grep True),$(p))) python3)
PY := .venv/bin/python

eval: deps
	$(PY) -m eval.run

deps: .deps/verifier .deps/grover .venv
.deps/verifier:
	git -c advice.detachedHead=false clone -q --depth 1 --branch $(VERIFIER_TAG) https://github.com/gravit-open-network-foundation/verifier.git $@
.deps/grover:
	git clone -q https://github.com/gravit-open-network-foundation/gravit-grover.git $@
	git -C $@ -c advice.detachedHead=false checkout -q $(GROVER_REF)
.venv:
	@$(PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python >= 3.10 required, found " + sys.version.split()[0] + " ($(PYTHON)); run: make eval PYTHON=python3.12")'
	$(PYTHON) -m venv .venv.tmp
	.venv.tmp/bin/python -m pip install -q .deps/verifier numpy scipy scikit-learn || { rm -rf .venv.tmp; exit 1; }
	mv .venv.tmp .venv

clean:
	rm -rf .deps .venv .venv.tmp

.PHONY: eval deps clean
