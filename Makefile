# One command: `make eval` (or `docker build -t gravit-eval . && docker run --rm gravit-eval`)
VERIFIER_TAG := v0.5.0
GROVER_REF   := 4ad9e5ca1c53548ccaefb91647905ad8945c0da1
PYTHON ?= python3
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
	$(PYTHON) -m venv .venv
	$(PY) -m pip install -q -e .deps/verifier numpy scipy scikit-learn

clean:
	rm -rf .deps .venv

.PHONY: eval deps clean
