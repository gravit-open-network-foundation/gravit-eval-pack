# Gravit evaluation pack

**Can an outside researcher verify the Gravit verification stack in five minutes, without
trusting us?** This repository is the answer. One command fetches the public code at pinned
versions, runs it, and prints every result. Nothing in the results was typed by hand.

```bash
git clone https://github.com/gravit-open-network-foundation/gravit-eval-pack
cd gravit-eval-pack
make eval                    # Python ≥ 3.10; or:
docker build -t gravit-eval . && docker run --rm gravit-eval
```

## What it checks

1. **Verifier conformance.** All 40 golden vectors of the
   [Gravit Verifier](https://github.com/gravit-open-network-foundation/verifier) v0.5.0 (the
   reference implementation of VEDS-00 / GEVP-07) are replayed and compared byte for byte,
   including each content-addressed `decision_id`.
2. **Adversarial benchmark.** The same vectors grouped by attack class: aggregation laundering
   (weak evidence presented as a fact), Sybil and non-independent sources, forged, tampered or
   replayed signatures, revoked keys, stale or malformed timestamps, missing provenance, missing
   trust root. For each case: what is claimed, what the verifier decides.
3. **Consensus under Sybil attack.** The 10x Sybil experiment and the 3000-claim
   theta_critical calibration of [gravit-grover](https://github.com/gravit-open-network-foundation/gravit-grover)
   at a pinned commit.

Results: [`BENCHMARK.md`](BENCHMARK.md) and `results/`. CI regenerates both on every change and
fails if a single byte differs; a second CI job builds and runs the Docker image.

## Scope, stated plainly

- The verifier decides whether evidence justifies a claimed epistemic state; it does not inspect
  model weights or internals.
- Registry and keys in the golden vectors are **test keys**. The Foundation's root key ceremony is
  planned; until then no claim of Sybil resistance in production is made.
- The theta_critical calibration does **not** support a uniquely calibrated threshold of 0.73:
  the error rates are flat over a wide range of theta. See BENCHMARK.md §3 and the technical note.

See also: [TECHNICAL_NOTE.md](TECHNICAL_NOTE.md) · IETF Internet-Drafts
[draft-gravit-gevp-07](https://datatracker.ietf.org/doc/draft-gravit-gevp/07/) and
[draft-gravit-verifiable-epistemic-decision-00](https://datatracker.ietf.org/doc/draft-gravit-verifiable-epistemic-decision/00/)
(individual submissions, not endorsed by the IETF).

Licence: Apache-2.0. Maintained by the Gravit Open Network Foundation, Zürich.
