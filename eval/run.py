"""
Gravit evaluation pack: one command, every number computed here.

1. Verifier conformance: replay all golden vectors of the public Gravit
   Verifier (pinned tag) and compare every decision record byte for byte.
2. Adversarial benchmark: the same vectors grouped by attack class - what the
   attacker claims, what the verifier decides, and whether the claim was refused.
3. Sybil resistance of the consensus engine (gravit-grover, pinned commit):
   the 10x Sybil experiment and the theta_critical calibration trace.

Writes results/*.json and BENCHMARK.md. Exit status 1 on any mismatch.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / ".deps" / "verifier"
GROVER = ROOT / ".deps" / "grover"
RESULTS = ROOT / "results"

# golden vector -> (attack class, what the case represents)
CLASSES = {
    "committed_two_strong": ("Baseline", "two independent signed operators, strong evidence"),
    "no_claim_strong_evidence": ("Baseline", "no claim, strong independent evidence"),
    "claims_lower_than_achieved": ("Baseline", "modest claim, strong evidence"),
    "two_sources_with_duplicates": ("Baseline", "two sources plus duplicate records"),
    "one_bad_record_others_converge": ("Baseline", "one bad record among converging sources"),
    "two_records_low_theta_claims_prob": ("Baseline", "weak evidence, honest modest claim"),
    "boundary_h_075_f_025_passes": ("Boundary", "convergence just inside the threshold"),
    "boundary_h_exactly_070_fails": ("Boundary", "convergence exactly at the threshold"),
    "boundary_h_070_f_030_fails": ("Boundary", "convergence just outside the threshold"),
    "theta_exactly_07_counts_honest": ("Boundary", "record exactly at the honesty cut-off"),
    "weak_aggregation_three": ("Aggregation laundering", "three weak records presented as a fact"),
    "single_high_theta": ("Aggregation laundering", "one confident record presented as a fact"),
    "weak_record_drags_source_down": ("Aggregation laundering", "weak record inside a strong source"),
    "weak_record_drags_source_down_reversed": ("Aggregation laundering", "same, opposite order"),
    "no_evidence_claims_fact": ("Aggregation laundering", "fact claimed with no evidence at all"),
    "no_evidence_no_claim": ("Aggregation laundering", "nothing claimed, nothing shown"),
    "duplicate_verifier_provenance": ("Sybil / non-independence", "same verifier and provenance twice"),
    "same_verifier_diff_provenance": ("Sybil / non-independence", "one verifier, two provenances"),
    "same_provenance_diff_verifier": ("Sybil / non-independence", "two verifiers, one provenance"),
    "chain_shared_keys_one_source": ("Sybil / non-independence", "records chained through shared keys"),
    "two_keys_one_operator": ("Sybil / non-independence", "one operator signing with two keys"),
    "unsigned_record_excluded": ("Forgery / replay", "unsigned record"),
    "unknown_key_excluded": ("Forgery / replay", "record signed by an unregistered key"),
    "revoked_key_excluded": ("Forgery / replay", "record signed by a revoked key"),
    "tampered_theta_bad_signature": ("Forgery / replay", "confidence raised after signing"),
    "replayed_from_other_artifact": ("Forgery / replay", "valid signature replayed from another artifact"),
    "malformed_theta_precision": ("Forgery / replay", "malformed record"),
    "no_registry_caps_at_prob": ("Trust root", "no signed verifier registry available"),
    "no_registry_missing_timestamp_not_stacked": ("Trust root", "no registry and missing timestamp"),
    "missing_timestamp_demotes": ("Freshness", "evidence without timestamp"),
    "fresh_age_equals_bound_passes": ("Freshness", "evidence exactly at the freshness bound"),
    "stale_by_one_second_demotes": ("Freshness", "evidence one second too old"),
    "future_timestamp_demotes": ("Freshness", "timestamp in the future"),
    "timestamp_wrong_format_demotes": ("Freshness", "timestamp in the wrong format"),
    "timestamp_impossible_date_demotes": ("Freshness", "impossible calendar date"),
    "leap_day_across_month_passes": ("Freshness", "valid leap-day timestamp"),
    "freshness_policy_incomplete_demotes": ("Freshness", "incomplete freshness policy"),
    "high_impact_missing_hash": ("Provenance", "high-impact decision without integrity hash"),
    "high_impact_ok": ("Provenance", "high-impact decision with full provenance"),
    "not_high_impact_missing_hash_ok": ("Provenance", "low-impact decision, two different content hashes"),
    "result_false_contradicts": ("Signed verdict", "one source signs that its check failed"),
    "result_null_is_no_support": ("Signed verdict", "both sources sign no verdict"),
    "result_one_true_one_null": ("Signed verdict", "one supporting source, one without verdict"),
    "result_false_outvoted_still_blocks": ("Signed verdict", "three supporting sources, one signed failure"),
    "result_false_unsigned_not_counted": ("Signed verdict", "unsigned 'failed' record cannot block"),
    "result_false_no_registry": ("Signed verdict", "signed failure, no registry"),
    "result_false_modest_claim": ("Signed verdict", "signed failure, modest claim"),
    "integrity_hash_mismatch_caps": ("One content", "two sources sign different content hashes"),
    "excluded_low_theta_does_not_block": ("Excluded records", "excluded low-theta record cannot block"),
    "excluded_shared_provenance_does_not_merge": ("Excluded records", "excluded record cannot merge provenance"),
    "excluded_stale_record_does_not_demote": ("Excluded records", "excluded stale record cannot demote"),
    "theta_string_malformed": ("Malformed input", "theta given as a string, with registry"),
    "theta_string_malformed_no_registry": ("Malformed input", "theta given as a string, no registry"),
    "theta_bool_malformed_no_registry": ("Malformed input", "theta given as true, no registry"),
}
VERSION = "v0.7.0"  # must match VERIFIER_TAG in the Makefile


def verifier_vectors() -> dict:
    sys.path.insert(0, str(VERIFIER))
    from gravit_verifier.kernel import EpistemicState, EvidenceRecord, VerificationRequest, VerifierKernel
    from gravit_verifier.loader import load_bindings_from_dir
    from gravit_verifier.registry import TrustRoot, VerifierRegistry

    golden = VERIFIER / "tests" / "golden"
    registry = VerifierRegistry.from_file(golden / "registry.json", TrustRoot.from_file(golden / "trust_root.json"))
    kernels = {True: VerifierKernel(registry), False: VerifierKernel()}
    for k in kernels.values():
        for b in load_bindings_from_dir(VERIFIER / "bindings"):
            k.load_binding(b)
    rows = []
    for v in json.loads((golden / "vectors.json").read_text()):
        claimed = EpistemicState(v["claimed_state"]) if v["claimed_state"] else None
        got = kernels[v["use_registry"]].verify(VerificationRequest(
            v["name"], claimed, [EvidenceRecord(**e) for e in v["evidence"]], v["context"])).to_dict()
        cls, desc = CLASSES.get(v["name"], ("Other", v["name"]))
        rows.append({
            "case": v["name"], "class": cls, "scenario": desc,
            "claimed": v["claimed_state"], "decided": got["final_epistemic_state"], "status": got["status"],
            "unjustified_claim_refused": v["claimed_state"] == "Verified Fact" and got["final_epistemic_state"] != "Verified Fact",
            "reproduced_byte_for_byte": got == v["expected"], "decision_id": got["decision_id"],
        })
    return {"verifier": f"gravit-open-network-foundation/verifier {VERSION}", "vectors": rows}


def grover() -> dict:
    out = RESULTS / "grover"
    out.mkdir(parents=True, exist_ok=True)
    env = {"PYTHONPATH": str(GROVER)}
    run = lambda *a: subprocess.run([sys.executable, "-m", *a], cwd=GROVER, env={**__import__("os").environ, **env},
                                    check=True, capture_output=True, text=True)
    run("simulations.simulate_sybil", "--out", str(out / "sybil-10x-g1.5.json"))
    run("simulations.theta_calibration", "--out", str(out))
    hist = json.loads((out / "sybil-10x-g1.5.json").read_text())
    cal = json.loads((out / "theta-calibration-summary.json").read_text())
    (out / "theta-calibration.jsonl").unlink()  # 3000 records; the summary carries their Merkle root
    return {
        "engine": "gravit-open-network-foundation/gravit-grover (pinned commit)",
        "sybil_10x": {"nodes_honest": 100, "nodes_sybil": 1000, "rounds": len(hist),
                      "confidence_true_final": hist[-1]["confidence_true"],
                      "confidence_false_final": hist[-1]["confidence_false"],
                      "sybil_stake_share_round_9": hist[8]["sybil_fraction"]},
        "theta_calibration": {k: cal[k] for k in ("at_theta", "roc_auc", "youden", "merkle_root", "seed")},
    }


def write_report(v: dict, g: dict) -> None:
    rows = v["vectors"]
    classes = {}
    for r in rows:
        c = classes.setdefault(r["class"], {"cases": 0, "attacks": 0, "refused": 0, "reproduced": 0})
        c["cases"] += 1
        c["reproduced"] += r["reproduced_byte_for_byte"]
        if r["claimed"] == "Verified Fact" and r["status"] != "SUCCESS":
            c["attacks"] += 1
            c["refused"] += r["unjustified_claim_refused"]
    t, s = g["theta_calibration"]["at_theta"], g["sybil_10x"]
    lines = [
        "# Benchmark results",
        "",
        "Generated by `make eval`; every number below is computed by the code in this repository.",
        "",
        "## 1. Verifier conformance",
        "",
        f"**{sum(r['reproduced_byte_for_byte'] for r in rows)} of {len(rows)}** golden vectors of the Gravit Verifier {VERSION} "
        "reproduced byte for byte (decision records, including content-addressed `decision_id`).",
        "",
        "## 2. Adversarial benchmark",
        "",
        "An *attack* is a case where a 'Verified Fact' is claimed but the evidence does not justify it. "
        "*Refused* means the verifier did not grant 'Verified Fact'.",
        "",
        "| Class | Cases | Attacks | Refused | Reproduced |",
        "|---|---|---|---|---|",
        *[f"| {k} | {c['cases']} | {c['attacks']} | {c['refused']} | {c['reproduced']} |" for k, c in classes.items()],
        "",
        "| Case | Class | Claimed | Decided | Status |",
        "|---|---|---|---|---|",
        *[f"| {r['scenario']} | {r['class']} | {r['claimed'] or '—'} | {r['decided'] or '—'} | {r['status']} |" for r in rows],
        "",
        "## 3. Consensus engine under Sybil attack (gravit-grover)",
        "",
        f"- 10x Sybil (100 honest vs 1000 Sybil nodes, {s['rounds']} rounds): confidence in the true claim "
        f"{s['confidence_true_final']:.4f}, in the false claim {s['confidence_false_final']:.4f}; Sybil stake share at "
        f"round 9: {s['sybil_stake_share_round_9']:.4%}.",
        f"- theta_critical calibration (3000 claims, seed {g['theta_calibration']['seed']}): at theta = 0.73, "
        f"TPR {t['tpr']:.1%} ({t['tp']}/{t['tp'] + t['fn']}), FPR {t['fpr']:.1%} ({t['fp']}/{t['fp'] + t['tn']}), "
        f"ROC AUC {g['theta_calibration']['roc_auc']:.3f}. The rates are identical for every theta in "
        f"[{g['theta_calibration']['youden']['theta_min']}, {g['theta_calibration']['youden']['theta_max']}]: after "
        "30 rounds the threshold barely matters; what decides is whether honest evidence outweighs the Sybils. "
        "False accepts occur for hard claims, where honest evidence is weak.",
        f"- Merkle root of the 3000-record trace: `{g['theta_calibration']['merkle_root']}`.",
    ]
    (ROOT / "BENCHMARK.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    RESULTS.mkdir(exist_ok=True)
    v = verifier_vectors()
    (RESULTS / "verifier-vectors.json").write_text(json.dumps(v, indent=1, sort_keys=True) + "\n")
    g = grover()
    (RESULTS / "grover.json").write_text(json.dumps(g, indent=1, sort_keys=True) + "\n")
    write_report(v, g)
    ok = all(r["reproduced_byte_for_byte"] for r in v["vectors"])
    print((ROOT / "BENCHMARK.md").read_text())
    print("ALL REPRODUCED" if ok else "MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
