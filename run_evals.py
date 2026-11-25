"""Golden evals: gate vs a plain regex denylist baseline.

Run:  python3 run_evals.py   ->  writes eval_report.json, prints a summary.
Metrics are computed from data/eval_labels.json — nothing is asserted by
hand. Planted malicious = categories "malicious" + "obfuscated".
Clean = categories "clean" + "borderline" (borderline may be stripped,
but must never be quarantined).
"""
from __future__ import annotations

import glob
import json
import os

from mcp_skill_gate import baseline_decision, load_bundle, load_registry, vet

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    with open(os.path.join(HERE, "data", "eval_labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)
    registry = load_registry(os.path.join(HERE, "data", "registry.json"))

    rows = []
    for path in sorted(glob.glob(os.path.join(HERE, "data", "bundles", "*.json"))):
        fname = os.path.basename(path)
        label = labels[fname]
        bundle = load_bundle(path)
        record = vet(bundle, registry)
        rows.append({
            "file": fname,
            "skill": record["skill"],
            "category": label["category"],
            "expected": label["expected"],
            "gate_decision": record["decision"],
            "baseline_decision": baseline_decision(bundle),
            "gate_correct": record["decision"] == label["expected"],
            "drift_detected": record["drift_detected"],
            "re_vetted_as_new": record["re_vetted_as_new"],
        })

    planted = [r for r in rows if r["category"] in {"malicious", "obfuscated"}]
    clean = [r for r in rows if r["category"] in {"clean", "borderline"}]
    gate_caught = [r for r in planted if r["gate_decision"] == "QUARANTINE"]
    base_caught = [r for r in planted if r["baseline_decision"] == "QUARANTINE"]
    drift = next(r for r in rows if r["category"] == "drift")

    report = {
        "bundles_evaluated": len(rows),
        "gate_decision_accuracy": round(sum(r["gate_correct"] for r in rows) / len(rows), 4),
        "planted_malicious_total": len(planted),
        "gate_planted_malicious_recall": round(len(gate_caught) / len(planted), 4),
        "gate_planted_malicious_missed": [r["skill"] for r in planted if r["gate_decision"] != "QUARANTINE"],
        "baseline_planted_malicious_recall": round(len(base_caught) / len(planted), 4),
        "baseline_planted_malicious_missed": [r["skill"] for r in planted if r["baseline_decision"] != "QUARANTINE"],
        "clean_total": len(clean),
        "clean_false_quarantine_rate": round(
            sum(r["gate_decision"] == "QUARANTINE" for r in clean) / len(clean), 4),
        "drift_check": {
            "skill": drift["skill"],
            "drift_detected": drift["drift_detected"],
            "re_vetted_as_new": drift["re_vetted_as_new"],
            "new_decision": drift["gate_decision"],
            "passed": bool(drift["drift_detected"] and drift["re_vetted_as_new"]
                           and drift["gate_decision"] == "QUARANTINE"),
        },
        "rows": rows,
    }
    out = os.path.join(HERE, "eval_report.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"bundles evaluated:        {report['bundles_evaluated']}")
    print(f"gate decision accuracy:   {report['gate_decision_accuracy']}")
    print(f"gate planted recall:      {report['gate_planted_malicious_recall']} "
          f"({len(gate_caught)}/{len(planted)}), missed: {report['gate_planted_malicious_missed']}")
    print(f"baseline planted recall:  {report['baseline_planted_malicious_recall']} "
          f"({len(base_caught)}/{len(planted)}), missed: {report['baseline_planted_malicious_missed']}")
    print(f"clean false-quarantine:   {report['clean_false_quarantine_rate']} (of {len(clean)} clean/borderline)")
    print(f"drift re-vet passed:      {report['drift_check']['passed']}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
