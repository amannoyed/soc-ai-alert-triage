"""
scripts/calibrate.py
════════════════════
Measure the scorer instead of defending it.

Runs the REAL pipeline (rules + Isolation Forest + UEBA + correlation,
ingest=False so the triage queue is never touched) over a labelled
synthetic corpus (data/calibration_corpus.json) and reports:

  - accuracy on the corpus
  - UNDER-TRIAGED cases (should have reached an analyst, did not) —
    the number that matters; any count above zero exits 1
  - OVER-TRIAGED cases (benign, but escalated)

Honesty notes:
  - Corpus IPs are 203.0.113.0/24 (TEST-NET documentation range) so no
    real address is implicated and no pre-existing UEBA profile for a
    demo IP pollutes the run.
  - The pipeline persists UEBA profiles on every run, so this script
    snapshots model/ueba_profiles.json and restores it afterwards —
    calibration must not train production baselines on synthetic data.
  - The corpus encodes the author's expectations, not ground truth.
    Replace it with labelled real alerts before tuning any weight.

Usage:  python scripts/calibrate.py
"""

import json
import os
import shutil
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_BASE = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_BASE, "src"))

from soc_pipeline import run_from_logs  # noqa: E402
from scoring_engine import ScoringConfig  # noqa: E402

_CORPUS = os.path.join(_BASE, "data", "calibration_corpus.json")
_UEBA = os.path.join(_BASE, "model", "ueba_profiles.json")


def main() -> int:
    with open(_CORPUS) as f:
        data = json.load(f)
    cases = data["cases"] if isinstance(data, dict) else data
    print(f"Calibration corpus: {len(cases)} labelled cases\n")

    # Snapshot UEBA profiles — calibration must not train on synthetic data.
    tmp = None
    if os.path.exists(_UEBA):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        shutil.copyfile(_UEBA, tmp.name)
    try:
        results = []
        for case in cases:
            pr = run_from_logs(case["events"], ScoringConfig(), ingest=False)
            predicted = bool(pr.is_threat)
            expected = bool(case["expected_escalate"])
            verdict = ("OK" if predicted == expected else
                       "UNDER-TRIAGED" if expected and not predicted else
                       "OVER-TRIAGED")
            results.append((case, pr, predicted, verdict))
            print(f"{verdict:14s} {case['name']:28s} "
                  f"score={pr.final_score:3d} sev={pr.severity} "
                  f"(expected escalate={expected})")
    finally:
        if tmp is not None:
            shutil.copyfile(tmp.name, _UEBA)
            os.unlink(tmp.name)

    under = [r for r in results if r[3] == "UNDER-TRIAGED"]
    over = [r for r in results if r[3] == "OVER-TRIAGED"]
    correct = len(results) - len(under) - len(over)
    print(f"\nAccuracy: {correct}/{len(results)}")
    print(f"Under-triaged (the number that matters): {len(under)}")
    for case, _, _, _ in under:
        print(f"  - {case['name']}: {case['note']}")
    print(f"Over-triaged: {len(over)}")
    for case, _, _, _ in over:
        print(f"  - {case['name']}: {case['note']}")
    print("\nUEBA profiles restored; triage queue untouched (ingest=False).")
    return 1 if under else 0


if __name__ == "__main__":
    raise SystemExit(main())
