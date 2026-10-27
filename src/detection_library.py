"""
detection_library.py
════════════════════
Load the Sigma detection library (detections/*.yml) for the console.

The rules are Sigma — the vendor-neutral industry format — with a
first-pass SPL/KQL translation stored alongside each rule. Translations
are labeled first-pass in the rule files: field names must be reviewed
against the target SIEM schema before deployment (field misalignment is
the #1 cause of dead rules).
"""

import glob
import os

import yaml

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DET_DIR = os.path.join(_BASE, "detections")

REQUIRED_FIELDS = ("title", "id", "status", "description", "logsource",
                   "detection", "falsepositives", "level", "tags",
                   "spl", "kql", "tests")


def load_detections() -> list[dict]:
    """All rules, sorted by filename, each annotated with its source file."""
    rules = []
    for path in sorted(glob.glob(os.path.join(_DET_DIR, "*.yml"))):
        with open(path) as f:
            rule = yaml.safe_load(f)
        rule["_file"] = os.path.basename(path)
        rules.append(rule)
    return rules


def validate_rule_shape(rule: dict) -> list[str]:
    """Missing-field check only; logic tests live in validate_detections.py."""
    missing = [f for f in REQUIRED_FIELDS if f not in rule]
    problems = [f"missing field: {f}" for f in missing]
    det = rule.get("detection", {})
    if not isinstance(det, dict) or "selection" not in det:
        problems.append("detection.selection missing")
    tests = rule.get("tests", {})
    if not isinstance(tests, dict) or "positive" not in tests \
            or "negative" not in tests:
        problems.append("tests.positive/negative missing")
    return problems
