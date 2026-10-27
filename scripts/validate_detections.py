"""
scripts/validate_detections.py
══════════════════════════════
Test the Sigma detection library WITHOUT a SIEM:

  - every rule has the required fields (title, id, detection, FP notes,
    level, ATT&CK tags, SPL/KQL translations, test cases)
  - the positive test event matches the rule's selection logic
  - the negative test event does NOT match

Matcher scope (honest limits, printed in the report):
  - scalar equality, list membership, |contains, |endswith
  - `selection and not <filter>` exclusion filters
  - aggregation conditions (count()) are NOT executed — the selection
    fields are checked and the threshold is flagged for review
  - time_condition (e.g. off-hours) is NOT machine-checked — it must be
    enforced in the SIEM query; the validator confirms it is documented

Exit 0 when every rule passes, 1 otherwise.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "src"))

from detection_library import load_detections, validate_rule_shape


def _match(criteria: dict, event: dict) -> bool:
    """True if the event satisfies every criterion in the selection dict."""
    for raw_key, expected in criteria.items():
        parts = raw_key.split("|")
        field, ops = parts[0], parts[1:]
        if field not in event:
            return False
        actual = str(event[field])
        expected_list = expected if isinstance(expected, list) else [expected]
        if "contains" in ops:
            if not any(str(e).lower() in actual.lower()
                       for e in expected_list):
                return False
        elif "endswith" in ops:
            if not any(actual.lower().endswith(str(e).lower())
                       for e in expected_list):
                return False
        else:
            if actual not in [str(e) for e in expected_list]:
                return False
    return True


def evaluate(rule: dict, event: dict) -> tuple[bool, str]:
    """
    Evaluate one event against a rule. Returns (matched, note).
    Aggregation and time conditions are flagged, not executed.
    """
    det = rule["detection"]
    selection = det.get("selection", {})
    condition = str(det.get("condition", "selection"))
    notes = []
    if "count()" in condition:
        notes.append("aggregation (count) — threshold reviewed, not executed")
        return _match(selection, event), "; ".join(notes)
    matched = _match(selection, event)
    for key, filt in det.items():
        if key.startswith("filter") and f"not {key}" in condition:
            if _match(filt, event):
                matched = False
    if "time_condition" in det:
        notes.append(f"time condition documented, not machine-checked: "
                     f"{det['time_condition']}")
    return matched, "; ".join(notes)


def main() -> int:
    rules = load_detections()
    print(f"Detection library: {len(rules)} rules\n")
    failures = 0
    for rule in rules:
        problems = validate_rule_shape(rule)
        line = f"[{rule.get('id', '?')}] {rule.get('title', '?')} " \
               f"({rule.get('level', '?')}) — {rule.get('_file', '?')}"
        if problems:
            print(f"FAIL {line}\n     shape: {'; '.join(problems)}")
            failures += 1
            continue
        pos, pos_note = evaluate(rule, rule["tests"]["positive"])
        neg, _ = evaluate(rule, rule["tests"]["negative"])
        ok = pos and not neg
        notes = f" [{pos_note}]" if pos_note else ""
        status = "PASS" if ok else "FAIL"
        print(f"{status} {line}{notes}")
        if not ok:
            print(f"     positive matched={pos} (want True), "
                  f"negative matched={neg} (want False)")
            failures += 1
    print(f"\n{len(rules) - failures}/{len(rules)} rules pass.")
    print("Limits: aggregation thresholds and time conditions are reviewed, "
          "not executed — see per-rule notes.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
