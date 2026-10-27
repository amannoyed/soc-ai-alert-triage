"""
ir_report.py
════════════
Build an exportable incident report (NIST SP 800-61 structure) from a
pipeline investigation result.

Two audiences, one file:
  - Executive summary first: bottom line up front, impact, containment
    status, what leadership is being asked for.
  - Technical detail after: timeline, correlation alerts, IOCs, MITRE
    techniques, analyst reasoning, and explicitly listed limitations.

Honesty rules:
  - Containment / eradication / recovery actions are labeled RECOMMENDED
    unless the caller states otherwise — this report never claims an
    action was taken that was not.
  - Inferred items are marked as assessed, never as observed.
  - Visibility gaps are listed, not silently omitted.
"""

from datetime import datetime, timezone


def _ioc_parts(ioc):
    if isinstance(ioc, dict):
        return (ioc.get("type", "?"), ioc.get("value", "?"),
                ioc.get("note", ""))
    return (getattr(ioc, "type", "?"), getattr(ioc, "value", "?"),
            getattr(ioc, "note", ""))


def _plain(sev) -> str:
    for plain in ("Critical", "High", "Medium", "Low"):
        if plain in str(sev):
            return plain
    return "Low"


def build_ir_report(inv, timeline=None, correlation=None,
                    final_score=None, severity=None,
                    unique_ips=None) -> str:
    """Render the full report as Markdown. All inputs are optional-safe."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev = _plain(severity) if severity is not None else "Unknown"
    lines = []
    lines.append(f"# Incident Report — {inv.case_id}")
    lines.append("")
    lines.append(f"Generated: {now} · Source: SOC AI Triage Console")
    lines.append("")

    # ── Executive summary ──────────────────────────────────────────────
    lines.append("## Executive Summary (BLUF)")
    lines.append("")
    lines.append(f"**Classification:** {inv.attack_classification}")
    lines.append(f"**Confidence:** {inv.confidence}%")
    lines.append(f"**Severity:** {sev}"
                 + (f" · Final risk score: {final_score}/100"
                    if final_score is not None else ""))
    lines.append("")
    lines.append(inv.attack_summary)
    lines.append("")
    if unique_ips:
        lines.append(f"**Affected indicators:** {len(unique_ips)} unique IP(s) "
                     f"observed in the uploaded evidence.")
        lines.append("")
    lines.append("**Containment status:** NOT YET CONTAINED by this report — "
                 "see Recommended Actions. This document is an analysis "
                 "product, not evidence of response.")
    lines.append("")

    # ── NIST phases ────────────────────────────────────────────────────
    lines.append("## Response Plan (NIST SP 800-61)")
    lines.append("")
    lines.append("### Detection & Analysis")
    lines.append("")
    for i, step in enumerate(inv.reasoning_steps, 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append("### Containment — RECOMMENDED")
    lines.append("")
    lines.append("- Isolate affected hosts from the network pending triage.")
    lines.append("- Disable or rotate credentials observed in the incident.")
    lines.append("- Preserve logs and memory images before remediation "
                 "(chain of custody).")
    lines.append("")
    lines.append("### Eradication — RECOMMENDED")
    lines.append("")
    lines.append("- Remove persistence mechanisms identified in the timeline.")
    lines.append("- Hunt for the same indicators across the estate.")
    lines.append("")
    lines.append("### Recovery — RECOMMENDED")
    lines.append("")
    lines.append("- Restore affected systems from known-good images.")
    lines.append("- Monitor for reoccurrence of the same techniques for "
                 "30 days.")
    lines.append("")
    lines.append("### Post-Incident")
    lines.append("")
    lines.append("- Convert this incident's techniques into detection rules "
                 "(see the Detection Library tab).")
    lines.append("- Record lessons learned and update runbooks.")
    lines.append("")

    # ── Timeline ───────────────────────────────────────────────────────
    entries = list(getattr(timeline, "entries", []) or [])
    if entries:
        lines.append("## Attack Timeline")
        lines.append("")
        lines.append("| When | Event | Stage | MITRE | Risk | Pivot |")
        lines.append("|---|---|---|---|---|---|")
        for e in entries:
            lines.append(f"| {getattr(e, 'timestamp_rel', '?')} | "
                         f"{getattr(e, 'alert_type', '?')} | "
                         f"{getattr(e, 'stage', '?')} | "
                         f"{getattr(e, 'technique_id', '—') or '—'} | "
                         f"— | {'⬆' if getattr(e, 'is_pivot', False) else ''} |")
        lines.append("")

    # ── Correlation ────────────────────────────────────────────────────
    alerts = list(getattr(correlation, "alerts", []) or []) if correlation \
        else []
    if alerts:
        lines.append("## Correlation Alerts")
        lines.append("")
        for a in alerts:
            lines.append(f"- **{a.name}** ({a.severity}, "
                         f"confidence {a.confidence}%): {a.description}")
        lines.append("")

    # ── IOCs + MITRE ───────────────────────────────────────────────────
    iocs = list(getattr(inv, "iocs", []) or [])
    if iocs:
        lines.append("## Indicators of Compromise")
        lines.append("")
        lines.append("| Type | Value | Note |")
        lines.append("|---|---|---|")
        for ioc in iocs:
            t, v, n = _ioc_parts(ioc)
            lines.append(f"| {t} | `{v}` | {n} |")
        lines.append("")

    techniques = sorted({getattr(e, "technique_id", "")
                         for e in entries if getattr(e, "technique_id", "")})
    if techniques:
        lines.append("## MITRE ATT&CK Techniques Observed")
        lines.append("")
        lines.append(", ".join(f"`{t}`" for t in techniques))
        lines.append("")

    # ── Limitations ────────────────────────────────────────────────────
    lines.append("## Limitations & Visibility Gaps")
    lines.append("")
    lines.append("- Evidence is limited to the logs uploaded for this "
                 "investigation; absence of a technique here is absence of "
                 "evidence, not evidence of absence.")
    lines.append("- Scores and classifications are pipeline assessments "
                 "from observable signals; analyst review is required "
                 "before action.")
    lines.append("- Timestamps are as parsed from the source logs.")
    lines.append("")
    return "\n".join(lines)
