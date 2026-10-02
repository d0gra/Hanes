#!/usr/bin/env python3
"""Auto-summary generator: produces a live engagement dashboard from all tracked state.
Run it anytime or on a timer to get current status."""
import csv
import datetime
import glob
import os
import re
import sys

ENG = os.environ.get("HANES_ENGAGEMENT", "engagement")
SCOPE = os.path.join(ENG, "scope.txt")
CREDS = os.path.join(ENG, "credentials.csv")
FINDINGS = os.path.join(ENG, "findings")
EVIDENCE = os.path.join(ENG, "evidence")
MAP = os.path.join(ENG, "network-map.md")
TIMER = os.path.join(ENG, ".session_start")
SUMMARY_OUT = os.path.join(ENG, "summary.md")

ZONES = [
    ("network-system", 500), ("active-directory", 375), ("binary", 375),
    ("web", 250), ("iot-wireless", 250), ("defense-evasion", 250),
    ("privesc", 250), ("pivoting", 125), ("reporting", 125),
]
TOTAL_PTS = 2500
PASS_PCT = 70


def _read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def _read_creds():
    if not os.path.exists(CREDS):
        return []
    with open(CREDS, newline="") as f:
        return list(csv.DictReader(f))


def _finding_files():
    if not os.path.isdir(FINDINGS):
        return []
    return sorted(f for f in os.listdir(FINDINGS)
                  if f.endswith(".md") and not f.startswith("_"))


def _parse_finding(path):
    meta = {}
    with open(path) as f:
        for line in f:
            if line.startswith("# ") and "_title" not in meta:
                meta["_title"] = line[2:].strip()
            m = re.match(r"- (\w+): (.*)", line)
            if m:
                meta[m.group(1)] = m.group(2).strip()
    return meta


def _elapsed():
    if os.path.exists(TIMER):
        with open(TIMER) as f:
            start = datetime.datetime.fromisoformat(f.read().strip())
        delta = datetime.datetime.now() - start
        hours = delta.total_seconds() / 3600
        return f"{hours:.1f}h elapsed", hours
    return "timer not started", 0


def _evidence_count():
    if not os.path.isdir(EVIDENCE):
        return 0
    return len([f for f in os.listdir(EVIDENCE) if os.path.isfile(os.path.join(EVIDENCE, f))])


def _target_dirs():
    td = os.path.join(ENG, "targets")
    if not os.path.isdir(td):
        return []
    return [d for d in os.listdir(td) if os.path.isdir(os.path.join(td, d)) and d != "_template.md"]


def generate_summary(to_file=True):
    elapsed_str, hours = _elapsed()
    scope_entries = _read_lines(SCOPE)
    creds = _read_creds()
    findings_meta = [_parse_finding(os.path.join(FINDINGS, f)) for f in _finding_files()]
    ev_count = _evidence_count()
    targets = _target_dirs()

    # Zone coverage
    zone_counts = {}
    zone_sevs = {}
    for z, _ in ZONES:
        zone_counts[z] = 0
        zone_sevs[z] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for m in findings_meta:
        z = m.get("zone", "")
        if z in zone_counts:
            zone_counts[z] += 1
            sev = m.get("severity", "")
            if sev in zone_sevs[z]:
                zone_sevs[z][sev] += 1

    touched = sum(1 for z, _ in ZONES if zone_counts[z] > 0)
    untouched = [z for z, _ in ZONES if zone_counts[z] == 0 and z != "reporting"]

    # Unique hosts with creds
    cred_hosts = set(c.get("ip", "") for c in creds if c.get("ip"))
    unique_users = set(c.get("user", "") for c in creds if c.get("user"))

    # Build summary
    lines = []
    lines.append("# Engagement Summary")
    lines.append(f"\n**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Session:** {elapsed_str}")
    lines.append("")

    # Quick stats bar
    lines.append("## Quick Stats")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Scope ranges | {len(scope_entries)} |")
    lines.append(f"| Targets touched | {len(targets)} |")
    lines.append(f"| Findings logged | {len(findings_meta)} |")
    lines.append(f"| Credentials collected | {len(creds)} ({len(unique_users)} unique users, {len(cred_hosts)} hosts) |")
    lines.append(f"| Evidence files | {ev_count} |")
    lines.append(f"| Zones covered | {touched}/{len(ZONES)} |")
    lines.append("")

    # Zone coverage with progress bars
    lines.append("## Zone Coverage")
    lines.append("")
    lines.append("| Zone | Max Pts | Findings | Coverage | Status |")
    lines.append("|---|---|---|---|---|")
    for z, pts in ZONES:
        count = zone_counts[z]
        bar = "█" * min(count, 10) + "░" * max(0, 10 - count)
        if count == 0 and z != "reporting":
            status = "⚠️ UNTOUCHED"
        elif count >= 3:
            status = "✅ Good"
        else:
            status = "🔶 Started"
        lines.append(f"| {z} | {pts} | {count} | {bar} | {status} |")
    lines.append("")

    # Warnings
    lines.append("## Alerts")
    lines.append("")
    if untouched:
        lines.append(f"🚨 **{len(untouched)} untouched zone(s):** {', '.join(untouched)}")
        lines.append("   → Get at least one finding in each before going deep on any.")
    if hours > 0 and hours < 12 and len(findings_meta) < 5:
        lines.append(f"⏰ **Low output rate:** {len(findings_meta)} findings in {hours:.1f}h. "
                      "Target low-hanging fruit first.")
    if hours > 10 and not os.path.exists(os.path.join(ENG, "report-draft.md")):
        lines.append("📝 **No report draft yet.** Start assembling now — run `bin/cpent report`.")

    # Check for findings missing required fields
    incomplete = []
    for m in findings_meta:
        missing = []
        if not m.get("severity"):
            missing.append("severity")
        if not m.get("target"):
            missing.append("target")
        if missing:
            incomplete.append(f"  - {m.get('_title', '?')}: missing {', '.join(missing)}")
    if incomplete:
        lines.append(f"⚠️ **{len(incomplete)} finding(s) with missing fields:**")
        lines.extend(incomplete)
    lines.append("")

    # Credential summary
    if creds:
        lines.append("## Credentials")
        lines.append("")
        lines.append("| IP | User | Type | Source |")
        lines.append("|---|---|---|---|")
        for c in creds[-15:]:  # last 15
            ctype = "hash" if c.get("hash") else "password"
            lines.append(f"| {c.get('ip','')} | {c.get('user','')} | {ctype} | {c.get('source','')} |")
        if len(creds) > 15:
            lines.append(f"| ... | +{len(creds)-15} more | | |")
        lines.append("")
        lines.append(f"**Tip:** {len(creds)} creds on hand. Try spraying untested hosts before brute-forcing.")

    # Recent findings
    if findings_meta:
        lines.append("")
        lines.append("## Recent Findings")
        lines.append("")
        lines.append("| # | Severity | Zone | Target | Title |")
        lines.append("|---|---|---|---|---|")
        for i, m in enumerate(findings_meta[-10:], 1):
            lines.append(f"| {i} | {m.get('severity','?')} | {m.get('zone','?')} | "
                         f"{m.get('target','?')} | {m.get('_title','')} |")
    lines.append("")

    # Recommendation
    lines.append("## Next Move")
    lines.append("")
    if not scope_entries:
        lines.append("→ Set your scope first: `bin/cpent scope add <cidr> <label>`")
    elif untouched:
        pick = max(untouched, key=lambda z: dict(ZONES)[z])
        lines.append(f"→ Highest-value untouched zone: **{pick}** ({dict(ZONES)[pick]} pts). "
                      "Grab a quick win there.")
    else:
        lines.append("→ All zones touched. Deepen the highest-value zones and pursue DA/root.")
    lines.append("")

    body = "\n".join(lines)

    if to_file:
        with open(SUMMARY_OUT, "w") as f:
            f.write(body)
        print(f"Summary written: {SUMMARY_OUT}")

    print(body)
    return body


def start_timer():
    """Record session start time."""
    os.makedirs(ENG, exist_ok=True)
    now = datetime.datetime.now()
    with open(TIMER, "w") as f:
        f.write(now.isoformat())
    print(f"Session timer started at {now.strftime('%Y-%m-%d %H:%M:%S')}")


def main():
    import argparse
    p = argparse.ArgumentParser(prog="summary")
    sub = p.add_subparsers(dest="action")

    sub.add_parser("generate", help="Generate engagement summary")
    sub.add_parser("start-timer", help="Start the session timer")
    sub.add_parser("quick", help="Print a one-line status")

    args = p.parse_args()
    action = args.action or "generate"

    if action == "generate":
        generate_summary()
    elif action == "start-timer":
        start_timer()
    elif action == "quick":
        elapsed_str, _ = _elapsed()
        findings = _finding_files()
        creds = _read_creds()
        print(f"[{elapsed_str}] {len(findings)} findings | {len(creds)} creds | "
              f"{_evidence_count()} evidence files")


if __name__ == "__main__":
    main()
