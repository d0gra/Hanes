#!/usr/bin/env python3
"""Assemble the CPENT report from the engagement log into the report template.
Fills FINDINGS / NETWORKMAP / CREDENTIALS / NARRATIVE / TARGETNOTES placeholders and
flags incomplete findings. Also verifies evidence (screenshots on disk, network diagram)
so the report that gates 95% of the marks is actually gated. Prints to stdout; gaps to
stderr. Redirect stdout to engagement/report-draft.md."""
import csv
import os
import re
import sys

ENG = os.environ.get("HANES_ENGAGEMENT", "engagement")
FINDINGS = os.path.join(ENG, "findings")
CREDS = os.path.join(ENG, "credentials.csv")
MAP = os.path.join(ENG, "network-map.md")
EVIDENCE = os.path.join(ENG, "evidence")
TARGETS = os.path.join(ENG, "targets")
TMPL = os.path.join("templates", "report-template.md")

REQUIRED = ["severity", "target"]
SECTIONS_NEEDED = ["## Remediation", "## Business impact", "## Proof of access"]


def _finding_files():
    if not os.path.isdir(FINDINGS):
        return []
    return sorted(f for f in os.listdir(FINDINGS)
                  if f.endswith(".md") and not f.startswith("_"))


def _meta(text):
    return dict(re.findall(r"- (\w+): (.*)", text))


def _title(text, fallback):
    return next((l[2:].strip() for l in text.splitlines() if l.startswith("# ")), fallback)


def _section_is_empty(text, header):
    m = re.search(re.escape(header) + r"\n(.*?)(?=\n## |\Z)", text, re.S)
    if not m:
        return True
    body = re.sub(r"```.*?```", "", m.group(1), flags=re.S)
    body = re.sub(r"#.*", "", body)  # drop comment-ish lines
    return not body.strip()


def count_screenshots():
    """Count .png evidence on disk (screenshots the report's findings can reference)."""
    pngs = []
    for base in (EVIDENCE, TARGETS):
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base):
            pngs += [os.path.join(root, f) for f in files if f.lower().endswith(".png")]
    return pngs


def build_findings():
    out, gaps = [], []
    screenshots = count_screenshots()
    for fn in _finding_files():
        path = os.path.join(FINDINGS, fn)
        text = open(path).read()
        meta = _meta(text)
        missing = [k for k in REQUIRED if not meta.get(k)]
        for h in SECTIONS_NEEDED:
            if _section_is_empty(text, h):
                missing.append(h.replace("## ", "").lower())
        if not meta.get("cvss"):
            missing.append("cvss")
        # Evidence section should name at least one screenshot file
        if not _section_is_empty(text, "## Evidence"):
            ev_block = re.search(r"## Evidence\n(.*?)(?=\n## |\Z)", text, re.S)
            if ev_block and not re.search(r"\.png|\.jpg|sha256", ev_block.group(1), re.I):
                missing.append("evidence(screenshot/sha256)")
        else:
            missing.append("evidence(screenshot/sha256)")
        if missing:
            gaps.append(f"  - {fn}: missing {', '.join(missing)}")
        out.append(text.strip() + "\n")
    body = "\n\n---\n\n".join(out) if out else "_(no findings logged)_"
    return body, gaps, screenshots


def build_narrative():
    """Auto-draft the attack narrative: findings in chronological order (by ts).
    This is a scaffold for the operator to expand into prose, not a finished narrative."""
    rows = []
    for fn in _finding_files():
        text = open(os.path.join(FINDINGS, fn)).read()
        meta = _meta(text)
        rows.append((meta.get("ts", ""), meta.get("target", "?"),
                     meta.get("zone", "?"), meta.get("severity", "?"),
                     _title(text, fn)))
    rows.sort(key=lambda r: r[0])
    if not rows:
        return ("_(no findings yet — the narrative is built from the findings log in the "
                "order you discovered them)_")
    lines = ["_Auto-drafted from the findings log in discovery order. Expand each step into "
             "prose, and add the pivot path to the diagram below._\n"]
    for i, (ts, tgt, zone, sev, title) in enumerate(rows, 1):
        lines.append(f"{i}. **[{ts}]** `{tgt}` ({zone}, {sev}) — {title}")
    return "\n".join(lines)


def read_map():
    if not os.path.exists(MAP):
        return "_(network map empty)_"
    return open(MAP).read().strip() or "_(network map empty)_"


def read_target_notes():
    """Concatenate per-target notes into the appendix."""
    if not os.path.isdir(TARGETS):
        return "_(no per-target notes)_"
    blocks = []
    for ip in sorted(os.listdir(TARGETS)):
        note = os.path.join(TARGETS, ip, "notes.md")
        if ip.startswith("_") or not os.path.exists(note):
            continue
        content = open(note).read().strip()
        if content:
            blocks.append(f"#### {ip}\n\n{content}")
    return "\n\n".join(blocks) if blocks else "_(no per-target notes)_"


def read_creds():
    if not os.path.exists(CREDS):
        return "_(no credentials logged)_"
    rows = list(csv.DictReader(open(CREDS, newline="")))
    if not rows:
        return "_(no credentials logged)_"
    lines = ["| IP | User | Password | Hash | Source |", "|---|---|---|---|---|"]
    for r in rows:
        h = (r.get("hash", "")[:20] + "…") if r.get("hash") else ""
        lines.append(f"| {r.get('ip','')} | {r.get('user','')} | {r.get('password','')} "
                     f"| {h} | {r.get('source','')} |")
    return "\n".join(lines)


def map_has_diagram():
    """True if the network map has real content or references a diagram image."""
    if not os.path.exists(MAP):
        return False
    text = open(MAP).read()
    if re.search(r"\.png|\.jpg|\.svg|```|->|─|→", text):
        return True
    # non-trivial text (more than the template heading)
    return len(re.sub(r"[#\s]", "", text)) > 40


def main():
    if not os.path.exists(TMPL):
        sys.exit(f"template not found: {TMPL}")
    tmpl = open(TMPL).read()
    findings, gaps, screenshots = build_findings()
    out = (tmpl
           .replace("<!-- FINDINGS -->", findings)
           .replace("<!-- NARRATIVE -->", build_narrative())
           .replace("<!-- NETWORKMAP -->", read_map())
           .replace("<!-- TARGETNOTES -->", read_target_notes())
           .replace("<!-- CREDENTIALS -->", read_creds()))
    print(out)

    # ---- gate checks to stderr ----
    problems = list(gaps)
    if not screenshots:
        problems.append("  - NO SCREENSHOTS found on disk under engagement/evidence or "
                        "engagement/targets — the report needs IP+timestamp proof shots.")
    if not map_has_diagram():
        problems.append("  - network-map.md has no diagram/pivot path — the attack narrative "
                        "is graded on the network diagram.")
    if not _finding_files():
        problems.append("  - no findings logged — nothing to report.")

    if problems:
        sys.stderr.write("\n=== REPORT GAPS (fix before submission) ===\n")
        sys.stderr.write("\n".join(problems) + "\n")
        sys.stderr.write(f"\nEvidence on disk: {len(screenshots)} screenshot(s), "
                         f"{len(_finding_files())} finding(s).\n")
        sys.stderr.write("Verify every finding's screenshots show the target IP + a "
                         "timestamp, and that CVSS/severity are set.\n")
    else:
        sys.stderr.write(f"\n=== REPORT OK — {len(_finding_files())} findings, "
                         f"{len(screenshots)} screenshots, diagram present. ===\n")


if __name__ == "__main__":
    main()
