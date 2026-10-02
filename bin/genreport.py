#!/usr/bin/env python3
"""Assemble the CPENT report from the engagement log into the report template.
Fills the FINDINGS / NETWORKMAP / CREDENTIALS placeholders; flags incomplete findings.
Prints to stdout — redirect to engagement/report-draft.md."""
import csv
import os
import re
import sys

ENG = os.environ.get("HANES_ENGAGEMENT", "engagement")
FINDINGS = os.path.join(ENG, "findings")
CREDS = os.path.join(ENG, "credentials.csv")
MAP = os.path.join(ENG, "network-map.md")
TMPL = os.path.join("templates", "report-template.md")

REQUIRED = ["severity", "target"]
SECTIONS_NEEDED = ["## Remediation", "## Business impact", "## Proof of access"]


def _finding_files():
    if not os.path.isdir(FINDINGS):
        return []
    return sorted(f for f in os.listdir(FINDINGS)
                  if f.endswith(".md") and not f.startswith("_"))


def _section_is_empty(text, header):
    # grab text from header to next "## " and check if it's blank/placeholder
    m = re.search(re.escape(header) + r"\n(.*?)(?=\n## |\Z)", text, re.S)
    if not m:
        return True
    body = re.sub(r"```.*?```", "", m.group(1), flags=re.S)
    body = re.sub(r"#.*", "", body)  # drop comment-ish lines
    return not body.strip()


def build_findings():
    out, gaps = [], []
    for fn in _finding_files():
        path = os.path.join(FINDINGS, fn)
        text = open(path).read()
        title = next((l[2:].strip() for l in text.splitlines() if l.startswith("# ")), fn)
        meta = dict(re.findall(r"- (\w+): (.*)", text))
        missing = [k for k in REQUIRED if not meta.get(k)]
        for h in SECTIONS_NEEDED:
            if _section_is_empty(text, h):
                missing.append(h.replace("## ", "").lower())
        if missing:
            gaps.append(f"  - {fn}: missing {', '.join(missing)}")
        out.append(text.strip() + "\n")
    body = "\n\n---\n\n".join(out) if out else "_(no findings logged)_"
    return body, gaps


def read_map():
    return open(MAP).read().strip() if os.path.exists(MAP) else "_(network map empty)_"


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


def main():
    if not os.path.exists(TMPL):
        sys.exit(f"template not found: {TMPL}")
    tmpl = open(TMPL).read()
    findings, gaps = build_findings()
    out = (tmpl
           .replace("<!-- FINDINGS -->", findings)
           .replace("<!-- NETWORKMAP -->", read_map())
           .replace("<!-- CREDENTIALS -->", read_creds()))
    print(out)
    if gaps:
        sys.stderr.write("\n=== REPORT GAPS (fix before submission) ===\n")
        sys.stderr.write("\n".join(gaps) + "\n")
        sys.stderr.write("Also verify: network diagram present, every finding screenshotted "
                         "(IP+timestamp), CVSS set.\n")


if __name__ == "__main__":
    main()
