---
name: reporting
description: Report-writing and evidence discipline for CPENT — the finding schema, screenshot rules, and the EC-Council report structure. Use when logging findings and when assembling the report. The report gates your ability to claim every other point.
---

# Reporting & Evidence (Zone 9, 5% — gates the other 95%)

You cannot re-exploit after the clock stops, so an undocumented point is a lost point.
Document as you go; polish at the end. Report due 7 days after the exam.

## The finding schema (what `bin/cpent finding new` captures)

Each finding records:

- **Title** and **zone/range**
- **Target** IP / hostname
- **Severity** Critical/High/Medium/Low + **CVSS** where applicable
- **Description** — what the flaw is
- **PoC** — the exact command(s) that worked and the key output
- **Proof of access** — `whoami; hostname; ip a` (and the flag value) captured
- **Business impact** — one line
- **Remediation** — one line
- **Evidence** — screenshot filenames + any loot file and its `sha256sum`

## Screenshot rules

**Command-line evidence is auto-captured.** Every `bin/cpent ev`/`ev-scan`/`ev-proof`
renders the command + its real output into an annotated PNG (target IP + timestamp
banners, sha256-hashed), saved under `engagement/targets/<ip>/` and the session evidence
folder. For CLI tools (nmap, whoami, secretsdump, hydra hits, cracked hashes) you do **not**
need a manual screenshot — run it through the evidence engine and the proof image exists.

**The operator still manually screenshots GUI evidence** (you can't):
- Browser/Burp views, web-app exploitation, admin panels.
- RDP/VNC desktop sessions, GUI tools (Immunity, Wireshark, BloodHound).
- Use `bin/cpent screenshot --ip <ip>` on the GUI session (IP + timestamp overlaid).

Rules for both: every image shows the **target IP and a timestamp**; proof-of-access shows
`whoami`/`id`, `hostname`, `ip a`; capture before **and** after exploitation. Lost access =
no re-shot evidence, so capture as you go.

## EC-Council report structure (see `templates/report-template.md`)

1. **Executive Summary** — 1 page, non-technical, business-risk language.
2. **Scope & Methodology** — what was tested, tools, approach.
3. **Attack Narrative** — the graded centrepiece: step-by-step chain across segments with a
   **network diagram** of the pivot path.
4. **Findings** — per vuln: severity+CVSS, description, PoC w/ screenshots, impact,
   remediation.
5. **Appendices** — tool output, host/subnet map, command log, credential list.

## Common point-losers to check for

No flag screenshot · missing remediation · no network diagram · missing CVSS/severity ·
sloppy formatting. `bin/cpent report` flags findings missing any required field.

Never fabricate a result — report only what the findings log contains.
