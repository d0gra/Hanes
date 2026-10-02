---
description: Assemble the EC-Council-style penetration test report from the engagement log
---

Build the report. Do this between sessions and at the end — never leave it to memory.

1. Run `bin/cpent report` to assemble a draft from findings, credentials, and the network
   map into the `templates/report-template.md` structure.
2. Review the draft against the `reporting` skill's checklist:
   - Executive summary (1 page, non-technical, business risk)
   - Scope & methodology
   - Attack narrative — the graded centrepiece: step-by-step chain across segments, with
     the network diagram / pivot path
   - Findings: severity + CVSS, description, PoC (reference the screenshots), impact,
     remediation
   - Appendices: tool output, host/subnet map, command log, credential list
3. Flag gaps: findings missing remediation, missing severity, no proof reference, or no
   network diagram. List exactly what the operator still needs to screenshot or add.

Write the result to `engagement/report-draft.md`. Do not fabricate results — only report
what the findings log actually contains.

$ARGUMENTS
