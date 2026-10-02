---
description: Log a structured finding (foothold / flag / confirmed vuln) for the report
argument-hint: [short title]
---

Record a finding NOW — undocumented points are lost points (no re-exploit after the clock).

Follow the `reporting` skill's finding schema. Gather from the recent context:

- Title, target IP/host, the zone/range it belongs to
- Severity (Critical/High/Medium/Low) and CVSS if applicable
- The exact command(s) that worked and the key output
- Proof captured (flag value, and the `whoami; hostname; ip a` that proves access)
- Business impact (one line) and remediation (one line)
- Any loot file + its `sha256sum`

Write it with `bin/cpent finding new --ip <ip> --zone <zone> --sev <sev> --title "..."`,
then append the detail. Remind the operator to screenshot before/after with IP + timestamp
visible if they haven't — you can't capture their screen.

$ARGUMENTS
