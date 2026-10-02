---
description: Run the recon/enumeration playbook against an in-scope target
argument-hint: <target-ip-or-cidr>
---

Enumerate `$ARGUMENTS` following the `recon-enum` skill.

First: `bin/cpent scope check $ARGUMENTS`. If it is not in scope, STOP and ask the operator
to confirm and add it — do not scan first.

Then work the recon-enum checklist in order (host discovery → full port scan →
service/script scan → per-service enumeration). For each step, give the exact command, say
what it touches, and interpret the output. Save raw output under
`engagement/targets/$ARGUMENTS/`. Create/update the target note with
`bin/cpent target note $ARGUMENTS`.

Flag immediately: dual-NIC indicators, default-cred candidates, and anything that is a
likely quick win. End by recommending the first exploitation move and which skill to load.
