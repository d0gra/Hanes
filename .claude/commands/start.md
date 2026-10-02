---
description: Initialize the exam session — start timer, verify scope, and show the game plan
---

Exam session startup sequence:

1. Start the session timer: `bin/cpent start`
2. Verify scope is set: `bin/cpent scope list`
   - If empty, prompt the operator to add their assigned ranges.
3. Show the initial game plan — the 12-hour split strategy:
   - Hours 0–2: Full recon of all visible subnets. Map every host.
   - Hours 2–4: Lowest-hanging fruit — default creds, obvious web vulns, open shares.
   - Hours 4–8: Network/system exploitation, pop shells, build tunnels, start AD enum.
   - Hours 8–11: Harder targets — binary, IoT/OT, AD chains.
   - Hours 11–12: Stop exploiting. Review captures, organize notes, draft report.
4. Remind: **Save button on every answer in the exam platform!**
5. Run `bin/cpent summary` to show the initial dashboard.

$ARGUMENTS
