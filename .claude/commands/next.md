---
description: ROI prioritizer — what to work on now given the clock and what's unsolved
---

Decide the operator's next move using points-per-hour, not interest.

1. Run `bin/cpent next` to get the current state: scope, solved vs. unsolved zones,
   points captured, credentials on hand, open pivots, and elapsed time.
2. Apply the exam ROI rules from `CLAUDE.md`:
   - Breadth beats depth — every range should have *some* score before any range gets a
     deep dive.
   - An open dual-NIC/pivot host outranks almost everything: it gates whole ranges.
   - Easy wins first: default creds, SMB shares, AS-REP/Kerberoast, obvious web vulns.
3. Recommend ONE concrete next target and the first command to run against it, plus the
   skill to load. If something long-running (crack/scan/spray) could be backgrounded in
   parallel, say so.

Keep it to a short, decisive recommendation — the operator is on a clock.

$ARGUMENTS
