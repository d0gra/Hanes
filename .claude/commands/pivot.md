---
description: Set up or reason about a pivot, and update the network map
argument-hint: [pivot-host-ip]
---

Work the `pivoting` skill. Pivoting is only 5% of marks but it GATES the ranges worth far
more — treat an open pivot as top priority.

1. Confirm the pivot host is compromised and has a second interface (from its host-triage
   output). If you don't yet know its interfaces, get them first.
2. Choose the tunnelling method per the skill (SSH `-D` SOCKS first if SSH is available,
   else chisel/ligolo/meterpreter autoroute). Give the exact commands for both ends and the
   proxychains config line.
3. Verify the tunnel with a single known port before full scanning
   (`proxychains curl`/`proxychains nmap -sT -Pn`).
4. Update `engagement/network-map.md`: add the new segment and the attacker → pivot → target
   chain. Note which hosts are dual-NIC.

$ARGUMENTS
