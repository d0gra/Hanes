---
description: Run a command with auto-evidence capture — saves output, hashes it, auto-detects creds and dual-NICs
argument-hint: <command> --ip <target-ip>
---

Execute a command through the evidence engine. This automatically:
1. Saves timestamped output under `engagement/targets/<ip>/`
2. Computes and records sha256 of the evidence file
3. Scans output for credentials (user/pass patterns, NTLM hashes, Kerberos tickets)
4. Detects multiple network interfaces (dual-NIC = pivot candidate)
5. Detects proof-of-access markers (whoami output)

Run: `bin/cpent ev "$ARGUMENTS"`

After capture, if credentials were detected, record confirmed ones with `bin/cpent cred add`.
If a dual-NIC was detected, immediately flag it and load the pivoting skill.
