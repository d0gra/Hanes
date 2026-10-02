---
name: recon-enum
description: Reconnaissance and enumeration playbook for CPENT Range 1 (Network & System). Use at the start of every target and whenever landing a new shell — host discovery, port/service scanning, per-service enumeration, and the host-triage block that finds pivots.
---

# Recon & Enumeration (Zone 1 — Network & System, 20%)

Broadest surface, easiest quick wins, and every shell here is a stepping stone deeper.
**Always `bin/cpent scope check <ip>` before touching a target.**

## Discovery → scanning (work in order, use evidence capture)

Use `bin/cpent ev-scan` to auto-save and auto-detect:

```
bin/cpent ev-scan 10.10.10.0/24 --type discovery     # host discovery
bin/cpent ev-scan <t> --type full                     # full TCP port sweep
bin/cpent ev-scan <t> --type service --ports 80,445   # service + scripts
bin/cpent ev-scan <t> --type vuln                     # vuln scripts

# Through a pivot (auto-adds proxychains + -sT -Pn):
bin/cpent ev-scan <t> --type service --proxychains
```

Output is auto-saved under `engagement/targets/<ip>/` with sha256 hashing.
Credential patterns and dual-NICs in the output are flagged automatically.

## Per-service enumeration

- **SMB (445):** `smbmap -H <t>`, `enum4linux-ng <t>`, `crackmapexec smb <t> --shares`.
  Null/guest sessions, readable shares, sensitive files.
- **Web (80/443):** see `web-exploitation` skill; always `gobuster dir` + tech fingerprint.
- **SNMP (161/udp):** `snmpwalk -v2c -c public <t>` — leaks users, processes, interfaces.
- **FTP/21, NFS/2049, RDP/3389, LDAP/389, DNS/53:** banner-grab, check anon/guest, zone
  transfer `dig axfr @<t> <domain>`.

## Host-triage block — run on EVERY shell, immediately

The automated triage runs all checks and captures evidence in one shot:

```
# Via SSH (with password or key):
bin/cpent ev-triage --ip <t> --os linux --remote ssh --user <u> --secret '<p>'

# Via WinRM (evil-winrm):
bin/cpent ev-triage --ip <t> --os windows --remote winrm --user <u> --secret '<p>'

# Via pass-the-hash:
bin/cpent ev-triage --ip <t> --os windows --remote pth --user <u> --secret '<ntlm>'

# If you already have a local shell on the box:
bin/cpent ev-triage --ip <t> --os linux
```

This runs identity, interfaces, routes, users, privilege checks, and cron/services —
saves each as a separate evidence file and **auto-detects dual-NICs** (flags pivots).

If a host has two interfaces → it's a pivot. Load the `pivoting` skill now, don't wait.

## Credentials & quick wins

- Always try defaults: `admin/admin`, `admin/password`, product defaults, and **reuse from
  the tracker** (`bin/cpent cred list`) before brute-forcing.
- Find the right wordlist: `bin/cpent wordlist password` → `/usr/share/wordlists/rockyou.txt`
  (or `bin/cpent wordlist brute-small` → `/usr/share/wordlists/fasttrack.txt` for quick runs).
- Brute-force: `hydra -L users.txt -P $(bin/cpent wordlist brute-small) <t> <service>`
- Password spray: `crackmapexec smb <t> -u users.txt -p 'Password1'` — background and work on.
- Before your first scan: `bin/cpent kali-check` to verify all tools and wordlists are present.

## Hand-off

Record found creds (`bin/cpent cred add`), write a finding for any foothold
(`bin/cpent finding new`), and recommend the exploitation path + next skill.
