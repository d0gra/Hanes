---
name: recon-enum
description: Reconnaissance and enumeration playbook for CPENT Range 1 (Network & System). Use at the start of every target and whenever landing a new shell — host discovery, port/service scanning, per-service enumeration, and the host-triage block that finds pivots.
---

# Recon & Enumeration (Zone 1 — Network & System, 20%)

Broadest surface, easiest quick wins, and every shell here is a stepping stone deeper.
**Always `bin/cpent scope check <ip>` before touching a target.**

## Discovery → scanning (parallel strategy, never limit ports)

Use `bin/cpent ev-scan` to auto-save and auto-detect. **Always scan all 65535 ports** —
services on high ports (8080, 8443, 9090, 49152+) are common CPENT targets. Use sub-agents
to run the fast and deep scans in parallel:

### Phase 1: discover hosts + quick top-ports (parallel)
```
# Agent 1: host discovery across the subnet
bin/cpent ev-scan 10.10.10.0/24 --type discovery

# Agent 2 (per live host): quick service scan on common ports for fast wins
bin/cpent ev "nmap -sC -sV -T4 --top-ports 1000 <t>" --ip <t>
```

### Phase 2: full port sweep (background while you work phase 1 results)
```
# Agent 3: all 65535 TCP ports — catches high-port services others miss
bin/cpent ev-scan <t> --type full

# When full scan returns, service-scan any NEW ports not in top-1000:
bin/cpent ev-scan <t> --type service --ports <new-high-ports>
```

### Phase 3: targeted follow-up
```
# Vuln scripts on interesting ports:
bin/cpent ev-scan <t> --type vuln --ports <interesting-ports>

# UDP top-20 (slow but SNMP/TFTP/DNS are exam staples):
bin/cpent ev "nmap -sU --top-ports 20 -T4 <t>" --ip <t>

# Through a pivot (auto-adds proxychains + -sT -Pn):
bin/cpent ev-scan <t> --type service --proxychains
```

**Key rule:** never scan only a handful of ports. The quick scan gives you something to
work on immediately; the full scan runs in parallel and catches everything. Compare results
— any port in the full scan not in the quick scan gets a service scan.

Output is auto-saved under `engagement/targets/<ip>/` with sha256 hashing.
Credential patterns and dual-NICs in the output are flagged automatically.

## IPv6 — don't miss a whole address family

CPENT ranges plant IPv6-only services. If a host has a global/ULA v6 address, scan it:
```
nmap -6 -sC -sV -p- <ipv6-addr>
# discover link-local neighbours on a segment you have a shell on:
ping6 -c3 ff02::1%<iface>   ;   ip -6 neigh
```
The triage block captures `inet6` lines and the evidence engine now flags a second v6 NIC
as a pivot candidate — treat a dual-stack host like any dual-NIC host.

## Per-service enumeration

- **SMB (445):** `smbmap -H <t>`, `enum4linux-ng <t>`, `nxc smb <t> --shares -u '' -p ''`
  (null) then `-u guest -p ''`. Check readable/writable shares, spider for creds/configs.
- **Web (80/443):** see `web-exploitation` skill; always `gobuster dir` + tech fingerprint.
- **SNMP (161/udp):** `snmpwalk -v2c -c public <t>` — leaks users, processes, interfaces,
  routes. Try write community too: `snmpset` with `private` (reconfigure/leak).
  Brute communities: `onesixtyone -c /usr/share/seclists/Discovery/SNMP/common.snmp.txt <t>`.
- **NFS (2049):** `showmount -e <t>` → mount exports (`mount -t nfs <t>:/share /mnt`); check
  for `no_root_squash` (write a SUID binary as root). 
- **LDAP (389/636):** anonymous bind dump:
  `ldapsearch -x -H ldap://<t> -b "dc=<dom>,dc=<tld>"` — leaks users/descriptions (passwords
  in description fields are common).
- **FTP/21:** anonymous login (`ftp <t>` → anonymous), check writable dir for web-root upload.
- **RDP/3389:** `nxc rdp <t> -u .. -p ..`; **DNS/53:** zone transfer `dig axfr @<t> <domain>`.

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
- **The instant you get ANY credential, spray it across the whole scope** — reuse is rampant
  and this is the single highest-ROI move in the exam:
  ```
  bin/cpent spray --user admin --pass 'Summer2024!' --proto smb --bg   # all scoped hosts
  bin/cpent spray --user svc --hash <ntlm> --proto winrm --local-auth  # pass-the-hash
  ```
  It reads scope automatically, runs through evidence capture, and `--bg` backgrounds it.
- Find the right wordlist: `bin/cpent wordlist password` → `/usr/share/wordlists/rockyou.txt`
  (or `bin/cpent wordlist brute-small` → `/usr/share/wordlists/fasttrack.txt` for quick runs).
- Brute-force (background it): `bin/cpent ev "hydra -L users.txt -P $(bin/cpent wordlist brute-small) <t> <service>" --ip <t> --bg`
- Before your first scan: `bin/cpent kali-check` to verify all tools and wordlists are present.

## Hand-off

Record found creds (`bin/cpent cred add`), write a finding for any foothold
(`bin/cpent finding new`), and recommend the exploitation path + next skill.
