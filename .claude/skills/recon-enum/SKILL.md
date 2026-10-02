---
name: recon-enum
description: Reconnaissance and enumeration playbook for CPENT Range 1 (Network & System). Use at the start of every target and whenever landing a new shell — host discovery, port/service scanning, per-service enumeration, and the host-triage block that finds pivots.
---

# Recon & Enumeration (Zone 1 — Network & System, 20%)

Broadest surface, easiest quick wins, and every shell here is a stepping stone deeper.
**Always `bin/cpent scope check <ip>` before touching a target.**

## Discovery → scanning (work in order)

```
nmap -sn 10.10.10.0/24                              # host discovery across a range
nmap -p- --min-rate 2000 -T4 <t>                    # full TCP port sweep
nmap -sC -sV -p <open-ports> <t>                    # service + default scripts on what's open
nmap --script "smb-vuln-*" -p445 <t>                # targeted vuln scripts
```

Save every scan under `engagement/targets/<ip>/`. Over a pivot/SOCKS proxy use
`proxychains nmap -sT -Pn` (SYN scan and host discovery don't traverse SOCKS).

## Per-service enumeration

- **SMB (445):** `smbmap -H <t>`, `enum4linux-ng <t>`, `crackmapexec smb <t> --shares`.
  Null/guest sessions, readable shares, sensitive files.
- **Web (80/443):** see `web-exploitation` skill; always `gobuster dir` + tech fingerprint.
- **SNMP (161/udp):** `snmpwalk -v2c -c public <t>` — leaks users, processes, interfaces.
- **FTP/21, NFS/2049, RDP/3389, LDAP/389, DNS/53:** banner-grab, check anon/guest, zone
  transfer `dig axfr @<t> <domain>`.

## Host-triage block — run on EVERY shell, immediately

Finding a second NIC is finding a whole new range. Log interfaces to the network map.

```
# Linux
id; sudo -l; ip a; ip route; arp -a; cat /etc/passwd; uname -a
# Windows
whoami /all; ipconfig /all; route print; arp -a; net user; net group /domain
```

If a host has two interfaces → it's a pivot. Load the `pivoting` skill now, don't wait.

## Credentials & quick wins

- Always try defaults: `admin/admin`, `admin/password`, product defaults, and **reuse from
  the tracker** (`bin/cpent cred list`) before brute-forcing.
- Brute-force only when it's the right move: `hydra -L users.txt -P pass.txt <t> <service>`,
  `crackmapexec smb <t> -u users.txt -p 'Password1'` (spray). Background it and work on.

## Hand-off

Record found creds (`bin/cpent cred add`), write a finding for any foothold
(`bin/cpent finding new`), and recommend the exploitation path + next skill.
