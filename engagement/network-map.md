# Network map

Keep this current — a stale map costs you a whole segment. Mark every dual-NIC host.

```
attacker (you)
   |
   └── [ pivot1  ext:10.10.10.x  int:172.16.20.x ]   <-- dual-NIC, SOCKS :1080
          |
          └── [ pivot2  ext:172.16.20.x  int:192.168.1.x ]   <-- dual-NIC, SOCKS :1081
                 |
                 └── targets: 192.168.1.0/24  (AD? OT?)
```

## Segments

| Segment | Reached via | Notes |
|---|---|---|
| 10.10.10.0/24 | direct | Range 1 — Network & System |
| | | |

## Hosts

| IP | Hostname | Interfaces | Role | Access level |
|---|---|---|---|---|
| | | | | |
