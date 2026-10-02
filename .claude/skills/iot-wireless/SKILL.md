---
name: iot-wireless
description: IoT, OT/SCADA and wireless playbook for CPENT Zone 5 — firmware extraction/analysis, embedded device attacks, ModBus, and WPA2/evil-twin. Use for the IoT/OT range and wireless challenges.
---

# IoT, OT/SCADA & Wireless (Zone 5, 10%)

The zone that sets CPENT apart. Often procedural — follow the steps and the points come.
The OT range may need a proctor reset; document issues with screenshots + timestamps.

## Firmware analysis

```
binwalk -e firmware.bin                                  # extract filesystem
file ./extracted/.../bin/<binary>                        # arch: ARM / MIPS / x86
strings firmware.bin | grep -i 'http\|admin\|root\|pass'
grep -rniE 'password|passwd|secret|key|token' ./extracted/
qemu-arm -L ./extracted/squashfs-root/ ./extracted/squashfs-root/usr/bin/<binary>
```

Common IoT wins: hardcoded/default creds on telnet/SSH/HTTP admin, unauth API endpoints,
command injection in web UIs, exposed debug (UART/JTAG), plaintext protocols leaking creds.

## OT / SCADA — identify the protocol first

ICS protocols are unauthenticated/unencrypted by design — enumeration usually *is* the
exploit. Fingerprint the device and speak its protocol:

```
# Discover ICS services and devices on the segment:
nmap -Pn -sV --script "modbus-discover,s7-info,bacnet-info,enip-info" -p 502,102,47808,44818 <range>
plcscan <plc-ip>                                # ports 502 (ModBus) + 102 (S7)
```

| Protocol | Port | Device | Tooling |
|---|---|---|---|
| **ModBus/TCP** | 502 | generic PLC | `mbtget`, `modbus-cli`, pymodbus, Nmap `modbus-discover` |
| **S7comm** | 102 | Siemens S7 | `plcscan`, Nmap `s7-info`, snap7 (python-snap7) |
| **EtherNet/IP + CIP** | 44818 | Allen-Bradley | Nmap `enip-info`, cpppo |
| **BACnet** | 47808/udp | building automation | Nmap `bacnet-info`, BACnet-stack tools |
| **DNP3** | 20000 | power/water RTUs | Nmap `dnp3-info`, dnp3 scripts |

### ModBus (502) — read/write registers and coils
```
tcpdump -i <iface> -w modbus.pcap port 502      # capture; analyze in Wireshark (filter: mbtcp)
mbtget -r3 -a 1 -n 10 <plc-ip>                  # read 10 holding registers from addr 1
mbtget -w5 -a 100 1 <plc-ip>                    # write coil 100 = ON   (DESTRUCTIVE — confirm first)
# pymodbus REPL for scripted read/write once you know the register map
```

### S7comm (102) — Siemens
```
python3 -c "import snap7; c=snap7.client.Client(); c.connect('<plc-ip>',0,1); print(c.get_cpu_info())"
# read/write data blocks (DB) once identified; nmap s7-info leaks module/firmware/serial
```

**Register/coil writes change physical process state.** Treat every write as destructive:
describe exactly what it toggles and confirm with the operator before sending (CLAUDE.md §6).

## Wireless — WPA2 / evil twin

```
airmon-ng start wlan0
airodump-ng wlan0mon                                     # find BSSID/channel
airodump-ng -c <ch> --bssid <bssid> -w cap wlan0mon
aireplay-ng -0 5 -a <bssid> wlan0mon                     # deauth to force handshake
aircrack-ng cap.cap -w wordlist                          # crack captured handshake
wash -i wlan0mon                                         # check for WPS
# rogue AP: hostapd-mana / wifiphisher
```

Record extracted creds and the capture file's `sha256sum`; write a finding per device.
