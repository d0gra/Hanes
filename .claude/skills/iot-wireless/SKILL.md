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

## OT / SCADA — ModBus

ModBus/TCP (502) is unauthenticated and unencrypted by design.

```
tcpdump -i <iface> -w modbus.pcap port 502      # capture
# analyze in Wireshark:  filter  modbus  or  mbtcp
mbtget -r3 -a 1 -n 10 <plc-ip>                  # read holding registers
# read/write coils and registers directly once you know the map
```

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
