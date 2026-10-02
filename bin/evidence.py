#!/usr/bin/env python3
"""Auto-evidence capture: runs a command, saves timestamped output, hashes it,
auto-detects credentials and network interfaces in the output, and optionally
takes a screenshot. Designed for exam-day automation."""
import argparse
import datetime
import hashlib
import os
import re
import subprocess
import sys

ENG = os.environ.get("HANES_ENGAGEMENT", "engagement")
EVIDENCE = os.path.join(ENG, "evidence")
CREDS_CSV = os.path.join(ENG, "credentials.csv")


def _ts():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _ts_human():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_dirs(ip=None):
    os.makedirs(EVIDENCE, exist_ok=True)
    if ip:
        os.makedirs(os.path.join(ENG, "targets", ip), exist_ok=True)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_creds(text):
    """Scan output for likely credentials. Returns list of dicts."""
    found = []
    patterns = [
        # user:password or user:hash patterns
        (r"(?i)(?:user(?:name)?|login)\s*[:=]\s*(\S+)", "user"),
        (r"(?i)(?:pass(?:word)?|pwd)\s*[:=]\s*(\S+)", "pass"),
        # NTLM hashes (32 hex chars)
        (r"\b([a-fA-F0-9]{32})\b", "hash_candidate"),
        # user:LM:NTLM from secretsdump/hashdump
        (r"^(\S+?):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::", "hashdump"),
        # Kerberos ticket hashes ($krb5tgs$ or $krb5asrep$)
        (r"(\$krb5(?:tgs|asrep)\$\S+)", "kerb_hash"),
    ]
    for line in text.splitlines():
        for pat, kind in patterns:
            for m in re.finditer(pat, line):
                found.append({"kind": kind, "match": m.group(0), "line": line.strip()})
    return found


def _detect_interfaces(text):
    """Scan for network interfaces / dual-NIC indicators."""
    found = []
    # Linux: inet X.X.X.X from ip a
    for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", text):
        found.append(m.group(1))
    # Windows: IPv4 Address from ipconfig
    for m in re.finditer(r"IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", text):
        found.append(m.group(1))
    return found


def _detect_proof(text):
    """Check if output contains proof-of-access markers."""
    markers = {}
    # whoami
    for m in re.finditer(r"(?:^|\n)\s*((?:\S+\\)?\S+)\s*$", text):
        if any(k in text.lower() for k in ["whoami", "uid=", "root", "system", "admin"]):
            markers["identity"] = m.group(1).strip()
            break
    # hostname
    for m in re.finditer(r"(?i)(?:hostname|computer\s*name)[:\s]+(\S+)", text):
        markers["hostname"] = m.group(1)
    return markers


def take_screenshot(target_ip, label="", output_dir=None):
    """Take a screenshot with timestamp and target IP overlay."""
    ts = _ts()
    out_dir = output_dir or EVIDENCE
    os.makedirs(out_dir, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-") if label else "screen"
    filename = f"{ts}_{target_ip}_{slug}.png"
    filepath = os.path.join(out_dir, filename)

    # Try multiple screenshot tools (exam VM may have any of these)
    tools = [
        # scrot (common on Kali)
        ["scrot", filepath],
        # import from ImageMagick
        ["import", "-window", "root", filepath],
        # gnome-screenshot
        ["gnome-screenshot", "-f", filepath],
        # xfce4-screenshooter
        ["xfce4-screenshooter", "-f", "-s", filepath],
        # maim
        ["maim", filepath],
    ]

    for cmd in tools:
        try:
            subprocess.run(cmd, capture_output=True, timeout=10)
            if os.path.exists(filepath):
                sha = _sha256(filepath)
                # Annotate with IP + timestamp if convert (ImageMagick) is available
                try:
                    annotation = f"{target_ip} | {_ts_human()}"
                    subprocess.run([
                        "convert", filepath,
                        "-gravity", "SouthEast",
                        "-pointsize", "18",
                        "-fill", "yellow",
                        "-undercolor", "black",
                        "-annotate", "+10+10", annotation,
                        filepath,
                    ], capture_output=True, timeout=10)
                except Exception:
                    pass  # annotation is nice-to-have
                print(f"SCREENSHOT: {filepath}")
                print(f"  sha256: {sha}")
                return filepath, sha
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    print("WARNING: no screenshot tool found (tried scrot, import, gnome-screenshot, "
          "xfce4-screenshooter, maim). Take manually.", file=sys.stderr)
    return None, None


def capture_command(cmd_str, target_ip, zone="", label="", screenshot=False):
    """Run a command, capture output as evidence, auto-detect creds/interfaces."""
    _ensure_dirs(target_ip)
    ts = _ts()
    slug = re.sub(r"[^a-z0-9]+", "-", (label or cmd_str.split()[0]).lower()).strip("-")[:40]
    evidence_file = os.path.join(ENG, "targets", target_ip, f"{ts}_{slug}.txt")

    # Header
    header = (f"{'='*72}\n"
              f"TARGET: {target_ip}\n"
              f"TIME:   {_ts_human()}\n"
              f"ZONE:   {zone}\n"
              f"CMD:    {cmd_str}\n"
              f"{'='*72}\n\n")

    # Run the command
    print(f"[evidence] running: {cmd_str}")
    try:
        proc = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True, timeout=300
        )
        output = proc.stdout
        if proc.stderr:
            output += f"\n--- STDERR ---\n{proc.stderr}"
        retcode = proc.returncode
    except subprocess.TimeoutExpired:
        output = "(command timed out after 300s)"
        retcode = -1

    # Write evidence file
    with open(evidence_file, "w") as f:
        f.write(header)
        f.write(output)
        f.write(f"\n\n{'='*72}\n")
        f.write(f"EXIT CODE: {retcode}\n")

    sha = _sha256(evidence_file)
    print(f"[evidence] saved: {evidence_file}")
    print(f"[evidence] sha256: {sha}")

    # Print the actual output so the operator sees it
    print(f"\n{output}")

    # Auto-detect credentials
    creds = _detect_creds(output)
    if creds:
        print(f"\n[auto-detect] potential credentials found ({len(creds)}):")
        for c in creds:
            print(f"  {c['kind']}: {c['match']}")
        print("  -> Review and add confirmed creds with: bin/cpent cred add ...")

    # Auto-detect network interfaces (dual-NIC hunt)
    ifaces = _detect_interfaces(output)
    if len(ifaces) > 1:
        print(f"\n[auto-detect] DUAL-NIC / MULTIPLE INTERFACES on {target_ip}:")
        for iface in ifaces:
            print(f"  {iface}")
        print("  -> This host is a PIVOT candidate! Update network map and load pivoting skill.")
    elif ifaces:
        print(f"\n[auto-detect] interface: {ifaces[0]}")

    # Auto-detect proof of access
    proof = _detect_proof(output)
    if proof:
        print(f"\n[auto-detect] proof of access: {proof}")

    # Screenshot if requested
    if screenshot:
        take_screenshot(target_ip, label or slug)

    return evidence_file, sha, output


def main():
    p = argparse.ArgumentParser(
        prog="evidence",
        description="Auto-evidence capture: run, save, hash, detect creds/interfaces"
    )
    sub = p.add_subparsers(dest="action", required=True)

    # capture: run a command and save evidence
    cap = sub.add_parser("capture", help="Run a command and save timestamped evidence")
    cap.add_argument("cmd", help="Command to run (quote it)")
    cap.add_argument("--ip", required=True, help="Target IP")
    cap.add_argument("--zone", default="", help="Exam zone")
    cap.add_argument("--label", default="", help="Short label for the evidence file")
    cap.add_argument("--screenshot", action="store_true", help="Also take a screenshot")

    # screenshot: just take a screenshot
    scr = sub.add_parser("screenshot", help="Take an annotated screenshot")
    scr.add_argument("--ip", required=True, help="Target IP to annotate")
    scr.add_argument("--label", default="", help="Label")

    # scan: run an nmap scan with auto-evidence
    scan = sub.add_parser("scan", help="Nmap scan with auto-evidence capture")
    scan.add_argument("target", help="Target IP or CIDR")
    scan.add_argument("--type", choices=["discovery", "full", "service", "vuln"],
                       default="service", help="Scan type")
    scan.add_argument("--ports", default="", help="Specific ports")

    # proof: capture proof-of-access block (whoami + hostname + ip/ifconfig)
    prf = sub.add_parser("proof", help="Run the proof-of-access block and save evidence")
    prf.add_argument("--ip", required=True, help="Target IP")
    prf.add_argument("--os", choices=["linux", "windows"], default="linux")
    prf.add_argument("--via", default="local", help="How you're connected (ssh/winrm/meterpreter/local)")

    args = p.parse_args()

    if args.action == "capture":
        capture_command(args.cmd, args.ip, args.zone, args.label, args.screenshot)

    elif args.action == "screenshot":
        take_screenshot(args.ip, args.label)

    elif args.action == "scan":
        scan_cmds = {
            "discovery": f"nmap -sn {args.target}",
            "full": f"nmap -p- --min-rate 2000 -T4 {args.target}",
            "service": f"nmap -sC -sV {'-p ' + args.ports if args.ports else '-p-'} {args.target}",
            "vuln": f"nmap --script vuln {'-p ' + args.ports if args.ports else ''} {args.target}",
        }
        cmd = scan_cmds[args.type]
        capture_command(cmd, args.target, "network-system", f"nmap-{args.type}", screenshot=False)

    elif args.action == "proof":
        if args.os == "linux":
            cmd = "echo '=== PROOF OF ACCESS ===' && whoami && hostname && id && ip a && ip route && cat /etc/hostname 2>/dev/null"
        else:
            cmd = 'echo === PROOF OF ACCESS === && whoami && hostname && ipconfig /all'
        capture_command(cmd, args.ip, "", "proof-of-access", screenshot=True)


if __name__ == "__main__":
    main()
