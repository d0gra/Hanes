#!/usr/bin/env python3
"""Auto-evidence capture: runs commands locally or on remote targets (SSH/WinRM),
saves timestamped output, hashes it, auto-detects credentials and network interfaces
in the output, and optionally takes a screenshot. Designed for exam-day automation
on a Kali VM with VPN lab access."""
import argparse
import datetime
import hashlib
import os
import re
import subprocess
import sys

# Import Kali helpers (same directory)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from kali import run_remote, find_tool, get_vpn_interface
except ImportError:
    run_remote = None
    find_tool = lambda x: x
    get_vpn_interface = lambda: (None, None)

ENG = os.environ.get("HANES_ENGAGEMENT", "engagement")
EVIDENCE = os.path.join(ENG, "evidence")
CREDS_CSV = os.path.join(ENG, "credentials.csv")
SESSION_FILE = os.path.join(ENG, ".session_start")


def _ts():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _ts_human():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _session_folder():
    """Return the current session's evidence folder (named by session start time).
    Falls back to a timestamped folder if no session is active."""
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE) as f:
            start = f.read().strip()
        folder_name = start.replace(":", "-").replace("T", "_")[:19]
    else:
        folder_name = _ts()
    return os.path.join(EVIDENCE, folder_name)


def _ensure_dirs(ip=None):
    session_dir = _session_folder()
    os.makedirs(session_dir, exist_ok=True)
    if ip:
        os.makedirs(os.path.join(ENG, "targets", ip), exist_ok=True)
    return session_dir


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
    session_dir = _session_folder()
    out_dir = output_dir or session_dir
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


def capture_command(cmd_str, target_ip, zone="", label="", screenshot=False,
                    remote_method=None, remote_user=None, remote_secret=None,
                    timeout=300):
    """Run a command (locally or on a remote target), capture output as evidence,
    auto-detect creds/interfaces. For remote: method is ssh/winrm/pth."""
    session_dir = _ensure_dirs(target_ip)
    ts = _ts()
    slug = re.sub(r"[^a-z0-9]+", "-", (label or cmd_str.split()[0]).lower()).strip("-")[:40]
    evidence_file = os.path.join(ENG, "targets", target_ip, f"{ts}_{slug}.txt")
    session_copy = os.path.join(session_dir, f"{ts}_{target_ip}_{slug}.txt")

    exec_mode = f"remote ({remote_method})" if remote_method else "local"

    # Header
    header = (f"{'='*72}\n"
              f"TARGET: {target_ip}\n"
              f"TIME:   {_ts_human()}\n"
              f"ZONE:   {zone}\n"
              f"EXEC:   {exec_mode}\n"
              f"CMD:    {cmd_str}\n"
              f"{'='*72}\n\n")

    # Run the command
    print(f"[evidence] running ({exec_mode}): {cmd_str}")

    if remote_method and run_remote:
        # Execute on the remote target
        stdout, stderr, retcode = run_remote(
            target_ip, remote_user, remote_secret, cmd_str, method=remote_method
        )
        output = stdout
        if stderr:
            output += f"\n--- STDERR ---\n{stderr}"
    elif remote_method and not run_remote:
        output = "(remote execution unavailable: kali.py not found)"
        retcode = -1
    else:
        # Local execution
        try:
            proc = subprocess.run(
                cmd_str, shell=True, capture_output=True, text=True, timeout=timeout
            )
            output = proc.stdout
            if proc.stderr:
                output += f"\n--- STDERR ---\n{proc.stderr}"
            retcode = proc.returncode
        except subprocess.TimeoutExpired:
            output = f"(command timed out after {timeout}s)"
            retcode = -1

    # Write evidence file (per-target)
    content = header + output + f"\n\n{'='*72}\nEXIT CODE: {retcode}\n"
    with open(evidence_file, "w") as f:
        f.write(content)

    # Also write to session-level evidence folder for chronological view
    with open(session_copy, "w") as f:
        f.write(content)

    sha = _sha256(evidence_file)
    print(f"[evidence] saved: {evidence_file}")
    print(f"[evidence] session: {session_copy}")
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

    # Shared remote-execution args (added to multiple subparsers)
    def add_remote_args(parser):
        parser.add_argument("--remote", choices=["ssh", "winrm", "pth"],
                            help="Execute on the remote target via this method")
        parser.add_argument("--user", help="Remote username")
        parser.add_argument("--secret", help="Password or NTLM hash for remote auth")

    # capture: run a command and save evidence
    cap = sub.add_parser("capture", help="Run a command and save timestamped evidence")
    cap.add_argument("cmd", help="Command to run (quote it)")
    cap.add_argument("--ip", required=True, help="Target IP")
    cap.add_argument("--zone", default="", help="Exam zone")
    cap.add_argument("--label", default="", help="Short label for the evidence file")
    cap.add_argument("--screenshot", action="store_true", help="Also take a screenshot")
    cap.add_argument("--timeout", type=int, default=300, help="Command timeout in seconds")
    add_remote_args(cap)

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
    scan.add_argument("--proxychains", action="store_true",
                       help="Run through proxychains (for pivoted targets)")

    # proof: capture proof-of-access block on a remote target
    prf = sub.add_parser("proof", help="Run the proof-of-access block and save evidence")
    prf.add_argument("--ip", required=True, help="Target IP")
    prf.add_argument("--os", choices=["linux", "windows"], default="linux")
    add_remote_args(prf)

    # triage: full host-triage block (proof + routes + users + privesc check)
    tri = sub.add_parser("triage", help="Full host-triage on a remote target")
    tri.add_argument("--ip", required=True, help="Target IP")
    tri.add_argument("--os", choices=["linux", "windows"], default="linux")
    add_remote_args(tri)

    args = p.parse_args()

    if args.action == "capture":
        capture_command(
            args.cmd, args.ip, args.zone, args.label, args.screenshot,
            remote_method=args.remote, remote_user=args.user,
            remote_secret=args.secret, timeout=args.timeout
        )

    elif args.action == "screenshot":
        take_screenshot(args.ip, args.label)

    elif args.action == "scan":
        prefix = "proxychains -q " if args.proxychains else ""
        scan_flag = "-sT -Pn" if args.proxychains else ""
        scan_cmds = {
            "discovery": f"{prefix}nmap -sn {args.target}",
            "full": f"{prefix}nmap {scan_flag} -p- --min-rate 2000 -T4 {args.target}",
            "service": f"{prefix}nmap {scan_flag} -sC -sV {'-p ' + args.ports if args.ports else '-p-'} {args.target}",
            "vuln": f"{prefix}nmap {scan_flag} --script vuln {'-p ' + args.ports if args.ports else ''} {args.target}",
        }
        cmd = scan_cmds[args.type]
        capture_command(cmd, args.target, "network-system", f"nmap-{args.type}", screenshot=False)

    elif args.action == "proof":
        if args.os == "linux":
            cmd = "echo '=== PROOF OF ACCESS ===' && whoami && hostname && id && ip a && ip route"
        else:
            cmd = 'echo === PROOF OF ACCESS === && whoami && hostname && ipconfig /all'
        capture_command(
            cmd, args.ip, "", "proof-of-access", screenshot=True,
            remote_method=args.remote, remote_user=args.user,
            remote_secret=args.secret
        )

    elif args.action == "triage":
        # Full host-triage: identity, privs, interfaces, routes, users, local secrets
        if args.os == "linux":
            cmds = [
                ("identity",    "id && whoami && hostname"),
                ("interfaces",  "ip a && ip route && arp -a"),
                ("users",       "cat /etc/passwd"),
                ("privesc",     "sudo -l 2>&1; find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null"),
                ("cron",        "cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null"),
                ("kernel",      "uname -a && cat /etc/os-release 2>/dev/null"),
            ]
        else:
            cmds = [
                ("identity",    "whoami /all"),
                ("interfaces",  "ipconfig /all && route print && arp -a"),
                ("users",       "net user && net localgroup administrators"),
                ("domain",      "net user /domain 2>nul && net group /domain 2>nul"),
                ("services",    'wmic service get name,pathname,startmode 2>nul | findstr /i "auto"'),
                ("privesc",     "whoami /priv"),
            ]
        print(f"[triage] Full host-triage on {args.ip} ({args.os}) via {args.remote or 'local'}")
        for label, cmd in cmds:
            print(f"\n{'='*60}\n[triage:{label}]\n{'='*60}")
            capture_command(
                cmd, args.ip, "", f"triage-{label}", screenshot=False,
                remote_method=args.remote, remote_user=args.user,
                remote_secret=args.secret
            )


if __name__ == "__main__":
    main()
