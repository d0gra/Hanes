#!/usr/bin/env python3
"""Kali Linux environment awareness: wordlists, tool paths, VPN/interface detection,
and remote session execution (SSH, WinRM, evil-winrm). The ground truth for paths
and tooling the rest of the harness references."""
import os
import re
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# Wordlists — actual Kali paths, checked at runtime
# ---------------------------------------------------------------------------
WORDLIST_PATHS = {
    # Password lists
    "rockyou":        "/usr/share/wordlists/rockyou.txt",
    "rockyou.gz":     "/usr/share/wordlists/rockyou.txt.gz",
    "fasttrack":      "/usr/share/wordlists/fasttrack.txt",
    "common":         "/usr/share/wordlists/dirb/common.txt",
    "big":            "/usr/share/wordlists/dirb/big.txt",
    "small":          "/usr/share/wordlists/dirb/small.txt",

    # Web fuzzing
    "dirbuster-med":  "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "dirbuster-sml":  "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",

    # Users
    "names":          "/usr/share/wordlists/dirb/others/names.txt",
    "xato-users":     "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",

    # SecLists (if installed via apt install seclists)
    "seclists-web":   "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "seclists-dns":   "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "seclists-pass":  "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "seclists-user":  "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",

    # Nmap scripts
    "nmap-scripts":   "/usr/share/nmap/scripts/",
}

# Preferred wordlist per task type
WORDLIST_FOR = {
    "password":     ["rockyou", "fasttrack", "seclists-pass"],
    "directory":    ["common", "dirbuster-med", "seclists-web"],
    "username":     ["seclists-user", "xato-users", "names"],
    "dns":          ["seclists-dns"],
    "brute-small":  ["fasttrack"],
    "brute-full":   ["rockyou"],
}

# ---------------------------------------------------------------------------
# Tool locations
# ---------------------------------------------------------------------------
TOOLS = {
    # Recon
    "nmap":             "nmap",
    "masscan":          "masscan",
    "enum4linux-ng":    "enum4linux-ng",
    "smbmap":           "smbmap",
    "smbclient":       "smbclient",
    "rpcclient":        "rpcclient",
    "crackmapexec":     "crackmapexec",
    "nxc":              "nxc",            # netexec (CME successor)
    "gobuster":         "gobuster",
    "feroxbuster":      "feroxbuster",
    "wpscan":           "wpscan",
    "nikto":            "nikto",
    "whatweb":          "whatweb",
    "snmpwalk":         "snmpwalk",

    # Exploitation / Metasploit
    "msfconsole":       "msfconsole",
    "msfvenom":         "msfvenom",
    "msfdb":            "msfdb",
    "msf-pattern_create": "msf-pattern_create",
    "msf-pattern_offset": "msf-pattern_offset",
    "msf-nasm_shell":   "msf-nasm_shell",
    "sqlmap":           "sqlmap",
    "searchsploit":     "searchsploit",

    # AD / Impacket
    "impacket-psexec":       "impacket-psexec",
    "impacket-wmiexec":      "impacket-wmiexec",
    "impacket-smbexec":      "impacket-smbexec",
    "impacket-secretsdump":  "impacket-secretsdump",
    "impacket-GetUserSPNs": "impacket-GetUserSPNs",
    "impacket-GetNPUsers":  "impacket-GetNPUsers",
    "impacket-GetADUsers":  "impacket-GetADUsers",
    "impacket-getTGT":      "impacket-getTGT",
    "evil-winrm":       "evil-winrm",
    "bloodhound-python":"bloodhound-python",
    "certipy":          "certipy",

    # Web testing
    "ffuf":             "ffuf",
    "nuclei":           "nuclei",
    "sslscan":          "sslscan",
    "testssl":          "testssl.sh",
    "curl":             "curl",
    "wfuzz":            "wfuzz",
    "droopescan":       "droopescan",
    "joomscan":         "joomscan",

    # Password cracking
    "hashcat":          "hashcat",
    "john":             "john",
    "hydra":            "hydra",

    # Pivoting
    "chisel":           "chisel",
    "ligolo-proxy":     "ligolo-proxy",
    "proxychains":      "proxychains4",
    "socat":            "socat",
    "ssh":              "ssh",
    "sshpass":          "sshpass",

    # Wireless
    "aircrack-ng":      "aircrack-ng",
    "airodump-ng":      "airodump-ng",
    "aireplay-ng":      "aireplay-ng",

    # IoT / OT / SCADA
    "binwalk":          "binwalk",
    "mbtget":           "mbtget",
    "plcscan":          "plcscan",
    "onesixtyone":      "onesixtyone",

    # Service enum helpers
    "ldapsearch":       "ldapsearch",
    "showmount":        "showmount",
    "snmpwalk":         "snmpwalk",
    "snmpset":          "snmpset",
    "dig":              "dig",

    # Binary
    "gdb":              "gdb",
    "ghidra":           "/opt/ghidra*/ghidraRun",
    "pwntools":         None,  # python library

    # Evidence
    "scrot":            "scrot",
    "import":           "import",  # ImageMagick

    # Remote access
    "xfreerdp":         "xfreerdp",
    "rdesktop":         "rdesktop",
}

# Impacket tools have two naming conventions across Kali versions
IMPACKET_ALIASES = {
    "GetUserSPNs.py":  ["impacket-GetUserSPNs", "GetUserSPNs.py"],
    "GetNPUsers.py":   ["impacket-GetNPUsers", "GetNPUsers.py"],
    "GetADUsers.py":   ["impacket-GetADUsers", "GetADUsers.py"],
    "secretsdump.py":  ["impacket-secretsdump", "secretsdump.py"],
    "psexec.py":       ["impacket-psexec", "psexec.py"],
    "wmiexec.py":      ["impacket-wmiexec", "wmiexec.py"],
    "smbexec.py":      ["impacket-smbexec", "smbexec.py"],
    "getTGT.py":       ["impacket-getTGT", "getTGT.py"],
    "ticketer.py":     ["impacket-ticketer", "ticketer.py"],
    "ntlmrelayx.py":   ["impacket-ntlmrelayx", "ntlmrelayx.py"],
}


def find_wordlist(task_type="password"):
    """Return the best available wordlist path for a task type."""
    candidates = WORDLIST_FOR.get(task_type, WORDLIST_FOR["password"])
    for name in candidates:
        path = WORDLIST_PATHS.get(name, "")
        if os.path.exists(path):
            return path
        # Check for .gz version (rockyou)
        if path.endswith(".txt") and os.path.exists(path + ".gz"):
            print(f"[kali] {path} is gzipped. Decompress first: sudo gunzip {path}.gz",
                  file=sys.stderr)
            return path + ".gz"
    # Fallback: search /usr/share/wordlists
    wl_dir = "/usr/share/wordlists"
    if os.path.isdir(wl_dir):
        for root, _, files in os.walk(wl_dir):
            for f in files:
                if f.endswith(".txt") and os.path.getsize(os.path.join(root, f)) > 1000:
                    return os.path.join(root, f)
    return None


def find_impacket(tool_name):
    """Find the correct impacket binary name (handles Kali naming differences)."""
    aliases = IMPACKET_ALIASES.get(tool_name, [tool_name])
    for alias in aliases:
        if shutil.which(alias):
            return alias
    # Try in common impacket install paths
    for p in ["/usr/share/doc/python3-impacket/examples/",
              "/usr/bin/", "/usr/local/bin/",
              os.path.expanduser("~/.local/bin/")]:
        for alias in aliases:
            full = os.path.join(p, alias)
            if os.path.exists(full):
                return full
    return tool_name  # return as-is, let it fail visibly


def find_tool(name):
    """Find a tool's actual path/command."""
    if name in IMPACKET_ALIASES:
        return find_impacket(name)
    cmd = TOOLS.get(name, name)
    if cmd and shutil.which(cmd):
        return cmd
    # nxc vs crackmapexec
    if name == "crackmapexec" and shutil.which("nxc"):
        return "nxc"
    if name == "nxc" and shutil.which("crackmapexec"):
        return "crackmapexec"
    return cmd


def check_environment():
    """Print a Kali environment status report."""
    print("=== Kali Environment Check ===\n")

    # Wordlists
    print("WORDLISTS:")
    rockyou = WORDLIST_PATHS["rockyou"]
    if os.path.exists(rockyou):
        size = os.path.getsize(rockyou) // (1024*1024)
        print(f"  rockyou.txt: {rockyou} ({size}MB)")
    elif os.path.exists(rockyou + ".gz"):
        print(f"  rockyou.txt.gz: needs decompression -> sudo gunzip {rockyou}.gz")
    else:
        print("  rockyou.txt: NOT FOUND")
    seclists = "/usr/share/seclists"
    if os.path.isdir(seclists):
        print(f"  SecLists: installed at {seclists}")
    else:
        print("  SecLists: not installed -> sudo apt install -y seclists")
    print()

    # Key tools
    print("TOOLS:")
    critical = ["nmap", "msfconsole", "msfvenom", "searchsploit", "crackmapexec",
                 "hydra", "sqlmap", "gobuster", "nikto", "ffuf", "nuclei",
                 "evil-winrm", "hashcat", "ssh", "proxychains"]
    for t in critical:
        loc = shutil.which(find_tool(t))
        status = f"  {t}: {loc}" if loc else f"  {t}: NOT FOUND"
        print(status)
    print()

    # Impacket
    print("IMPACKET:")
    for tool_name in ["secretsdump.py", "psexec.py", "GetUserSPNs.py", "GetNPUsers.py"]:
        found = find_impacket(tool_name)
        loc = shutil.which(found)
        print(f"  {tool_name}: {loc or 'NOT FOUND'} (as: {found})")
    print()

    # Network interfaces
    print("NETWORK:")
    _print_interfaces()
    print()

    # Proxychains config
    pc_conf = "/etc/proxychains4.conf"
    if not os.path.exists(pc_conf):
        pc_conf = "/etc/proxychains.conf"
    if os.path.exists(pc_conf):
        print(f"PROXYCHAINS: {pc_conf}")
        with open(pc_conf) as f:
            for line in f:
                if line.strip() and not line.startswith("#") and "socks" in line.lower():
                    print(f"  {line.strip()}")
    print()


def _print_interfaces():
    """List network interfaces and flag VPN/tunnel."""
    try:
        out = subprocess.check_output(["ip", "-o", "addr", "show"], text=True)
    except Exception:
        print("  (could not enumerate interfaces)")
        return

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[1]
        # Skip loopback
        if iface == "lo":
            continue
        ip_match = re.search(r"inet\s+(\S+)", line)
        ip = ip_match.group(1) if ip_match else "?"
        kind = ""
        if iface.startswith("tun") or iface.startswith("tap"):
            kind = " [VPN/TUNNEL]"
        elif iface.startswith("wlan"):
            kind = " [WIRELESS]"
        elif iface.startswith("eth") or iface.startswith("ens"):
            kind = " [ETHERNET]"
        elif iface.startswith("docker") or iface.startswith("br-"):
            kind = " [DOCKER]"
        print(f"  {iface}: {ip}{kind}")


def get_vpn_interface():
    """Return the VPN/tunnel interface name and IP, or None."""
    try:
        out = subprocess.check_output(["ip", "-o", "addr", "show"], text=True)
    except Exception:
        return None, None
    for line in out.splitlines():
        parts = line.split()
        iface = parts[1] if len(parts) > 1 else ""
        if iface.startswith("tun") or iface.startswith("tap"):
            ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
            return iface, ip_match.group(1) if ip_match else None
    return None, None


def get_proxychains_conf():
    """Return the path to proxychains config."""
    for p in ["/etc/proxychains4.conf", "/etc/proxychains.conf"]:
        if os.path.exists(p):
            return p
    return None


# ---------------------------------------------------------------------------
# Remote command execution
# ---------------------------------------------------------------------------

def run_ssh(target_ip, user, command, password=None, key=None, port=22, timeout=60):
    """Execute a command over SSH and return (stdout, stderr, returncode)."""
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", f"ConnectTimeout={min(timeout, 30)}",
           "-p", str(port)]
    if key:
        cmd += ["-i", key]
    cmd += [f"{user}@{target_ip}", command]

    if password and shutil.which("sshpass"):
        cmd = ["sshpass", "-p", password] + cmd
    elif password:
        print("[kali] WARNING: sshpass not found. Install: sudo apt install -y sshpass",
              file=sys.stderr)
        print(f"[kali] Manual: ssh {user}@{target_ip} -p {port}", file=sys.stderr)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"SSH command timed out after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1


def run_winrm(target_ip, user, password, command, domain="", use_hash=False):
    """Execute a command over evil-winrm and return output."""
    ewrm = find_tool("evil-winrm")
    if not shutil.which(ewrm):
        return "", "evil-winrm not found", -1

    cmd = [ewrm, "-i", target_ip, "-u", user]
    if use_hash:
        cmd += ["-H", password]
    else:
        cmd += ["-p", password]
    cmd += ["-c", command]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "WinRM command timed out", -1
    except Exception as e:
        return "", str(e), -1


def run_remote(target_ip, user, secret, command, method="ssh", **kwargs):
    """Dispatch to the right remote execution method."""
    if method == "ssh":
        return run_ssh(target_ip, user, command, password=secret, **kwargs)
    elif method == "winrm":
        return run_winrm(target_ip, user, secret, command, **kwargs)
    elif method == "pth":
        # pass-the-hash via impacket
        psexec = find_impacket("psexec.py")
        cmd_str = f'{psexec} -hashes ":{secret}" {user}@{target_ip} "{command}"'
        proc = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=120)
        return proc.stdout, proc.stderr, proc.returncode
    else:
        return "", f"unknown method: {method}", -1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    p = argparse.ArgumentParser(prog="kali", description="Kali environment awareness")
    sub = p.add_subparsers(dest="action", required=True)

    sub.add_parser("check", help="Full environment check")
    sub.add_parser("vpn", help="Show VPN interface")

    wl = sub.add_parser("wordlist", help="Find best wordlist for a task")
    wl.add_argument("task", choices=list(WORDLIST_FOR.keys()), nargs="?", default="password")

    tl = sub.add_parser("tool", help="Find a tool's actual path")
    tl.add_argument("name")

    imp = sub.add_parser("impacket", help="Find impacket tool")
    imp.add_argument("name")

    args = p.parse_args()

    if args.action == "check":
        check_environment()
    elif args.action == "vpn":
        iface, ip = get_vpn_interface()
        if iface:
            print(f"VPN: {iface} -> {ip}")
        else:
            print("No VPN/tunnel interface found. Start your VPN first.")
    elif args.action == "wordlist":
        wl_path = find_wordlist(args.task)
        if wl_path:
            print(wl_path)
        else:
            print(f"No wordlist found for '{args.task}'. Install: sudo apt install -y wordlists seclists",
                  file=sys.stderr)
    elif args.action == "tool":
        print(find_tool(args.name))
    elif args.action == "impacket":
        print(find_impacket(args.name))


if __name__ == "__main__":
    main()
