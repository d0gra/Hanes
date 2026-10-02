#!/usr/bin/env python3
"""Hanes engagement tracker: scope, credentials, findings, targets, and the ROI 'next'
prioritizer. No external deps. State lives under $HANES_ENGAGEMENT (default: engagement/)."""
import argparse
import csv
import datetime
import ipaddress
import os
import re
import sys

ENG = os.environ.get("HANES_ENGAGEMENT", "engagement")
SCOPE = os.path.join(ENG, "scope.txt")
CREDS = os.path.join(ENG, "credentials.csv")
FINDINGS = os.path.join(ENG, "findings")

ZONES = [
    "network-system", "active-directory", "binary", "web",
    "iot-wireless", "defense-evasion", "privesc", "pivoting", "reporting",
]
# Approx CPENT point weighting per zone, for the ROI prioritizer.
ZONE_POINTS = {
    "network-system": 500, "active-directory": 375, "binary": 375, "web": 250,
    "iot-wireless": 250, "defense-evasion": 250, "privesc": 250, "pivoting": 125,
    "reporting": 125,
}


def _ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure():
    os.makedirs(ENG, exist_ok=True)
    os.makedirs(FINDINGS, exist_ok=True)


# ---------- scope ----------
def _scope_entries():
    if not os.path.exists(SCOPE):
        return []
    out = []
    with open(SCOPE) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t", 1)
            out.append((parts[0].strip(), parts[1].strip() if len(parts) > 1 else ""))
    return out


def _normalize_cidr(cidr):
    """Bare IP → /32, validate, return normalized string or None."""
    if "/" not in cidr:
        try:
            ipaddress.ip_address(cidr)
            cidr = cidr + "/32"
        except ValueError:
            pass
    try:
        ipaddress.ip_network(cidr, strict=False)
        return cidr
    except ValueError as e:
        print(f"skipping invalid: {cidr} ({e})", file=sys.stderr)
        return None


def scope(args):
    _ensure()
    cidrs = args.cidrs or []
    label = args.label or ""

    if args.action == "add":
        if not cidrs:
            sys.exit("usage: scope add <cidr> [cidr2 cidr3 ...] [-l label]")
        for raw in cidrs:
            cidr = _normalize_cidr(raw)
            if not cidr:
                continue
            with open(SCOPE, "a") as f:
                f.write(f"{cidr}\t{label}\n")
            print(f"scope += {cidr}  {label}")
    elif args.action == "set":
        if not cidrs:
            sys.exit("usage: scope set <cidr> [cidr2 cidr3 ...]")
        with open(SCOPE, "w") as f:
            for raw in cidrs:
                cidr = _normalize_cidr(raw)
                if not cidr:
                    continue
                f.write(f"{cidr}\t{label}\n")
                print(f"scope = {cidr}")
        print(f"scope replaced ({len(cidrs)} range(s))")
    elif args.action == "clear":
        if os.path.exists(SCOPE):
            os.remove(SCOPE)
        print("scope cleared")
    elif args.action == "list":
        entries = _scope_entries()
        if not entries:
            print("(scope empty — add authorized targets with: cpent scope add <cidr>)")
        for c, l in entries:
            print(f"{c:<20} {l}")
    elif args.action == "check":
        if not cidrs:
            sys.exit("usage: scope check <ip>")
        ip = cidrs[0]
        if _in_scope(ip):
            print(f"IN SCOPE: {ip}")
        else:
            print(f"NOT IN SCOPE: {ip}  -- do not touch until the operator adds it")
            sys.exit(2)


def _in_scope(ip):
    try:
        addr = ipaddress.ip_address(ip.split("/")[0])
    except ValueError:
        # maybe they passed a network; accept exact-string match against scope
        return any(ip == c for c, _ in _scope_entries())
    for c, _ in _scope_entries():
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


# ---------- credentials ----------
CRED_COLS = ["ts", "ip", "user", "password", "hash", "source", "notes"]


def _read_creds():
    if not os.path.exists(CREDS):
        return []
    with open(CREDS, newline="") as f:
        return list(csv.DictReader(f))


def cred(args):
    _ensure()
    if args.action == "add":
        new = not os.path.exists(CREDS)
        with open(CREDS, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=CRED_COLS)
            if new:
                w.writeheader()
            w.writerow({
                "ts": _ts(), "ip": args.ip or "", "user": args.user or "",
                "password": getattr(args, "pass") or "", "hash": args.hash or "",
                "source": args.source or "", "notes": args.notes or "",
            })
        print(f"cred recorded: {args.user or '?'}@{args.ip or '?'} (source: {args.source or '?'})")
        print("tip: try this credential against other in-scope hosts (reuse is rampant).")
    elif args.action == "list":
        rows = _read_creds()
        if not rows:
            print("(no credentials yet)")
            return
        for r in rows:
            secret = r["password"] or (r["hash"][:24] + "…" if r["hash"] else "")
            print(f"{r['ip']:<16} {r['user']:<18} {secret:<28} {r['source']}")
    elif args.action == "find":
        for r in _read_creds():
            if r["ip"] == args.ip or args.ip in (r["user"], r["source"]):
                print(r)


# ---------- findings ----------
def _finding_files():
    if not os.path.isdir(FINDINGS):
        return []
    return sorted(f for f in os.listdir(FINDINGS)
                  if f.endswith(".md") and not f.startswith("_"))


def finding(args):
    _ensure()
    if args.action == "new":
        existing = _finding_files()
        n = len(existing) + 1
        slug = re.sub(r"[^a-z0-9]+", "-", (args.title or "finding").lower()).strip("-")
        fid = f"{n:03d}-{slug}"[:60]
        path = os.path.join(FINDINGS, fid + ".md")
        with open(path, "w") as f:
            f.write(f"""# {args.title or 'Untitled finding'}

- id: {fid}
- ts: {_ts()}
- target: {args.ip or ''}
- zone: {args.zone or ''}
- severity: {args.sev or ''}
- cvss: {args.cvss or ''}

## Description


## Proof of concept (command + output)
```
{args.cmd or ''}
```

## Proof of access
```
# whoami ; hostname ; ip a   (paste here)
```

## Business impact


## Remediation


## Evidence
- screenshots:
- loot + sha256:
""")
        print(f"finding written: {path}")
        print("Now: fill description/impact/remediation, and SCREENSHOT before+after (IP+timestamp visible).")
    elif args.action == "list":
        files = _finding_files()
        if not files:
            print("(no findings yet)")
            return
        for fn in files:
            meta = _parse_finding(os.path.join(FINDINGS, fn))
            print(f"[{meta.get('severity','?'):<8}] {meta.get('zone','?'):<16} "
                  f"{meta.get('target','?'):<16} {meta.get('_title','')}")


def _parse_finding(path):
    meta = {}
    with open(path) as f:
        for line in f:
            if line.startswith("# ") and "_title" not in meta:
                meta["_title"] = line[2:].strip()
            m = re.match(r"- (\w+): (.*)", line)
            if m:
                meta[m.group(1)] = m.group(2).strip()
    return meta


# ---------- target note ----------
def target(args):
    _ensure()
    d = os.path.join(ENG, "targets", args.ip)
    os.makedirs(d, exist_ok=True)
    note = os.path.join(d, "notes.md")
    if not os.path.exists(note):
        tmpl = os.path.join(ENG, "targets", "_template.md")
        body = open(tmpl).read().replace("<IP>", args.ip) if os.path.exists(tmpl) else f"# Target: {args.ip}\n"
        open(note, "w").write(body)
    print(note)


# ---------- next (ROI prioritizer) ----------
def nxt(args):
    _ensure()
    findings = [_parse_finding(os.path.join(FINDINGS, f)) for f in _finding_files()]
    scored_zones = {z: 0 for z in ZONES}
    for m in findings:
        z = m.get("zone", "")
        if z in scored_zones:
            scored_zones[z] += 1
    creds = _read_creds()
    print("=== ROI snapshot ===")
    print(f"scope: {len(_scope_entries())} range(s) | findings: {len(findings)} | creds: {len(creds)}")
    print()
    print("zone coverage (breadth beats depth — get SOME score in every zone first):")
    for z in ZONES:
        bar = "#" * scored_zones[z]
        flag = "  <-- UNTOUCHED" if scored_zones[z] == 0 and z != "reporting" else ""
        print(f"  {z:<16} {ZONE_POINTS[z]:>4}pts  {bar}{flag}")
    print()
    untouched = [z for z in ZONES if scored_zones[z] == 0 and z != "reporting"]
    # Recommend: highest-value untouched zone, but pivoting first if any pivot is implied.
    print("=== recommendation ===")
    if not _scope_entries():
        print("-> Set your authorized scope first: cpent scope add <cidr> <label>")
    elif untouched:
        pick = max(untouched, key=lambda z: ZONE_POINTS[z])
        print(f"-> No score yet in {len(untouched)} zone(s). Highest-value untouched: "
              f"{pick} ({ZONE_POINTS[pick]} pts). Grab a quick win there.")
        print("   Easy wins across zones: default creds, SMB shares, AS-REP/Kerberoast, obvious web vulns.")
        if "pivoting" in untouched:
            print("   NOTE: any dual-NIC host you've popped -> pivot NOW; it gates AD/OT ranges.")
    else:
        print("-> Every zone has a score. Now deepen the highest-value zones and chase DA/root.")
    print("   Reminder: 45-min stall = document partial credit and move on.")


def reset(args):
    """Wipe all engagement state for a fresh start."""
    import shutil
    targets = [
        SCOPE,
        CREDS,
        os.path.join(ENG, ".session_start"),
        os.path.join(ENG, "summary.md"),
        os.path.join(ENG, "report-draft.md"),
    ]
    # Directories to wipe entirely (evidence has timestamped session subdirs)
    evidence_dir = os.path.join(ENG, "evidence")
    td = os.path.join(ENG, "targets")

    removed = 0
    for f in targets:
        if os.path.exists(f):
            os.remove(f)
            removed += 1
    # Wipe findings
    if os.path.isdir(FINDINGS):
        for fn in os.listdir(FINDINGS):
            fp = os.path.join(FINDINGS, fn)
            if os.path.isfile(fp):
                os.remove(fp)
                removed += 1
    # Wipe evidence session folders
    if os.path.isdir(evidence_dir):
        for entry in os.listdir(evidence_dir):
            fp = os.path.join(evidence_dir, entry)
            if os.path.isdir(fp):
                shutil.rmtree(fp)
                removed += 1
            elif os.path.isfile(fp):
                os.remove(fp)
                removed += 1
    # Wipe target subdirs (keep template)
    if os.path.isdir(td):
        for entry in os.listdir(td):
            fp = os.path.join(td, entry)
            if entry.startswith("_"):
                continue
            if os.path.isdir(fp):
                shutil.rmtree(fp)
                removed += 1
            elif os.path.isfile(fp):
                os.remove(fp)
                removed += 1

    _ensure()
    print(f"engagement reset — removed {removed} item(s)")
    print("ready for a fresh run. next: bin/cpent scope add <cidr> [label]")


def main():
    p = argparse.ArgumentParser(prog="track.py")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scope")
    s.add_argument("action", choices=["add", "set", "list", "check", "clear"])
    s.add_argument("cidrs", nargs="*", help="One or more CIDRs/IPs")
    s.add_argument("--label", "-l", default="", help="Label for the scope entry")

    c = sub.add_parser("cred"); c.add_argument("action", choices=["add", "list", "find"])
    c.add_argument("--ip"); c.add_argument("--user"); c.add_argument("--pass", dest="pass")
    c.add_argument("--hash"); c.add_argument("--source"); c.add_argument("--notes")
    c.add_argument("ip_pos", nargs="?")

    fi = sub.add_parser("finding"); fi.add_argument("action", choices=["new", "list"])
    fi.add_argument("--ip"); fi.add_argument("--zone", choices=ZONES); fi.add_argument("--sev")
    fi.add_argument("--cvss"); fi.add_argument("--title"); fi.add_argument("--cmd")

    t = sub.add_parser("target"); t.add_argument("action", choices=["note"]); t.add_argument("ip")

    sub.add_parser("next")
    sub.add_parser("reset")

    args = p.parse_args()
    if args.command == "scope":
        scope(args)
    elif args.command == "cred":
        if args.action == "find" and not args.ip:
            args.ip = args.ip_pos
        cred(args)
    elif args.command == "finding":
        finding(args)
    elif args.command == "target":
        target(args)
    elif args.command == "next":
        nxt(args)
    elif args.command == "reset":
        reset(args)


if __name__ == "__main__":
    main()
