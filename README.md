# Hanes — a Claude Code harness for CPENT

Hanes turns Claude Code into a disciplined penetration-testing *operator's companion*
for **CPENT** (EC-Council Certified Penetration Testing Professional) preparation and the
licensed exam range.

It is **not** an auto-pwn bot. The exam certifies *your* skill, the range is proctored,
and the whole thing runs on a clock. What actually loses people points is not missing a
flag — it's losing track of a credential, stalling 3 hours on one binary, forgetting a
dual-NIC pivot, or finishing exhausted with no evidence to write the report from. Hanes
attacks *those* problems:

- **Methodology on tap** — one skill per exam zone, each a checklist + command reference
  so you ask Claude "what's the next move here" instead of context-switching to notes.
- **ROI prioritization** — `/next` picks your highest points-per-hour target.
- **Relentless bookkeeping** — a credential tracker, per-target notes, and a live network
  map, because password reuse and pivots are where the points hide.
- **Report-as-you-go** — every finding is logged in a structured form the instant you land
  it, and `/report` assembles the EC-Council-style report from those logs. You cannot
  re-exploit after the clock stops; you *can* always regenerate the report.

## Scope & authorization — read this first

This toolkit is for **authorized engagements only**: the CPENT licensed cyber range, your
own lab (GOAD, HTB, THM, pwn.college), or a client engagement with a signed scope. The
range is explicitly in-scope and proctored — that is your authorization. Everything here
assumes a human operator driving, reviewing, and taking responsibility for each action.

`CLAUDE.md` makes this a hard rule for the agent: **no action against a host that isn't in
the engagement's recorded scope.** Set your scope before you start (`bin/cpent scope`).

## Quick start

```bash
# 1. Record the authorized scope (ranges/IPs the proctor assigned you)
bin/cpent scope add 10.10.10.0/24 "Range 1 - Network & System"

# 2. Open Claude Code in this repo. It reads CLAUDE.md and the skills automatically.
#    Ask it to work a target, e.g. "enumerate 10.10.10.5 and tell me the next move"

# 3. Every credential you find:
bin/cpent cred add --ip 10.10.10.5 --user admin --pass 'Summer2026!' --source 'wp-config.php'

# 4. Every foothold/flag:  log it immediately
#    (or ask Claude: "/finding")  -> writes engagement/findings/<id>.md

# 5. Between sessions and at the end:
bin/cpent report > engagement/report-draft.md
```

## Layout

| Path | What it is |
|---|---|
| `CLAUDE.md` | Operating rules for Claude Code: scope guardrails, methodology, ROI |
| `.claude/skills/` | One skill per zone — recon, web, AD, binary, IoT/wireless, privesc, pivoting, evasion, reporting |
| `.claude/commands/` | Slash commands: `/next`, `/recon`, `/cred`, `/finding`, `/pivot`, `/report` |
| `engagement/` | Your live workspace — targets, credentials, network map, findings |
| `templates/` | EC-Council-style report template |
| `bin/` | `cpent` dispatcher, `track.py` (tracker), `genreport.py` (report builder) |

## The five ranges (2,500 pts, 70% to pass)

Network & System (20%) · Active Directory (15%) · Binary Exploitation (15%) ·
Web App (10%) · IoT & Wireless (10%) · Defense Evasion (10%) · Privilege Escalation (10%)
· Pivoting (5%) · Report (5%).

Golden rule baked into `/next`: **partial scores across all ranges beat deep stalls on
one.** Pivoting is only 5% but it *gates* the ranges worth far more — treat it as critical.
