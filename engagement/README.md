# Engagement workspace

Your live exam/engagement state. Everything here is what the report is built from.

- `scope.txt` — authorized CIDRs/IPs, one per line as `cidr<TAB>label` (manage with
  `bin/cpent scope`). The agent will not touch anything not listed here.
- `credentials.csv` — the credential tracker (`bin/cpent cred ...`). Check it before every
  brute-force; password reuse is everywhere.
- `network-map.md` — live attacker → pivot → target diagram. Update on every dual-NIC host.
- `targets/<ip>/` — per-target raw scan output and notes.
- `findings/<id>.md` — one structured finding per foothold/flag/vuln (`bin/cpent finding ...`).

Generated files (`report-draft.md`, anything under `targets/`) are git-ignored by default
so you don't commit live range data — see `.gitignore`.
