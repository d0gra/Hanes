---
description: Record or look up a credential in the tracker
argument-hint: add --ip .. --user .. --pass/--hash .. --source .. | list | find <ip>
---

Manage the credential tracker — password/hash reuse across hosts is where exam points hide.

- To record: parse `$ARGUMENTS` and run `bin/cpent cred add ...`. Capture ip, user,
  pass or hash, and source (where you found it). Confirm it was written.
- To look up before an attack: `bin/cpent cred list` or `bin/cpent cred find <ip>`.
- Whenever you land a new credential anywhere, record it without being asked, then suggest
  spraying it against other in-scope hosts (propose the command; the operator runs it).

$ARGUMENTS
