# CPENT Penetration Test Report

> EC-Council-style structure. `bin/cpent report` fills the findings/credentials/map
> sections from your engagement log; you write the narrative and executive summary.

---

## 1. Executive Summary

*One page, non-technical, business-risk language. What was assessed, the overall risk
posture, and the most significant exposures in plain terms.*

## 2. Scope & Methodology

- **Scope (authorized targets):** _(from `engagement/scope.txt`)_
- **Dates / sessions:**
- **Approach:** reconnaissance → exploitation → post-exploitation → pivoting → reporting
- **Tools used:**

## 3. Attack Narrative  *(graded centrepiece)*

*Step-by-step walkthrough of how exploits were chained across segments. Include the network
diagram showing the pivot path (attacker → pivot1 → pivot2 → targets). This is where the
grader follows your thinking — make the chain explicit.*

<!-- NARRATIVE -->

_(network diagram — see `engagement/network-map.md`, reproduced below)_

## 4. Findings

*Auto-populated from `engagement/findings/`. Each: severity + CVSS, description, PoC with
screenshots, business impact, remediation.*

<!-- FINDINGS -->

## 5. Appendices

### A. Host / subnet map
<!-- NETWORKMAP -->

### B. Credential list
<!-- CREDENTIALS -->

### C. Per-target notes
<!-- TARGETNOTES -->

### D. Command log & tool output
_(full timestamped output + sha256 under `engagement/targets/<ip>/` and
`engagement/evidence/<session>/`)_
