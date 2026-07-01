# Medusa Detection Target List — Verified ATT&CK Mapping

**Project:** CTI Bridge — Phase 1 deliverable (detection-engineering target list)
**Adversary:** Medusa ransomware (RaaS). Disambiguation: Medusa RaaS ≠ MedusaLocker ≠ Medusa Android trojan.
**Status:** Committed. Every technique ID below verified against a live MITRE ATT&CK page.
**Date verified:** 2026-06-30

---

## Sources of record

| Source | ID | Type | MITRE version | Notes |
|--------|----|----|----|-------|
| Medusa Group | G1051 | Group (operator) | v19 (created 2025-10-15) | Human/intrusion behaviors |
| Medusa Ransomware | S1244 | Software (binary) | v19 (created 2025-10-17) | Encryptor behaviors |
| CISA advisory AA25-071A | — | Advisory | authored on ATT&CK v16 | Original TTP source; IDs now superseded in places |

**Verification method (dual):**
- **Concept match** — plain-English behavior queried through the local ATT&CK RAG (dataset current to v19) to confirm the behavior maps to the intended technique semantically.
- **Direct check / ID of record** — each ID confirmed against the live MITRE matrix (G1051 / S1244), which is authoritative over the v16 advisory.

The two columns agreed on all six. Disagreements between the RAG and the live matrix would indicate dataset drift; none were found.

---

## The committed six

| # | Behavior | Signature artifact | Technique(s) — current v19 | Tactic(s) | Attribution |
|---|----------|--------------------|-----------------------------|-----------|-------------|
| 1 | Shadow copy deletion | `vssadmin.exe delete shadows /all /quiet` | **T1490** Inhibit System Recovery | Impact | G1051 + S1244 |
| 2 | Encoded PowerShell | `powershell -enc <base64>` | **T1059.001** PowerShell · **T1027.010** Command Obfuscation | Execution · Defense Evasion | G1051 |
| 3 | BYOVD — kill security tools | `smuol.sys` / ABYSSWORKER driver; IOCTL `0x222094` | **T1685** Disable or Modify Tools · **T1543.003** Windows Service · **T1553.002** Code Signing | Defense Impairment · Persistence · Defense Evasion | G1051 + S1244 |
| 4 | RDP enablement | `fDenyTSConnections=0`, `DisableRestrictedAdmin=0`, `netsh advfirewall` 3389 rule (`openrdp.bat`) | **T1112** Modify Registry · **T1686** Disable or Modify System Firewall | Defense Evasion · Defense Impairment | G1051 |
| 5 | Service Stop | `taskkill /F /IM <proc> /T`, `net stop <svc>` | **T1489** Service Stop | Impact | G1051 + S1244 |
| 6 | PowerShell history wipe | `Remove-Item (Get-PSReadlineOption).HistorySavePath` | **T1070.003** Clear Command History · **T1690** Prevent Command History Logging | Defense Evasion | G1051 |

### Per-item verification notes

**1 — T1490 Inhibit System Recovery.** G1051 and S1244 both attribute shadow-copy deletion via `vssadmin.exe` to T1490. ID stable across v16→v19. Highest-confidence build: a literal command string.

**2 — T1059.001 + T1027.010.** G1051 attributes PowerShell execution to T1059.001 and separately attributes Base64-obfuscated PowerShell to T1027.010 Command Obfuscation. Detection should tag both: the interpreter (T1059.001) and the `-enc`/Base64 obfuscation (T1027.010). Note the binary's *internal* XOR string obfuscation is a different technique on S1244 (T1027.013 Encrypted/Encoded File) — do not conflate the two.

**3 — T1685 (primary) + T1543.003 + T1553.002.** This is the flagship detection and the one whose ID changed most. In v16 the tool-disabling was T1562.001. In v19, T1562/T1562.001 were restructured into the new parent **T1685 Disable or Modify Tools** under the new **Defense Impairment (TA0112)** tactic. BYOVD decomposes as: driver download (T1105 Ingress Tool Transfer) → driver load as service (T1543.003) → signed/vulnerable driver trust abuse (T1553.002) → tool disable effect (T1685, incl. IOCTL `0x222094`). Build the driver-load + tool-disable path; T1105 download is network-side and out of scope for endpoint logs.

**4 — T1112 + T1686.** Correction from the provisional list: the RDP *enablement* is registry + firewall, not T1021.001. G1051 maps the registry keys (`fDenyTSConnections`, `DisableRestrictedAdmin`) to T1112 and the firewall-rule modification to T1686 (a new v19 Defense-Impairment technique). This detection absorbs the old standalone "Restricted Admin" item. `T1021.001` (RDP as lateral movement, `mstsc.exe /v:`) is an **adjacent** technique, detected separately via logon/network telemetry — see Adjacent below.

**5 — T1489 Service Stop.** Replaces the old standalone "Restricted Admin" slot. Higher-signal than a second registry key, attributed to both the binary (S1244) and operators (G1051): `taskkill /F /IM <proc> /T` and `net stop <svc>`. Concrete, command-line-detectable.

**6 — T1070.003 + T1690.** MITRE dual-maps the single command `Remove-Item (Get-PSReadlineOption).HistorySavePath` to **both** T1070.003 (Clear Command History) and T1690 (Prevent Command History Logging). Tag both. T1070.003 confirmed intact in v19 (siblings T1070.001/.002 were absorbed into T1685; T1070.003/.004 survived). T1690 is new in v19.

---

## Corrections from the provisional (v16) list

| Item | Provisional (v16) | Committed (v19) | Reason |
|------|-------------------|-----------------|--------|
| #3 | T1562.001 | T1685 (+T1543.003, T1553.002) | v19 restructured T1562.001 into T1685 under the new Defense Impairment tactic |
| #4 | T1021.001 | T1112 + T1686 | T1021.001 is RDP *use* (lateral movement); the *enablement* is registry (T1112) + firewall (T1686) |
| #5 | T1112 (Restricted Admin) | folded into #4; slot → T1489 Service Stop | Restricted Admin is another facet of T1112 registry-mod; freed slot spent on higher-signal Service Stop |
| #6 | T1070 | T1070.003 + T1690 | MITRE dual-maps the exact command to both |

---

## Attribution split (software vs operator)

A professional distinction to state in the report: some behaviors are the **encryptor binary** (S1244), others are the **human operators** (G1051).

- **Binary (S1244):** shadow deletion (#1), PowerShell exec (#2), tool-kill (#3 effect), Service Stop (#5).
- **Operator (G1051):** RDP enablement (#4), history wipe (#6), plus the driver download/staging behind #3.

The homelab detects endpoint behaviors regardless of which "hand" performed them, but naming the split shows the CTI-to-detection reasoning the target role wants.

---

## Adjacent / deferred (coverage-map context, not built)

Documented deliberately so the coverage map shows the full Medusa picture and the prioritization logic — not oversights.

- **T1021.001** RDP (lateral movement, `mstsc.exe /v:`) — adjacent to #4; separate logon/network detection.
- **T1003.001 / T1003.003** LSASS (Mimikatz) / NTDS credential dumping — high value; strong candidate if the set is later expanded.
- **T1105** Ingress Tool Transfer (certutil, BITS, driver download) — network-side, low endpoint fidelity in this lab.
- **T1548.002** UAC bypass via COM; **T1136.002** domain account creation; **T1570 / T1072** lateral tool transfer via PDQ/BigFix — deferred as second-wave reps.
- **Initial access** (T1190 ConnectWise CVE-2024-1709 / Fortinet CVE-2023-48788, phishing, IAB-purchased access) — perimeter, not endpoint-log detectable here.

---

## Build order (recommended)

1. #1 shadow deletion (T1490) — literal string, fastest win.
2. #5 Service Stop (T1489) — literal strings, high signal.
3. #6 history wipe (T1070.003/T1690) — literal command.
4. #2 encoded PowerShell (T1059.001/T1027.010).
5. #4 RDP enablement (T1112/T1686) — registry + firewall.
6. #3 BYOVD (T1685/T1543.003/T1553.002) — highest difficulty, highest payoff; build last.

Each rule authored as vendor-neutral **Sigma**, translated to **SPL** for Splunk; **YARA** for file-based IOCs (`smuol.sys`, `gaze.exe`, ransom note `!READ_ME_MEDUSA!!!.txt`). Artifact = detection repo (Sigma + SPL + YARA + this coverage map + test evidence).
