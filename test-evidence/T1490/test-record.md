# Test Record — T1490 Volume Shadow Copy Deletion via Vssadmin

**Rule under test:** `proc_creation_win_medusa_vssadmin_shadow_deletion.yml`
**Rule ID:** 7b8ae0eb-e331-4143-a6de-5a4ef908a530
**Technique:** T1490 Inhibit System Recovery
**Adversary attribution:** Medusa — Group G1051 and Ransomware S1244 both map `vssadmin.exe` shadow-copy deletion to T1490.
**Tester:** Corbin Griffin
**Date:** 2026-06-30
**Result:** PASS (positive and negative validated)

## Environment

Windows VM with Sysmon installed, log forwarder shipping to Splunk, Atomic Red Team (`Invoke-AtomicRedTeam`) installed. Sysmon Event ID 1 (process creation with command line) is the source event. VM snapshotted before testing and rolled back after.

## Method

- **Positive stimulus:** Atomic Red Team T1490 Test #1 ("Windows - Delete Volume Shadow Copies"), which executes `vssadmin.exe delete shadows /all /quiet`.
- **Negative stimulus:** `vssadmin list shadows` — same binary, benign subcommand, no `delete` token. Used to prove the rule discriminates on behavior, not just on the vssadmin binary.
- Command inspected with `Invoke-AtomicTest T1490 -TestNumbers 1 -ShowDetails` before execution.

## Positive result — PASS

Command executed via Atomic Test #1. The VM held no shadow copies, so vssadmin returned "No items found that satisfy the query" — the deletion was a no-op. Sysmon still logged the process creation (Event ID 1) with the full command line `vssadmin.exe delete shadows /all /quiet`, and the detection query returned the event (1 row).

**Key finding:** the rule fires on the *execution attempt*, independent of whether shadow copies existed to delete. This is the correct and desirable behavior for a ransomware pre-encryption canary — the alert must land when the command runs, not after recovery data is already destroyed.

## Negative result — PASS (specificity proven)

`vssadmin list shadows` was executed in the same window. Comparison of the two queries over that window:

- Detection query (below): **1 row** — the delete event only.
- Broad query (`Image="*\\vssadmin.exe"`, no command filter): **2 rows** — the delete event and the list event.

Both events are present in Splunk; the rule matched only the malicious `delete shadows` and correctly excluded the benign `list shadows`. The one-event delta between the two queries is the empirical proof of specificity.

## Queries used

Detection (rule logic):
```
index=* source="*Sysmon*" EventCode=1
(Image="*\\vssadmin.exe" OR OriginalFileName="VSSADMIN.EXE")
CommandLine="*delete*" CommandLine="*shadows*"
| table _time host User ParentImage Image OriginalFileName CommandLine
```

Broad (specificity control):
```
index=* EventCode=1 Image="*\\vssadmin.exe"
| table _time host Image CommandLine
```

## Evidence

Screenshots stored alongside this record in `test-evidence/T1490/`:
- `01-powershell-execution.png` — Atomic Test #1 execution and vssadmin "No items found" output
- `02-sysmon-eventviewer.png` — Sysmon Event ID 1 showing the captured command line
- `03-splunk-detection-1row.png` — detection query returning the single delete event
- `04-splunk-broad-2rows.png` — broad query returning delete + list (specificity control)

## Conclusion and follow-ups

The rule detects Medusa's signature shadow-copy deletion command with a validated positive and a proven negative. Recommend bumping the rule `status` from `experimental` to `test` (lab-validated, not yet production-tested).

Open items, documented honestly rather than closed prematurely:
- **False-positive surface not yet characterized.** Legitimate backup/storage-management tools can call `vssadmin delete shadows`; none observed in this lab, but the rule has not run against production telemetry. FP tuning (parent-process or account filters) deferred until real-world baseline exists.
- **Scope boundary is deliberate.** This rule covers vssadmin only. Sibling T1490 tools (`wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit`, `diskshadow`) are out of scope and documented as a candidate companion rule in the coverage map.
