# EventID 322 – SOC344 EDR Tampering Attempt via EDR-Freeze

**Platform:** LetsDefend
**Role:** Incident Responder
**Severity:** High | **Difficulty:** Medium
**Verdict:** True Positive – Malicious

## Summary

RDP brute-force activity against host `WS-Prod-02` was followed by a successful logon, PowerShell-based reconnaissance, and execution of **EDR-Freeze**, a known EDR-tampering tool that abuses the Windows Error Reporting process to suspend endpoint defense agents without killing them outright. The binary's SHA256 hash was confirmed malicious on VirusTotal, and the alert was escalated for full investigation.

## Key Techniques (MITRE ATT&CK)

- T1078 – Valid Accounts
- T1059.001 – PowerShell
- T1055 – Process Injection
- T1562 / T1562.001 – Impair Defenses
- T1489 – Service Stop

## Files

- [`EventID-322-EDR-Freeze.md`](./EventID-322-EDR-Freeze.md) – Full investigation write-up: alert details, timeline, analysis, verdict, and response recommendations.

---

*Part of [letsdefend-labs](../../) — SOC analyst alert investigations.*
