# EventID 313 – SOC335 CVE-2024-49138 Exploitation Detected

**Platform:** LetsDefend
**Role:** Security Analyst
**Severity:** Medium | **Difficulty:** Medium
**Verdict:** True Positive – Malicious

## Summary

A suspicious process named `svohost.exe` — a near-identical mimic of the legitimate Windows process `svchost.exe` — was launched via PowerShell from a non-standard folder on host `Victor`. The file's hash and behavior matched exploitation patterns for **CVE-2024-49138**, an actively-exploited Windows CLFS driver vulnerability that allows local privilege escalation to SYSTEM level. The MITRE mapping also flags a preceding brute-force technique, suggesting the attacker gained initial access before attempting to escalate privileges.

## Key Techniques (MITRE ATT&CK)

- T1110 – Brute Force
- T1059.001 – PowerShell
- T1068 – Exploitation for Privilege Escalation
- T1548 – Abuse Elevation Control Mechanism
- T1055 – Process Injection

## Files

- [`EventID-313-CVE-2024-49138.md`](./EventID-313-CVE-2024-49138.md) – Full investigation write-up: alert details, timeline, analysis, verdict, and response recommendations.
- [`Incident-Investigation-Report-EventID-313.md`](./Incident-Investigation-Report-EventID-313.md) – Formal incident report summarizing the alert, findings, and determination.

---

*Part of [letsdefend-labs](../../) — SOC analyst alert investigations.*
