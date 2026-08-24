# Incident Investigation Report — EventID 313
## CVE-2024-49138 Privilege Escalation Exploitation (SOC335)
**Analyst:** Farhan Mazher
**Platform:** LetsDefend
**Role:** Security Analyst (Tier 1 / SOC Analyst)
**Date of Analysis:** 2025-01-22

---

## 1. Alert Summary

| Field | Value |
|---|---|
| Event ID | 313 |
| Event Time | 2025-01-22T02:37:00+03:00 |
| Detection Rule | SOC335 - CVE-2024-49138 Exploitation Detected |
| Alert Type | Privilege Escalation |
| Hostname | Victor |
| IP Address | 172.16.17.207 |
| Process ID | 7640 |
| File Hash | b432dcf4a0f0b601b1d79848467137a5e25cab5a0b7b1224be9d3b6540122db9 |
| Process Name | svohost.exe |
| Process Path | C:\temp\service_installer\svohost.exe |
| Command Line | `\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1` |
| Process User | EC2AMAZ-ILGVOIN\LetsDefend |
| Parent Process | powershell.exe |
| Device Action | **Allowed** |
| MITRE ATT&CK Techniques | T1059.001, T1055, T1068, T1548, T1110 |

**Alert Trigger Reason:** Unusual or suspicious patterns of behavior linked to the file hash were identified, indicating potential exploitation of CVE-2024-49138.

---

## 2. Findings

I hadn't come across CVE-2024-49138 before, so I researched it using Google and AI-assisted research (Claude) to understand what it does before making a call.

- CVE-2024-49138 is a real, actively-exploited vulnerability in the Windows Common Log File System (CLFS) driver — a low-level Windows component used for logging.
- It allows an attacker who already has some level of local access on a machine to escalate their privileges all the way up to SYSTEM, the highest level of access on Windows.
- It's listed on CISA's Known Exploited Vulnerabilities catalog, confirming it's a genuine, confirmed threat rather than a theoretical one.
- Exploiting this CVE requires local access first, which lines up with the T1110 (Brute Force) technique listed in this alert — suggesting the attacker likely brute-forced their way onto the machine before attempting to escalate privileges.

Separately from the CVE research, the process name itself stood out: `svohost.exe` closely mimics the legitimate Windows process `svchost.exe`, but with two letters swapped. It was also running from `C:\temp\service_installer\` rather than the real system directory, and was launched by PowerShell — all signs of an attacker trying to blend in while executing their exploit.

---

## 3. Determination

**Verdict: True Positive**

Based on my research, the pattern in this alert matches known exploitation behavior for CVE-2024-49138: a locally-running process attempting privilege escalation, executed via PowerShell, with a file deliberately named to resemble a trusted system process. The request was also marked "Allowed," meaning it wasn't blocked at execution.

Based on this, I classified the alert as a **True Positive**.

---

## 4. Next Steps

As the analyst on this alert, my role was to research the CVE, confirm the suspicious indicators (file naming, file path, execution chain), and make a clear, justified call for escalation. Deeper investigation — confirming whether the privilege escalation actually succeeded and what was done with elevated access — would need to be handed off to a Tier 2 / incident response analyst with full endpoint-level visibility.

---

## 5. Key Takeaway

This alert reinforced that small details matter just as much as big ones — a single swapped letter in a process name, or a file running from the wrong folder, can be the clearest sign something's wrong. As with the earlier CVE I researched, I don't need to know every vulnerability by name going in; I need to know how to quickly research one, understand what it actually does, and use that understanding to make a confident, evidence-backed decision.
