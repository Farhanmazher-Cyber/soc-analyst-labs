# Incident Investigation Report — EventID 322
## EDR Tampering Attempt via EDR-Freeze (SOC344)
**Analyst:** Farhan Mazher
**Platform:** LetsDefend
**Role:** Incident Responder
**Date of Analysis:** 2025-09-26

---

## 1. Alert Summary

| Field | Value |
|---|---|
| Event ID | 322 |
| Event Time | 2025-09-26T17:26:44+03:00 |
| Detection Rule | SOC344 - EDR Tampering Attempt via EDR-Freeze |
| Alert Type | Malware |
| Hostname | WS-Prod-02 |
| IP Address | 172.16.20.69 |
| SHA256 Hash | 970c7834e58b6ef22473875167a333dbb33bf7b667d1cb814829f68579cd85f7 |
| Process Name | EDR-Freeze_1.0.exe |
| Process Path | C:\Users\LetsDefend\Downloads\ |
| Command Line | `"C:\Users\LetsDefend\Downloads\EDR-Freeze_1.0.exe" 6080 10000` |
| Parent Process | powershell.exe |
| Device Action | **Allowed** |
| MITRE ATT&CK Techniques | T1078, T1059.001, T1055, T1562, T1562.001, T1489 |

**Alert Trigger Reason:** Execution of a known EDR tampering tool (EDR-Freeze) immediately following suspicious PowerShell activity, itself preceded by RDP brute-force login activity.

---

## 2. Findings

I hadn't come across EDR-Freeze before, so I researched it using Google and AI-assisted research (Claude) to understand what the tool actually does before making a call on the alert.

- EDR-Freeze is a publicly documented red-team/attacker tool that abuses the Windows Error Reporting mechanism (`WerFaultSecure.exe`) to forcibly **suspend** a target process rather than kill it outright.
- Attackers use it specifically to suspend EDR/antivirus agent processes, effectively blinding endpoint defenses during an attack while keeping the process technically "running" — which helps it evade detections built around process termination or service stops.
- In this case, the tool wasn't run in isolation. It was launched by `powershell.exe`, and the L1 note indicates it followed RDP brute-force activity and a successful logon, plus PowerShell-based reconnaissance. That sequence — brute force → access → recon → defense evasion — is a classic post-compromise attack chain.
- The SHA256 hash of the executed binary returned a malicious verdict on VirusTotal, which independently confirmed this wasn't a legitimate or unknown binary.

---

## 3. Determination

**Verdict: True Positive**

The combination of a known-malicious hash, a defense-evasion tool (EDR-Freeze) being launched from PowerShell, and it following on from brute-force RDP access all point to genuine attacker activity rather than a benign or accidental trigger. The fact that the device action was logged as "Allowed" is also consistent with how this tool is designed to work — it isn't meant to be blocked outright, it's meant to suspend the very tool that would block it.

Based on this, I classified the alert as a **True Positive**.

---

## 4. Next Steps

As the analyst investigating this alert, my role was to research the tool and technique, confirm the hash and behavior against threat intelligence, and make a clear, justified call for escalation. From here:

- The host (WS-Prod-02) should be isolated to contain further activity.
- The account used for the successful RDP logon should have its credentials reset and be reviewed for reuse.
- The hash should be blocked across the environment.
- A Tier 2 / IR analyst should take over deeper endpoint forensics — confirming whether the EDR agent was actually suspended, whether any follow-on actions occurred while defenses were blinded, and whether this is isolated to one host or part of a broader campaign.

---

## 5. Key Takeaway

This alert reinforced the same lesson as before: I don't need to already know every attacker tool by name. What matters is recognizing the pattern — a defense-evasion action landing right after initial access and recon — and knowing how to quickly research an unfamiliar tool, tie it to a known technique, and make a confident, evidence-backed call on whether it's a real threat.
