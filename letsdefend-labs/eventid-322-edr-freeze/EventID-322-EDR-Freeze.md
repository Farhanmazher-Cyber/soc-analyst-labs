# SOC344 - EDR Tampering Attempt via EDR-Freeze

**Platform:** LetsDefend
**Role:** Incident Responder
**Event ID:** 322
**Alert Type:** Malware
**Severity:** High
**Difficulty:** Medium
**Event Time:** 2025-09-26T17:26:44+03:00

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name |
|---|---|
| T1078 | Valid Accounts |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1055 | Process Injection |
| T1562 | Impair Defenses |
| T1562.001 | Impair Defenses: Disable or Modify Tools |
| T1489 | Service Stop |

---

## Alert Details

| Field | Value |
|---|---|
| Hostname | WS-Prod-02 |
| IP Address | 172.16.20.69 |
| SHA256 Hash | 970c7834e58b6ef22473875167a333dbb33bf7b667d1cb814829f68579cd85f7 |
| Process Name | EDR-Freeze_1.0.exe |
| Process Path | C:\Users\LetsDefend\Downloads\ |
| Command Line | `"C:\Users\LetsDefend\Downloads\EDR-Freeze_1.0.exe" 6080 10000` |
| Parent Process | powershell.exe |
| Device Action | Allowed |

**Trigger Reason:** Execution of known EDR tampering tool (EDR-Freeze) after suspicious PowerShell activity.

---

## L1 Analyst Note

During initial triage, RDP brute-force activity was observed prior to a successful logon on the host. Shortly after authentication, the attacker executed reconnaissance commands via PowerShell. The associated binary hash returned a malicious verdict on VirusTotal. The alert was escalated for further investigation.

---

## Investigation Timeline

1. **Initial Access** – Repeated RDP authentication attempts against WS-Prod-02 preceded a successful logon, consistent with a brute-force attack (T1078 – Valid Accounts).
2. **Discovery/Reconnaissance** – Following logon, PowerShell (`powershell.exe`) was used to run reconnaissance-style commands (T1059.001).
3. **Defense Evasion** – `powershell.exe` spawned `EDR-Freeze_1.0.exe` from `C:\Users\LetsDefend\Downloads\`, executed with arguments `6080 10000`. EDR-Freeze is a known technique that abuses legitimate Windows mechanisms (WER/process suspension) to temporarily suspend or "freeze" EDR/AV processes, effectively blinding endpoint defenses without formally terminating them (T1562 / T1562.001 – Impair Defenses; T1489 – Service Stop; T1055 – Process Injection, as the tool leverages process manipulation to suspend the target process).
4. **Detection Gap** – The device action logged for this process was "Allowed," indicating the tampering attempt was not blocked at execution time, which is the intended effect of an EDR-Freeze style attack — the goal is to run undetected while the endpoint agent is suspended.
5. **Hash Verification** – The SHA256 hash of the executed binary was checked against VirusTotal and returned a malicious verdict, confirming this was not a false positive.

---

## Analysis & Reasoning

EDR-Freeze is a publicly known red-team/attacker tool that abuses the Windows Error Reporting (WER) process (`WerFaultSecure.exe`) to suspend a target process — in this case, the EDR/AV agent — without killing it outright. This is significant because:

- Suspending (rather than killing) an EDR process can evade detections that specifically watch for process termination or service stops.
- The attacker chain here (RDP brute force → successful logon → PowerShell recon → EDR-Freeze execution) follows a classic post-compromise defense-evasion playbook: gain access, look around, then blind the defenses before proceeding to further objectives (e.g., lateral movement, data exfiltration, or ransomware deployment).
- The fact that this was "Allowed" by the endpoint control underscores why detection engineering (behavioral/EDR-tampering detections) matters more than relying solely on signature-based blocking.

## Verdict

**True Positive – Malicious**

## Recommended Response Actions

- Isolate WS-Prod-02 from the network immediately to contain further activity.
- Kill the `EDR-Freeze_1.0.exe` process and verify the EDR/AV agent has resumed normal function.
- Reset credentials for the account used in the successful RDP logon; review for reuse elsewhere.
- Block the SHA256 hash across the environment (EDR/AV, proxy, mail gateway as applicable).
- Review RDP exposure — restrict via VPN/jump host, enforce MFA, and enable account lockout policies to mitigate brute-force attempts.
- Hunt across the environment for the same hash, the EDR-Freeze command-line pattern, and any other hosts with a similar PowerShell → suspicious-binary execution chain.
- Escalate to IR team for full forensic timeline and to confirm scope (was this isolated to WS-Prod-02, or part of a broader campaign?).

## Lessons Learned

EDR-tampering tools like EDR-Freeze highlight the importance of monitoring for *process suspension* events, not just process termination — many detection rules focus on kills/uninstalls and miss suspension-based evasion. Behavioral detections around WER-related process manipulation and unusual PowerShell → downloaded-binary execution chains would have provided earlier warning.

---

*Write-up by Farhan Mazher | LetsDefend SOC Alert Investigation*
