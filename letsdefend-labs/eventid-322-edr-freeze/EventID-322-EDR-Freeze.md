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

During initial triage, I noticed there were multiple failed login attempts to the host over RDP (RDP is just how someone remotely connects to and controls a Windows computer, like a remote desktop) right before a successful login happened. This pattern usually means someone was guessing the password repeatedly until they got in, known as a brute-force attack.

Right after logging in, the attacker ran some commands using PowerShell (a built-in Windows tool that lets you run commands and scripts) to look around the system — this is normally done to gather information about the machine before doing anything else.

Then I looked into the file that was executed, called EDR-Freeze. I hadn't heard of this before, so I researched it. EDR-Freeze is a known attacker tool used to temporarily "freeze" or pause security software (like antivirus/EDR tools) on a computer, without actually shutting it down or uninstalling it. The idea is that while the security software is frozen, it can't detect or block whatever the attacker does next — but because it's not fully turned off, it can look less suspicious than if the attacker had disabled it outright.

I also checked the hash (a unique fingerprint) of the file that was run, and VirusTotal (a site that scans files against many antivirus engines) confirmed it was malicious. This wasn't a false alarm.

---

## Investigation Timeline

1. **Initial Access** – There were repeated failed RDP login attempts on the host, followed by a successful login. This looks like a brute-force attack, where someone kept guessing the password until it worked.
2. **Looking Around (Recon)** – Once logged in, the attacker used PowerShell to run commands, likely to gather information about the system.
3. **Disabling Security Tools** – PowerShell was then used to launch the EDR-Freeze tool from the Downloads folder. This tool is designed to pause the security software running on the machine so it can't catch what happens next.
4. **Not Blocked** – The system logs showed this action was "Allowed," meaning the security tool didn't stop it. This makes sense, since the whole point of EDR-Freeze is to sneak past defenses without triggering an obvious block.
5. **Confirming It's Malicious** – I checked the file's hash on VirusTotal, and it came back malicious, confirming this wasn't a mistake or a harmless file.

---

## My Reasoning

Putting it together, this looked like a real attack, not a false alarm, because:

- Someone got in through repeated login guessing (brute force), which is already suspicious on its own.
- Right after getting in, they didn't waste time — they looked around the system and then tried to disable the security tool, which is a common next step for attackers before doing something bigger (like spreading to other computers or stealing/encrypting data).
- The file used to disable security software was confirmed malicious by VirusTotal, so there was solid evidence backing this up, not just a hunch.

## Verdict

**True Positive – Malicious**

## What I'd Recommend Doing Next

- Disconnect the affected computer from the network right away so the attacker can't do anything further on it.
- Stop the malicious process and make sure the security software is working normally again.
- Change the password for the account that was used to log in, since it was clearly compromised.
- Block this file (using its hash) across the company so it can't run on any other computer.
- Look into why RDP was accessible enough to be brute-forced — this should probably be locked down further, or require extra verification (like MFA) to log in.
- Check other computers for the same file or similar suspicious activity, in case this wasn't limited to just one machine.
- Hand this off to the incident response team so they can dig deeper and confirm whether anything else happened on the network.

## What I Learned

I didn't know what EDR-Freeze was before this alert, and that's okay — the important part was recognizing the pattern: someone got in, looked around, and then tried to turn off the security tool. That sequence itself is a big red flag, even before knowing the exact tool being used. This alert taught me that I don't need to know every attacker tool by name; I just need to know how to research something unfamiliar quickly and make a confident, well-supported decision.

---

*Write-up by Farhan Mazher | LetsDefend SOC Alert Investigation*

---

*Write-up by Farhan Mazher | LetsDefend SOC Alert Investigation*
