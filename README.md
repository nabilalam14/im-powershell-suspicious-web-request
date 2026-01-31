# 🚨 PowerShell Suspicious Web Request Incident Response  
## Microsoft Sentinel & Defender for Endpoint  
### Aligned to NIST 800-61 Incident Response Lifecycle

---

## 📌 Incident Overview
This lab simulates a **post-exploitation scenario originating from an internal user endpoint**, where **PowerShell** was abused to download and execute scripts from the internet using `Invoke-WebRequest`.

From an incident response perspective, this case highlights how **benign user behavior (installing free software)** can lead to high-risk security events.  
The incident was handled end-to-end following the **NIST 800-61 Incident Response Lifecycle**, mirroring real-world SOC operations involving insider risk and user-driven compromise.

---

# 🧭 NIST 800-61 Incident Response Lifecycle

---

## 1️⃣ Preparation

### Environment & Tooling
- Azure Virtual Machine (Windows)
- Microsoft Defender for Endpoint (EDR)
- Microsoft Sentinel (SIEM)
- Log Analytics Workspace
- Kusto Query Language (KQL)

### Detection Readiness
- Process execution telemetry via `DeviceProcessEvents`
- Sentinel analytics rule designed to detect suspicious PowerShell web requests
- Entity mappings enabled:
  - Account (internal user)
  - Host
  - Process
- Automatic incident creation and alert grouping enabled

**Objective:** Detect abuse of legitimate tooling caused by internal user activity before impact escalates.

---

## 2️⃣ Detection & Analysis

### Detection Logic
An analytics rule triggered when:
- `powershell.exe` executed
- Command line contained `Invoke-WebRequest`
- External scripts were downloaded from the internet

This behavior is indicative of **post-exploitation activity initiated from an internal user context**, not an external attacker directly accessing the system.

### Detection Query (KQL)
```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

### Investigation Findings
- Incident triggered on **1 internal workstation by 1 internal user**
- User stated they had **installed a free piece of software** shortly before the activity
- PowerShell was silently leveraged to download **3 scripts**:
  - `portscan.ps1`
  - `eicar.ps1`
  - `pwncrypt.ps1`
- While this lab used an attack simulator, the scenario realistically reflects a **user-initiated compromise vector**
- 
<img width="613" height="568" alt="image" src="https://github.com/user-attachments/assets/b5e63e75-3822-47a1-8281-8be39d46d26d" />

---

### Validation: Script Execution Confirmed
```kql
let ScriptNames = dynamic(["eicar.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File"
| where ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
```
<img width="1105" height="414" alt="Screenshot 2026-01-31 145150" src="https://github.com/user-attachments/assets/d303708f-84f0-4c0c-b743-e2041f03b38d" />

**Result:**  
- All downloaded scripts were executed under the internal user context

---

## 3️⃣ Containment, Eradication, and Recovery

### Containment Actions
- Affected endpoint **isolated using Microsoft Defender for Endpoint**
- Full **antimalware scan** performed while isolated

### Script Behavior Analysis (Summary)
- **portscan.ps1** – Internal network reconnaissance across `10.0.0.155–10.0.0.200`
- **eicar.ps1** – Antivirus control validation via EICAR test file
- **pwncrypt.ps1** – Ransomware simulation:
  - Encrypts fake user data
  - Drops Bitcoin ransom note
  - Logs activity to `C:\ProgramData\entropygorilla.log`

### Eradication
- No persistent malware detected post-scan
- Malicious scripts removed

### Recovery
- Endpoint removed from isolation
- System restored to normal operation

---

## 4️⃣ Post-Incident Activity

### Lessons Learned
- Internal users are a major attack vector
- Free software installations present elevated risk
- PowerShell abuse is a common post-exploitation technique

### Awareness & Preventive Improvements
- Affected users completed **additional cybersecurity awareness training**
- Organization **upgraded KnowBe4 training package**
- Training frequency increased to reinforce:
  - Safe software installation practices
  - Phishing and malware awareness
- PowerShell usage restrictions planned for non-essential users

---

## 5️⃣ Incident Closure

### Final Assessment
- Incident classified as **True Positive**
- Root cause: **Internal user action leading to script execution**
- No lasting damage due to rapid detection and response
- Security posture improved through **technical controls and user education**

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique |
|------|---------|
| TA0002 – Execution | T1059.001 – PowerShell |
| TA0011 – Command and Control | T1105 – Ingress Tool Transfer |
| TA0007 – Discovery | T1046 – Network Service Scanning |
| TA0040 – Impact | T1486 – Data Encrypted for Impact |

---

## 🧠 Skills Demonstrated
- NIST 800-61 Incident Response Lifecycle
- Insider Threat & User-Initiated Incident Analysis
- Microsoft Sentinel (SIEM)
- Microsoft Defender for Endpoint (EDR)
- KQL Threat Hunting
- Malware Triage & Impact Assessment
- Security Awareness Program Improvement
