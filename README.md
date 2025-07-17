
# HelloPelloBello: A Student's Sigma Detection Rulebook

> Learning one Sigma rule at a time.

---

##  Introduction
This project, **UniversalSigmaRules**, is a personal initiative where I wrote **10 Sigma detection rules**. The goal wasn't to be perfect, the goal was to learn. To understand attacker behavior, translate it into detections.

All rules here are crafted for real-world use and tested in lab conditions. I’ve documented each one with detailed explanations, MITRE ATT\&CK mappings, references, and learning resources. I hope this helps other beginners like me.

---

##  Project Structure

```
UniversalSigmaRules/
├── README.md
├── suspicious_powershell_download.yaml
├── multiple_failed_logins.yaml
├── cmd_spawned_by_office.yaml
├── unusual_parent_child_process.yaml
├── remote_desktop_connection.yaml
├── wmiexec_remote_execution.yaml
├── ransomware_file_extensions.yaml
├── suspicious_base64_command.yaml
├── dns_tunneling_detect.yaml
├── persistence_new_scheduled_task.yaml
```

Each rule is a standalone `.yaml` file, following [Sigma standard format](https://github.com/SigmaHQ/sigma/wiki/Specification). You can plug them directly into SIEMs that support Sigma or convert them using [sigmac](https://github.com/SigmaHQ/sigmac).

---

##  What Is Sigma?

**Sigma** is like the YARA of logs. While YARA detects malicious files, Sigma detects malicious activity in logs. It uses a flexible YAML format that can be converted into queries for SIEMs like ELK, Splunk, or Sentinel.

Learn more: [https://sigmahq.io](https://sigmahq.io)

---

##  Tools I Used

*  MITRE ATT\&CK Framework: [https://attack.mitre.org/](https://attack.mitre.org/)
*  Sysmon + Windows Event Logs (for testing): [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
*  Sigma HQ: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
*  Sigma rule editor: [https://sigmac.io](https://sigmac.io)
*  CyberChef (for decoding base64, etc.): [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

---

##  Sigma Rule Explanations (Deep Dive)

---

### 1. `suspicious_powershell_download.yaml`

**What it detects:** Use of PowerShell to download files via suspicious commands

**Why it matters:** Attackers often use `Invoke-WebRequest`, `Start-BitsTransfer`, etc. to download malware during initial access.

**Event Source:** Sysmon (Event ID 1) or Windows Security (Event ID 4688)

**MITRE ATT\&CK:**

* T1059.001 (PowerShell)
* T1105 (Ingress Tool Transfer)

**Sample Query (converted to Splunk):**

```
(Image="*\\powershell.exe") (CommandLine="*Invoke-WebRequest*" OR "*Start-BitsTransfer*")
```

**References:**

* [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)
* [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)
* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)

---

### 2. `multiple_failed_logins.yaml`

**What it detects:** Multiple failed login attempts within a short time (brute-force indicator)

**Event Source:** Windows Security Logs (Event ID 4625)

**MITRE ATT\&CK:**

* T1110 (Brute Force)

**Why it matters:** Brute force attempts often go undetected if thresholds are too loose. This helps catch those attempts early.

**References:**

* [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)
* [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)

---

### 3. `cmd_spawned_by_office.yaml`

**What it detects:** Command shells (cmd, PowerShell) spawned by MS Office apps

**MITRE ATT\&CK:**

* T1059 (Command and Scripting Interpreter)
* T1203 (Exploitation for Client Execution)

**Why it matters:** Often seen in macro malware attacks — Word launching cmd → PowerShell → Download malware

**Reference Attack Chain:**

* Emotet, Qakbot, Dridex use this pattern

**Event Source:** Sysmon (Event ID 1)

---

### 4. `unusual_parent_child_process.yaml`

**What it detects:** Suspicious parent-child process pairs like `winword.exe → cmd.exe`

**MITRE ATT\&CK:**

* T1059
* T1047 (WMI Execution)

**Why it matters:** Unusual process inheritance is a huge red flag in malware behavior chains.

**Tool:** Sysmon is best for catching this

---

### 5. `remote_desktop_connection.yaml`

**What it detects:** Successful RDP logins (Logon Type 10)

**Event Source:** Windows Security Log (Event ID 4624)

**MITRE ATT\&CK:**

* T1021.001 (Remote Services: RDP)

**Why it matters:** Monitoring RDP usage is critical in detecting lateral movement, initial access, or insider activity.

**References:**

* [https://attack.mitre.org/techniques/T1021/001/](https://attack.mitre.org/techniques/T1021/001/)
* [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)

---

### 6. `wmiexec_remote_execution.yaml`

**What it detects:** Use of WMIC for remote command execution

**Event Source:** Sysmon (Event ID 1)

**MITRE ATT\&CK:**

* T1047 (WMI Execution)

**Why it matters:** WMIC is commonly used in fileless malware and red team operations

**Red team tools:**

* Impacket, Empire, Metasploit modules

---

### 7. `ransomware_file_extensions.yaml`

**What it detects:** File creations with known ransomware extensions (e.g., `.lock`, `.pay`, `.encrypted`)

**MITRE ATT\&CK:**

* T1486 (Data Encrypted for Impact)

**Event Source:** Sysmon (Event ID 11)

**Why it matters:** This can help identify ransomware **in-action**, especially if you're using file integrity monitoring (FIM).

**References:**

* [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/)

---

### 8. `suspicious_base64_command.yaml`

**What it detects:** PowerShell commands using `-enc` with large base64 payloads

**MITRE ATT\&CK:**

* T1027 (Obfuscated Files or Information)
* T1059.001

**Why it matters:** Obfuscation is used to hide malware behavior, and base64 is the most common method.

**Reference Tools:**

* CyberChef: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

---

### 9. `dns_tunneling_detect.yaml`

**What it detects:** Base64-like long DNS queries (possible exfiltration or C2)

**MITRE ATT\&CK:**

* T1071.004 (Application Layer Protocol: DNS)

**Event Source:** DNS logs, Zeek, Windows DNS logs

**Why it matters:** DNS is often ignored by defenders — great covert channel for attackers.

**Real-World Cases:**

* DNSCat2, Iodine, and other tunneling tools

---

### 10. `persistence_new_scheduled_task.yaml`

**What it detects:** Creation of scheduled tasks via `schtasks.exe`

**MITRE ATT\&CK:**

* T1053.005 (Scheduled Task/Job: Scheduled Task)

**Why it matters:** A common persistence method for malware and red teamers

**Event Source:** Sysmon (Event ID 1)

**References:**

* [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)
* [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)

---

##  What I Learned From This Project

1. **Writing detection rules forces you to understand attacker behavior deeply.**
2. Sigma is not about tools  it’s about mindset: spotting patterns.
3. Even basic logs (like login attempts or command lines) hold rich detection value.
4. MITRE ATT\&CK helps you frame your detections around known tactics.
5. Good documentation matters, every rule should tell a story.

---

## Credits

I learned a lot from these people and sources:

* [SigmaHQ Team](https://github.com/SigmaHQ)
* [MalwareArchaeology.com](https://www.malwarearchaeology.com)
* [HackerHurricane](https://github.com/HackerHurricane)
* [SwiftOnSecurity's Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config)
* YouTube channels: John Hammond, HuskyHacks, Detection Engineering Podcast, The Cyber Mentor

---

##  Disclaimer

This is a student project built for educational purposes. Do not use it in production environment.

---

---

Stay curious. Stay defensive. 💙

**Thank You.**

---

##  Introduction
This project, **UniversalSigmaRules**, is a personal initiative where I wrote **10 Sigma detection rules**. The goal wasn't to be perfect, the goal was to learn. To understand attacker behavior, translate it into detections, and grow as a blue teamer.

All rules here are crafted for real-world use and tested in lab conditions. I’ve documented each one with detailed explanations, MITRE ATT\&CK mappings, references, and learning resources. I hope this helps other beginners like me.

---

##  Project Structure

```
UniversalSigmaRules/
├── README.md
├── suspicious_powershell_download.yaml
├── multiple_failed_logins.yaml
├── cmd_spawned_by_office.yaml
├── unusual_parent_child_process.yaml
├── remote_desktop_connection.yaml
├── wmiexec_remote_execution.yaml
├── ransomware_file_extensions.yaml
├── suspicious_base64_command.yaml
├── dns_tunneling_detect.yaml
├── persistence_new_scheduled_task.yaml
```

Each rule is a standalone `.yaml` file, following [Sigma standard format](https://github.com/SigmaHQ/sigma/wiki/Specification). You can plug them directly into SIEMs that support Sigma or convert them using [sigmac](https://github.com/SigmaHQ/sigmac).

---

##  What Is Sigma?

**Sigma** is like the YARA of logs. While YARA detects malicious files, Sigma detects malicious activity in logs. It uses a flexible YAML format that can be converted into queries for SIEMs like ELK, Splunk, or Sentinel.

Learn more: [https://sigmahq.io](https://sigmahq.io)

---

##  Tools I Used

*  MITRE ATT\&CK Framework: [https://attack.mitre.org/](https://attack.mitre.org/)
*  Sysmon + Windows Event Logs (for testing): [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
*  Sigma HQ: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
*  Sigma rule editor: [https://sigmac.io](https://sigmac.io)
*  CyberChef (for decoding base64, etc.): [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

---

##  Sigma Rule Explanations (Deep Dive)

---

### 1. `suspicious_powershell_download.yaml`

**What it detects:** Use of PowerShell to download files via suspicious commands

**Why it matters:** Attackers often use `Invoke-WebRequest`, `Start-BitsTransfer`, etc. to download malware during initial access.

**Event Source:** Sysmon (Event ID 1) or Windows Security (Event ID 4688)

**MITRE ATT\&CK:**

* T1059.001 (PowerShell)
* T1105 (Ingress Tool Transfer)

**Sample Query (converted to Splunk):**

```
(Image="*\\powershell.exe") (CommandLine="*Invoke-WebRequest*" OR "*Start-BitsTransfer*")
```

**References:**

* [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)
* [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)
* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)

---

### 2. `multiple_failed_logins.yaml`

**What it detects:** Multiple failed login attempts within a short time (brute-force indicator)

**Event Source:** Windows Security Logs (Event ID 4625)

**MITRE ATT\&CK:**

* T1110 (Brute Force)

**Why it matters:** Brute force attempts often go undetected if thresholds are too loose. This helps catch those attempts early.

**References:**

* [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)
* [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)

---

### 3. `cmd_spawned_by_office.yaml`

**What it detects:** Command shells (cmd, PowerShell) spawned by MS Office apps

**MITRE ATT\&CK:**

* T1059 (Command and Scripting Interpreter)
* T1203 (Exploitation for Client Execution)

**Why it matters:** Often seen in macro malware attacks — Word launching cmd → PowerShell → Download malware

**Reference Attack Chain:**

* Emotet, Qakbot, Dridex use this pattern

**Event Source:** Sysmon (Event ID 1)

---

### 4. `unusual_parent_child_process.yaml`

**What it detects:** Suspicious parent-child process pairs like `winword.exe → cmd.exe`

**MITRE ATT\&CK:**

* T1059
* T1047 (WMI Execution)

**Why it matters:** Unusual process inheritance is a huge red flag in malware behavior chains.

**Tool:** Sysmon is best for catching this

---

### 5. `remote_desktop_connection.yaml`

**What it detects:** Successful RDP logins (Logon Type 10)

**Event Source:** Windows Security Log (Event ID 4624)

**MITRE ATT\&CK:**

* T1021.001 (Remote Services: RDP)

**Why it matters:** Monitoring RDP usage is critical in detecting lateral movement, initial access, or insider activity.

**References:**

* [https://attack.mitre.org/techniques/T1021/001/](https://attack.mitre.org/techniques/T1021/001/)
* [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)

---

### 6. `wmiexec_remote_execution.yaml`

**What it detects:** Use of WMIC for remote command execution

**Event Source:** Sysmon (Event ID 1)

**MITRE ATT\&CK:**

* T1047 (WMI Execution)

**Why it matters:** WMIC is commonly used in fileless malware and red team operations

**Red team tools:**

* Impacket, Empire, Metasploit modules

---

### 7. `ransomware_file_extensions.yaml`

**What it detects:** File creations with known ransomware extensions (e.g., `.lock`, `.pay`, `.encrypted`)

**MITRE ATT\&CK:**

* T1486 (Data Encrypted for Impact)

**Event Source:** Sysmon (Event ID 11)

**Why it matters:** This can help identify ransomware **in-action**, especially if you're using file integrity monitoring (FIM).

**References:**

* [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/)

---

### 8. `suspicious_base64_command.yaml`

**What it detects:** PowerShell commands using `-enc` with large base64 payloads

**MITRE ATT\&CK:**

* T1027 (Obfuscated Files or Information)
* T1059.001

**Why it matters:** Obfuscation is used to hide malware behavior, and base64 is the most common method.

**Reference Tools:**

* CyberChef: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

---

### 9. `dns_tunneling_detect.yaml`

**What it detects:** Base64-like long DNS queries (possible exfiltration or C2)

**MITRE ATT\&CK:**

* T1071.004 (Application Layer Protocol: DNS)

**Event Source:** DNS logs, Zeek, Windows DNS logs

**Why it matters:** DNS is often ignored by defenders — great covert channel for attackers.

**Real-World Cases:**

* DNSCat2, Iodine, and other tunneling tools

---

### 10. `persistence_new_scheduled_task.yaml`

**What it detects:** Creation of scheduled tasks via `schtasks.exe`

**MITRE ATT\&CK:**

* T1053.005 (Scheduled Task/Job: Scheduled Task)

**Why it matters:** A common persistence method for malware and red teamers

**Event Source:** Sysmon (Event ID 1)

**References:**

* [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)
* [https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)

---

##  What I Learned From This Project

1. **Writing detection rules forces you to understand attacker behavior deeply.**
2. Sigma is not about tools  it’s about mindset: spotting patterns.
3. Even basic logs (like login attempts or command lines) hold rich detection value.
4. MITRE ATT\&CK helps you frame your detections around known tactics.
5. Good documentation matters, every rule should tell a story.

---

## Credits

I learned a lot from these people and sources:

* [SigmaHQ Team](https://github.com/SigmaHQ)
* [MalwareArchaeology.com](https://www.malwarearchaeology.com)
* [HackerHurricane](https://github.com/HackerHurricane)
* [SwiftOnSecurity's Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config)
* YouTube channels: John Hammond, HuskyHacks, Detection Engineering Podcast, The Cyber Mentor

---

##  Disclaimer

This is a student project built for educational purposes. Do not use it in production environment.

---

---

Stay curious. Stay defensive. 💙

**Thank You.**
