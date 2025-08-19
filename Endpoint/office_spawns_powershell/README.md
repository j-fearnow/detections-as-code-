# Detection: office_spawns_powershell

**ID:** endpoint_office_spawns_powershell_v1
**Author:** Jesse Fearnow
**Date:** 2025-08-18
**Status:** Experimental
**ATT&CK Mapping:** T1059 - Command and Scripting Interpreter

---

## Description
Office products spawning a command or scripting interpreter like Powershell could be indicative of a malicious macro being executed via a phishing attempt or malicious download.

---

## Data Sources
- Windows Event Logs (Sysmon EventID 1, Security 4688)
- Splunk indexes: sysmon / wineventlog
- KQL: DeviceProcessEvents (Sentinel)
- Sigma: logsource: process_creation, product: windows

---

## Detection Logic
- **Parent Process:** winword.exe, excel.exe, powerpnt.exe
- **Child Process:** powershell.exe, cmd.exe, wscript.exe, cscript.exe 
- **Output:** timestamp computer user ParentImage Image CommandLine 

---

## Queries

### SPL
index=sysmon EventCode=1
| rex field=ParentImage "(?i)\\\\(?<parent_proc>[^\\\\]+\.exe$)"
| rex field=Image "(?i)\\\\(?<child_proc>[^\\\\]+\.exe$)"
| where match(parent_proc, "(?i)^(winword|pwrpnt|excel)\.exe$") AND match(child_proc, "(?i)^(powershell|wscript|cscript|cmd)\.exe$")
| table _time Computer User parent_proc child_proc CommandLine

### KQL
DeviceProcessEvents
| extend parent_proc=tostring(split(ParentImage, "\\")[-1]), extend child_proc=tostring(split(Image, "\\")[-1])
| where parent_proc in~ ("winword.exe", "pwrpnt.exe", "excel") and child_proc in~ ("powershell.exe", "wscript.exe", "cscript.exe", "cmd.exe")
| project Timestamp, Computer, User, parent_proc, child_proc, CommandLine

---

## Testing
- **Environment:** [Splunk / Log Analytics Workspace]
- **Positive Case:** winword.exe executing powershell.exe
- **Negative Case:** explorer.exe executing powershell.exe
- **Evidence:** 

### Splunk Output Sysmon

<img width="1919" height="435" alt="splunk_output_sysmon" src="https://github.com/user-attachments/assets/ec05e856-e870-47dd-94d0-ed11dd4ece4f" />

### Splunk Output WineventLog

<img width="1920" height="432" alt="splunk_output_wineventlog" src="https://github.com/user-attachments/assets/25a472ef-5c08-4096-aa37-2778ff4cb04f" />

### KQL Output

<img width="1920" height="1068" alt="KQL_output" src="https://github.com/user-attachments/assets/300844e9-c7e8-4382-85d7-f0a15220b429" />

---

## False Positives
- Legitimate Office macros or plugins

---

## Improvements
- Add additional LOLBIN executables
- Incorporate with a lookup to filter for known good executions.
