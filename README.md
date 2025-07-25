# Threat Hunting Scenario Lurker

## Overview

A critical responsibility of any security team is to ensure the complete elimination of threats within a network. Detecting, analyzing, isolating, eradicating, and recovering are the common steps involved in a threat hunting or incident response investigation. It is important to follow the NIST 800-61 Incident Response Life Cycle, as well as the organisation's internal playbook, when dealing with such issues. However, things are often overlooked, and hidden artefacts can emerge later. Being thorough is crucial for establishing a strong security posture, especially as threat actors continually find new and sophisticated ways to maintain persistence. This investigation presents the findings from a scenario in which a threat actor was not completely eliminated as initially thought, along with recommended steps to fully eradicate any artefacts left behind in the network.

---

## 1. Preparation

### Scenario:

The security team initially reported that they had eliminated an outside threat following a breach in the network. The infected device was isolated from the network to prevent further spread and was re-imaged for reuse. However, there are suspicions that a new device has started to exhibit similar signs as in the previous incident—such as the tools used, the time of operation, and the ease of movement. Additionally, fewer logs are being recorded, suggesting that this new attacker is covering their tracks more carefully. It is uncertain whether the current incident is a red-team exercise or if the previous incident was simply a Trojan horse designed to gain deeper access and enable more significant damage.

### Hypothesis:

The organisation is currently on high alert. It is reasonable to suspect that the threat actor has gained initial access while leaving very few traces. The investigation should focus on directories or folders that may contain backdoors or serve as nexus points for lateral movement within the network, as well as other common persistence mechanisms such as registry keys, scheduled tasks, and unauthorised user accounts.


## 2. Data Collection
  
### Action:

Gather relevant data from logs, network traffic, and endpoints.

Ensure the relevant tables contain recent logs:

```kql
- DeviceEvents
- DeviceProcessEvents
- DeviceFileEvents
```

#### Initial Findings:

At the start of the investigation, the security team received intel that may have indicated when the threat attacker triggered the alerts on Microsoft Defender for Endpoint.

1. Days active 2-3 days
2. Executions from Temp folder
3. 15th of June

Based on these parameters, the security team created a KQL query to identify commands executed from the `Temp` folder between June 15th and June 18th by the threat actor. It was important to avoid indexing the schema `DeviceProcessEvents` as this would have returned all PowerShell script executions and process launches over the course of 3 days, which would have generated too many logs. It was much more logical to use `DeviceEvents` instead as specific high-level ActionType events such as `PowerShellCommand`, which would return more filtered events. 

```kql
DeviceEvents
| where Timestamp >= datetime(2025-06-15 07:00:00) and Timestamp < datetime(2025-06-18 07:00:00)
| where ActionType has_any ("PowerShellCommand")
| where InitiatingProcessCommandLine has "Temp"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc

```
![image](https://github.com/user-attachments/assets/e2a5b358-c3af-4046-9161-ab2912aafc79)


The malicious PowerShell command is executed in the `Temp` folder, just as the intel suggested. 

<img width="1064" alt="Screenshot 2025-07-09 175326" src="https://github.com/user-attachments/assets/b7ad7c00-8899-4b59-a8c5-e03bb5df3930" />


Prior to the command execution in the `Temp` folder, the telemetry from the user `michaelvm` returned authorised and expected logs that didn't trigger any alerts. It was still unknown when or how the threat actor gained initial access. The team hypothesised that the threat actor surreptitiously executed the malicious PowerShell command during periods of the baseline telemetry sent from `michaelvm`. The `DeviceProcessEvents` schema was used to explore further on all of the PowerShell processes that were not picked up in the `DeviceEvents` schema. This spanned from `2025-06-15T07:02:17.8259072Z` til `2025-06-16T07:53:20.663666Z`, when the command was executed in the `Temp` folder. 

```kql
let EndTime = datetime(2025-06-16T07:53:20.663666Z);
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp >= datetime(2025-06-15 07:00:00) and Timestamp <= EndTime
| where FileName == "powershell.exe"
| where ProcessCommandLine contains ".ps1"
| project Timestamp, DeviceName, FileName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```


<img width="1094" alt="Screenshot 2025-07-09 185055" src="https://github.com/user-attachments/assets/518d30ba-8463-4fe2-8144-50f4803c9298" />


The yellow boxes represent `michaelvm`'s normal, baseline telemetry, while the red boxes highlight the unauthorised commands that were executed by the threat actor. The `InitiatingProcessCommandLine` was only a `powershell.exe` contrary to the rest of the logs provided. Upon further inspection, it was found that the threat actor ran the command `"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\Mich34L_id\CorporateSim\Investments\Crypto\wallet_gen_0.ps1"` along with four additional iterations ending in consecutive numbers:
1. `wallet_gen_1.ps1`
2. `wallet_gen_2.ps1`
3. `wallet_gen_3.ps1`
4. `wallet_gen_4.ps1`

The presence of the folder path `Crypto` within these commands is a strong indication that the threat actor infiltrated the user `michaelvm`'s device at `2025-06-16T05:38:07.9685093Z.`


<img width="1066" alt="Screenshot 2025-07-09 185649" src="https://github.com/user-attachments/assets/10d3901f-cd9d-42a1-afec-ad3cf25d966f" />


Threat actors will perform local reconnaissance to confirm they have successfully gained initial access. Commands such as `whoami`, `ipconfig`, and `systeminfo` will return detailed information about the internal environment that will ultimately facilitate the attacker's objectives. The security team checked `DeviceProcessEvents` and scanned for any reconnaissance activity occuring before `2025-06-16T07:53:20.663666Z`. 

<img width="1000" alt="Screenshot 2025-07-09 195459" src="https://github.com/user-attachments/assets/63a6b6d2-f252-4aca-b1bb-b2bad6569aec" />


The attacker runs the `whoami` command at `2025-06-16T05:56:58.3597286Z`, 18 minutes after it had initially infiltrated the user `michaelvm` at `2025-06-16T05:38:07.9685093Z`. This aligns with known techniques where threat actors try to remain undetected as long as possible after the initial compromise, trying to blend in with normal traffic or user behaviour. During this time, attackers may enumerate directories, check for security tools, or observe system processes to gather more information. 


After gaining establishing initial access, threat actors will start to scour the network, looking for any important files or data that they can exfiltrate or encrypt. Numerous logs returned information regarding cryptocurrency holdings. Focusing on the term `crypto` returned these results.


```kql
DeviceFileEvents
| where DeviceName == "michaelvm"
| where FileName == "crypto"
| where Timestamp >= datetime(2025-06-16T05:38:07.9685093Z) and Timestamp <= datetime(2025-06-16T07:53:20.663666Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine 
| order by Timestamp asc
```

<img width="1066" height="446" alt="Screenshot 2025-07-11 165349" src="https://github.com/user-attachments/assets/c6e1f572-25fc-4bdb-9cc9-34153d88a4c0" />

It is very likely that the threat actor was interested in the file `QuarterlyCryptoHoldings.docx`, as it would contain significant information regarding cryptocurrency ownership. Due to the importance of this document, it is reasonable to assume that the threat actor decided to exfiltrate it. Before exfiltration, the threat actor would typically access the file one last time, which aligns with the timeline shown in the logs below at `2025-06-16T06:12:28.2856483Z`.

```kql
DeviceEvents
| where DeviceName == "michaelvm"
| where FileName contains 'QuarterlyCryptoHolding'
| where Timestamp >= datetime(2025-06-16T05:38:07.9685093Z) and Timestamp <= datetime(2025-06-16T07:53:20.663666Z)
//| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine 
| order by Timestamp desc
``` 
<img width="1229" height="433" alt="Screenshot 2025-07-11 172923" src="https://github.com/user-attachments/assets/63dd577c-7b71-42b7-8644-ae4756b5dd7d" />

One method of managing file transfers is by using Windows' native command-line tool, `bitsadmin.exe`. Files are transferred via the Background Intelligent Transfer Service (BITS), which is often abused by threat actors as a Living off the Land Binary (LOLBIN) to stealthily download or upload files, frequently bypassing traditional security controls because it is a trusted, native tool. This technique is commonly a precursor to data exfiltration or establishing persistence, as BITS jobs can be scripted to continue even after a user logs out or the system reboots.


```kql
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where FileName contains "bitsadmin.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
``` 

<img width="1309" height="395" alt="Screenshot 2025-07-11 213256" src="https://github.com/user-attachments/assets/f9c52c39-c8b2-4025-9b9f-0fc1d3b4be9d" />

Before a threat actor launches an attack, they will often drop malicious payloads onto a host prior to execution. This process is known as staging, which frequently takes place in Temp folders or uncommon directories. Threat actors often name these payloads to resemble legitimate software in order to avoid detection. Returning to the crypto theme of this investigation, it is reasonable to assume that any file related to finance could be targeted, which can be seen below with the file `ledger_viewer.exe` at `2025-06-16T06:15:37.0446648Z`.

```kql
DeviceFileEvents
| where DeviceName == "michaelvm"
| where Timestamp >= datetime(2025-06-16T05:38:07.9685093Z) and Timestamp <= datetime(2025-06-16T07:53:20.663666Z)
| where FolderPath contains "temp"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
``` 
<img width="1123" height="512" alt="Screenshot 2025-07-11 221443" src="https://github.com/user-attachments/assets/97cffbf6-db3a-4972-a09c-01631c0e1498" />


A common technique used by attackers is executing a malicious HTML Application (HTA) script via a trusted Windows binary. Native Windows utilities such as `mshta.exe` are designed to execute HTA files, which are standalone applications written in HTML and scripting languages such as JavaScript or VBScript. Attackers may drop an HTA file in a Temp folder to stage an attack, then execute it with `mshta.exe`. This can be triggered by the user double-clicking the file or by running it from the command line. Since `mshta.exe` is signed by Microsoft and rarely blocked, detection is extremely difficult. Furthermore, because it runs outside the browser, it bypasses browser-based security restrictions. Attackers can easily phish users into executing malicious HTA files by giving them innocuous, legitimate-looking names. In this case, the threat actor named the HTA file `client_update.hta` and, with PowerShell as the parent process, executed the HTA file in the Temp folder using the command `"mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta` at `2025-06-16T06:17:27.0378198Z`.


```kql
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp >= datetime(2025-06-16T05:38:07.9685093Z) and Timestamp <= datetime(2025-06-16T07:53:20.663666Z)
| where FileName == "mshta.exe"
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
``` 

<img width="2581" height="838" alt="image" src="https://github.com/user-attachments/assets/3ece8cc9-f525-439f-a75f-d78fc5ff2796" />


Alternate Data Streams: 

```kql
DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp >= datetime(2025-06-16T05:38:07.9685093Z) and Timestamp <= datetime(2025-06-16T07:53:20.663666Z)
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, SHA1
``` 


<img width="1326" height="505" alt="Screenshot 2025-07-11 233322" src="https://github.com/user-attachments/assets/11d2cfa4-c7ff-4a85-9037-55c8a5313e78" />




Persistence achieved through autorun script

<img width="2515" height="664" alt="image" src="https://github.com/user-attachments/assets/82bd64c5-216b-4feb-955e-9392e2691276" />



Scheduled Task

<img width="1367" height="335" alt="Screenshot 2025-07-12 141751" src="https://github.com/user-attachments/assets/06da3d82-0b5d-4831-89e3-84bb65826795" />



Common Lateral Movement Commands
1. \\

    What it is: Double backslash, denotes a UNC (Universal Naming Convention) path.

    Example: \\REMOTEPC\C$\Windows\Temp

    Use: Accessing files or shares on a remote machine.

2. psexec

    What it is: A Sysinternals tool for executing processes on remote systems.

    Example: psexec \\REMOTEPC cmd.exe

    Use: Running commands or launching shells on remote computers.

3. wmic

    What it is: Windows Management Instrumentation Command-line tool.

    Example: wmic /node:REMOTEPC process call create "cmd.exe"

    Use: Managing and executing processes on remote machines.

4. mstsc

    What it is: Microsoft Terminal Services Client (Remote Desktop).

    Example: mstsc /v:REMOTEPC

    Use: Connecting to another computer via Remote Desktop Protocol (RDP).

5. Enter-PSSession

    What it is: PowerShell cmdlet for starting an interactive session with a remote computer.

    Example: Enter-PSSession -ComputerName REMOTEPC

    Use: Remotely controlling another computer via PowerShell.


```kql DeviceEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine contains "psexec"
    or ProcessCommandLine contains "wmic"
    or ProcessCommandLine contains "mstsc"
    or ProcessCommandLine contains "Enter-PSSession"
| where Timestamp >= datetime(2025-06-16T07:53:20.663666Z)
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```

<img width="1139" height="629" alt="Screenshot 2025-07-12 145236" src="https://github.com/user-attachments/assets/1d0ae602-cbcf-449f-b5d6-e8e5849bed35" />


```kql
DeviceProcessEvents
| where ProcessCommandLine contains "centralsrvr" and ProcessCommandLine contains "psexec"    
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp asc
```

<img width="1328" height="502" alt="Screenshot 2025-07-12 154706" src="https://github.com/user-attachments/assets/edf3ea0c-6f28-4a3d-a7b9-9a58692d1417" />





---





