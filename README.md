# Threat-Hunting-Scenario-Lurker

## Overview

A critical responsibility of any security team is to ensure the complete elimination of threats within a network. Detecting, analyzing, isolating, eradicating, and recovering are the common steps involved in a threat hunting or incident response investigation. It is important to follow the NIST 800-61 Incident Response Life Cycle, as well as the organisation's internal playbook, when dealing with such issues. However, things are often overlooked, and hidden artefacts can emerge later. Being thorough is crucial for establishing a strong security posture, especially as threat actors continually find new and sophisticated ways to maintain persistence. This investigation presents the findings from a scenario in which a threat actor was not completely eliminated as initially thought, along with recommended steps to fully eradicate any artefacts left behind in the network.

---

## 1. Preparation

### Scenario:

The security team initially reported that they had eliminated an outside threat following a breach in the network. The infected device was isolated from the network to prevent further spread and was re-imaged for reuse. However, there are suspicions that a new device has started to exhibit similar signs as in the previous incident—such as the tools used, the time of operation, and the ease of movement. Additionally, fewer logs are being recorded, suggesting that this new attacker is covering their tracks more carefully. It is uncertain whether the current incident is a red-team exercise or if the previous incident was simply a Trojan horse designed to gain deeper access and enable more significant damage.

### Hypothesis:

The organisation is currently on high alert. It is reasonable to suspect that the threat actor has gained initial access while leaving very few traces. The investigation should focus on directories or folders that may contain backdoors or serve as nexus points for lateral movement within the network.

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


---

