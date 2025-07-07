# Threat-Hunting-Scenario-Lurker

## Scenario


Before you officially begin the flags, you must first determine where to start hunting. Identify where to start hunting with the following intel given: 
1. Days active 2-3 days
2. Executions from Temp folder
3. 15th of June


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
- DeviceProcessEvents
- DeviceFileEvents
```

#### Initial Findings:






```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-06-15 00:00:00) and TimeGenerated < datetime(2025-06-16 00:00:00)
| where ProcessCommandLine has @"\AppData\Local\Temp\" and InitiatingProcessCommandLine has @"\AppData\Local\Temp\"
| where AccountName != "local service"
| order by TimeGenerated desc
```
<img width="1403" alt="Screenshot 2025-07-06 175953" src="https://github.com/user-attachments/assets/0293afb8-1797-4f9a-9d20-4af343a835d9" />

---

