# Com_NetSec_CA1
Endpoint Security Incident Response and Automated Remediation - Larkspur Retail Group

# CA1 — Endpoint Security Incident Response and Automated Remediation
**Module:** B9CY110 — Communications and Network Security  
**Programme:** MSc Cybersecurity | Dublin Business School  
**Scenario:** Larkspur Retail Group  

---

## What This Project Does
This project builds a complete endpoint security monitoring and automated response 
lab for Larkspur Retail Group. Wazuh SIEM monitors Windows 11 and Linux Ubuntu 
endpoints. A Dockerized AI stack using Ollama llama3.2:1b reads each security alert, 
summarises it in plain English, and automatically triggers a remediation action.

**Full pipeline:** Breach → Wazuh detects → Docker receives → Ollama AI analyses → Remediation executes → Verified in Wazuh

---

## Repository Contents

| File/Folder                         | Description                                                         |
|-------------------------------------|---------------------------------------------------------------------|
| `docker-compose.yml`                | Docker Compose stack — alert-processor and remediation-engine       |
| `alert-processor/processor.py`      | Reads Wazuh alerts, calls Ollama AI, triggers remediation           |
| `alert-processor/Dockerfile`        | Container definition for alert-processor                            |
| `remediation-engine/remediation.py` | HTTP API server — executes allowlisted remediation playbooks        |
| `remediation-engine/Dockerfile`     | Container definition for remediation-engine                         |
| `wazuh-linux-agent/`                | Dockerized Linux endpoint agent (Agent 003)                         |
| `local_rules.xml`                   | 10 custom Wazuh rules (100001–100014) mapped to MITRE ATT&CK        |
| `ossec.conf`                        | Wazuh manager configuration including ai-remediation.log monitoring |
| `actions.log`                       | Audit trail — all AI decisions and remediation actions              |
| `ai-remediation.log`                | AI pipeline events fed back into Wazuh dashboard                    |

---

## Lab Environment

| Host               | OS                    | IP            | Role               | Agent  |
|--------------------|-----------------------|---------------|--------------------|--------|
| Ruth (WSL2)        | Ubuntu 24.04 LTS      | 172.25.185.94 | Wazuh Server       | Server |
| Windows11-PC       | Windows 11 Enterprise | 10.0.2.15     | Windows Endpoint   | 001    |
| ruth-linux-agent   | Ubuntu 22.04 (Docker) | 172.25.185.94 | Linux Endpoint     | 003    |
| alert-processor    | Python 3.11 (Docker)  | 172.17.0.x    | AI Alert Processor | —      |
| remediation-engine | Python 3.11 (Docker)  | 172.17.0.x    | Remediation API    | —      |

---

## Five MITRE ATT&CK Detections

| Rule ID | Detection                            | MITRE    | Platform |
|--------|---------------------------------------|-----------|---------|
| 100001 | Privilege escalation via sudo to ROOT | T1548.003 | Linux   |
| 100002 | Credential access — /etc/shadow read  | T1003.008 | Linux   |
| 100003 | New local admin account created       | T1136.001 | Windows |
| 100004 | DLL Search Order Hijacking            | T1574.001 | Windows |
| 100005 | PowerShell reconnaissance commands    | T1059.001 | Windows |

---

## How to Reproduce the Demo
(bash)
# 1. Start Wazuh
sudo systemctl start wazuh-manager wazuh-indexer wazuh-dashboard

# 2. Start Docker
sudo dockerd > /dev/null 2>&1 & sleep 5
sudo docker start ruth-linux-agent

# 3. Start Ollama on all interfaces
sudo systemctl stop ollama && sleep 2
OLLAMA_HOST=0.0.0.0:11434 ollama serve > /dev/null 2>&1 & sleep 5

# 4. Start AI stack
cd ~/ai-security-stack && sudo docker compose up -d

# 5. Run breach simulations

# Breach Sim 1 — T1548.003 — Privilege Escalation (Ubuntu terminal)
sudo cat /etc/shadow

# Breach Sim 2 — T1003.008 — Credential Access (Ubuntu terminal)
sudo cat /etc/passwd

# Breach Sim 3 — T1136.001 — New Backdoor Account (Windows PowerShell as Admin)
net user hacker Password123! /add
net localgroup administrators hacker /add
net user hacker /delete     # cleanup immediately after

# Breach Sim 4 — T1574.001 — DLL Hijacking (already captured by Sysmon)
# Search in Wazuh Threat Hunting: rule.id: 92219 OR rule.id: 100004

# Breach Sim 5 — T1059.001 — PowerShell Reconnaissance (Windows PowerShell)
whoami /all
net user
net localgroup administrators
ipconfig /all

# 6. Watch AI respond live (Ubuntu terminal)
sudo docker logs -f alert-processor

# 7. Check audit trail
cat ~/ai-security-stack/audit-log/actions.log | tail -20

---

## Automated Remediation Playbooks

| Playbook        | Trigger                        | Action                            | Rollback                          |
|-----------------|--------------------------------|-----------------------------------|-----------------------------------|
| isolate_host    | CRITICAL severity alert        | iptables -A INPUT -s {ip} -j DROP | iptables -D INPUT -s {ip} -j DROP |
| disable_account | HIGH severity or AI recommends | usermod -L {username}             | usermod -U {username}             |

> All actions are **SIMULATED** and require human approval before live execution.  
> Every action is logged with UTC timestamp in `actions.log`.
(bash)
# Verify remediation is working
cat ~/ai-security-stack/audit-log/actions.log | grep "REMEDIATION" | tail -10

# Check AI pipeline visible in Wazuh
# Threat Hunting search: rule.id: 100012   ← remediation executed
# Threat Hunting search: rule.id: 100013   ← verification passed
# Threat Hunting search: rule.id: 100014   ← full pipeline complete
