# ELK SIEM Lab — SIEM-Based Incident Detection with Elastic Stack

> **Course:** BFOR 415/615 — Incident Response  
> **Institution:** University at Albany, SUNY  
> **Team:** Antonio Musumeci · Shrestha Aashish · Thapa Sujan

---

## Table of Contents

- [Project Overview](#project-overview)
- [Project Relevance](#project-relevance)
- [Methodology](#methodology)
- [Attack Scenarios and Results](#attack-scenarios-and-results)
- [Conclusion](#conclusion)
- [Team Contributions](#team-contributions)
- [References](#references)

---

## Project Overview

This project implements a fully functional **Security Information and Event Management (SIEM)** system using the **Elastic Stack (ELK)** deployed in a virtual lab environment. The system monitors, detects, and investigates security incidents across multiple endpoints in real time.

The lab simulates a small corporate network composed of:
- An **Ubuntu server** running the full ELK Stack (Elasticsearch, Logstash, Kibana) with Fleet management
- A **Windows Server 2022** endpoint with Elastic Agent and Sysmon
- A **Linux (Ubuntu)** endpoint with Elastic Agent and Auditd
- A **Kali Linux** attacker machine used to simulate real-world attacks

Three attack scenarios are simulated and investigated:
1. **SSH Brute Force** on Linux using Hydra
2. **RDP Brute Force** on Windows using Hydra
3. **Unauthorized File Modification** monitored via Auditd

---

## Project Relevance

### Why ELK SIEM in Incident Response?

In modern cybersecurity operations, the ability to **detect, analyze, and respond to threats in real time** is critical. A SIEM platform is the backbone of any Security Operations Center (SOC), and the Elastic Stack is one of the most widely adopted open-source solutions in the industry — used by organizations such as the **US Air Force, Cisco, Barclays, and Slack**.

### Mapping to the IR Lifecycle

| IR Phase | ELK Role |
|---|---|
| **Preparation** | Deploy SIEM, configure agents, define monitoring policies |
| **Detection and Analysis** | Kibana dashboards alert on brute force, file changes, anomalous behavior |
| **Containment** | Identify attacker IPs and affected systems from logs |
| **Eradication and Recovery** | Use log evidence to understand scope and reverse damage |
| **Post-Incident Activity** | Review collected logs, improve detection rules |

### Key Skills Developed
- Real-time log ingestion and correlation
- Threat hunting with KQL (Kibana Query Language)
- Endpoint telemetry collection (Sysmon, Auditd)
- Attack simulation and detection validation

---

## Methodology

### Lab Architecture

```
+----------------------------------------------------------+
|                   Virtual Lab Network                    |
|                (Host-Only: 192.168.56.0/24)              |
|                                                          |
|  +-------------------+       +----------------------+   |
|  |  Ubuntu Server    |       |  Windows Server 2022 |   |
|  |  ELK Stack        |<----->|  Elastic Agent       |   |
|  |  + Fleet Server   |       |  + Sysmon            |   |
|  |  192.168.56.10    |       |  192.168.56.20       |   |
|  +-------------------+       +----------------------+   |
|           ^                                              |
|           |          +------------------------+         |
|           +--------->|  Ubuntu Linux Agent    |         |
|                      |  Elastic Agent         |         |
|                      |  + Auditd              |         |
|                      |  192.168.56.30         |         |
|                      +------------------------+         |
|                               ^                         |
|                      +--------+----------+              |
|                      |  Kali Linux       |              |
|                      |  Attacker Machine |              |
|                      |  + Hydra          |              |
|                      |  192.168.56.40    |              |
|                      +-------------------+              |
+----------------------------------------------------------+
```

### Tools and Technologies

| Tool | Version | Role |
|---|---|---|
| **Elasticsearch** | 8.x | Log storage, indexing, search |
| **Logstash** | 8.x | Data collection and processing pipeline |
| **Kibana** | 8.x | Visualization, dashboards, investigation |
| **Elastic Agent + Fleet** | 8.x | Centralized endpoint log collection |
| **Sysmon** | Latest | Windows telemetry (process, network, file) |
| **Auditd** | Latest | Linux file integrity and activity monitoring |
| **Hydra** | Latest | Attack simulation (SSH and RDP brute force) |
| **VirtualBox** | 7.x | Virtualization platform |

### Environment Setup

#### Virtual Machines

| VM | OS | RAM | Role |
|---|---|---|---|
| ELK Server | Ubuntu 22.04 | 4 GB | Elasticsearch + Logstash + Kibana + Fleet |
| Windows Agent | Windows Server 2022 | 4 GB | Elastic Agent + Sysmon |
| Linux Agent | Ubuntu 22.04 | 2 GB | Elastic Agent + Auditd |
| Attacker | Kali Linux | 2 GB | Hydra attack simulation |

#### Network Configuration
All VMs are connected on a **Host-Only network** (192.168.56.0/24) to isolate the lab environment from the host machine network.

### Step-by-Step Process

#### Phase 1 — ELK Stack Installation (Ubuntu Server)
1. Update system and install Java
2. Add Elastic repository and install Elasticsearch, Logstash, Kibana
3. Configure remote access (`network.host: 0.0.0.0`) and open ports 9200 and 5601
4. Generate enrollment token and encryption keys
5. Access Kibana dashboard and complete setup

See screenshots: `docs/screenshots/01-elk-setup/`

#### Phase 2 — Fleet Server Setup
1. Add Fleet Server from Kibana Management > Fleet
2. Deploy Elastic Agent on Ubuntu server as Fleet Server
3. Verify Fleet Server connection on dashboard

See screenshots: `docs/screenshots/02-fleet-server/`

#### Phase 3 — Windows Agent Onboarding
1. Create agent policy in Fleet for Windows endpoint
2. Install Elastic Agent via PowerShell on Windows Server
3. Add Windows integration with Sysmon Operational log channel enabled
4. Verify agent health in Fleet dashboard

See screenshots: `docs/screenshots/03-windows-agent/`

#### Phase 4 — Linux Agent Onboarding
1. Create agent policy in Fleet for Linux endpoint
2. Install and enroll Elastic Agent on Ubuntu Linux machine
3. Install and configure Auditd with custom rules for `/etc/passwd` and `/etc/shadow`
4. Verify agent health in Fleet dashboard

See screenshots: `docs/screenshots/04-linux-agent/`

---

## Attack Scenarios and Results

### Scenario 1 — SSH Brute Force (Linux)

**Objective:** Simulate a brute force attack on SSH and detect it in Kibana.

**Attack Command:**
```bash
hydra -l root -P password.txt <TARGET_IP> ssh
```

**Detection Query (KQL):**
```
event.outcome: "failure" AND process.name: "sshd"
```

> Screenshots and log evidence to be added after lab execution.

See screenshots: `docs/screenshots/05-ssh-bruteforce/`

---

### Scenario 2 — RDP Brute Force (Windows)

**Objective:** Simulate a brute force attack on RDP and detect it via Sysmon logs in Kibana.

**Attack Command:**
```bash
hydra -l administrator -P password.txt <TARGET_IP> rdp
```

**Detection Query (KQL):**
```
winlog.channel: "Microsoft-Windows-Sysmon/Operational" AND event.code: 3
```

> Screenshots and log evidence to be added after lab execution.

See screenshots: `docs/screenshots/06-rdp-bruteforce/`

---

### Scenario 3 — Unauthorized File Modification (Linux)

**Objective:** Detect unauthorized modification of `/etc/passwd` using Auditd.

**Auditd Rules:**
```bash
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
```

**Simulated Attack:**
```bash
sudo echo "testuser:x:1001:1001::/home/testuser:/bin/bash" >> /etc/passwd
```

**Detection Query (KQL):**
```
auditd.log.key: "passwd_changes"
```

> Screenshots and log evidence to be added after lab execution.

See screenshots: `docs/screenshots/07-file-integrity/`

---

## Conclusion

### Key Insights

This project demonstrated that the Elastic Stack provides a powerful, scalable, and cost-effective SIEM solution for real-time threat detection and incident investigation:

- **Centralized visibility** across heterogeneous environments (Windows and Linux) is achievable with a single platform
- **Brute force attacks** generate distinctive log patterns that are easily detectable with simple KQL queries
- **File integrity monitoring** via Auditd provides granular visibility into sensitive system file changes
- **Fleet management** simplifies agent deployment and policy enforcement at scale

### Lessons Learned

- Proper network segmentation is essential even in a lab environment
- Sysmon Event ID 3 (network connection) is highly effective for detecting brute force patterns on Windows
- Auditd rules must be carefully scoped to avoid log flooding while maintaining coverage of critical paths

### Potential Improvements

- Implement automated detection rules and alerts aligned with MITRE ATT&CK
- Add Threat Intelligence integration to enrich logs with known malicious IPs
- Expand monitoring to include DNS, firewall, and web server logs
- Implement role-based access control (RBAC) in Kibana for multi-analyst environments

---

## Team Contributions

| Member | Role | Responsibilities |
|---|---|---|
| **Antonio Musumeci** | Infrastructure Lead | ELK Stack installation and configuration, network setup, firewall rules, Fleet Server management |
| **Shrestha Aashish** | Windows Endpoint Lead | Windows Agent configuration, Sysmon setup, RDP Brute Force simulation, Kibana analysis |
| **Thapa Sujan** | Linux Endpoint Lead | Linux Agent configuration, Auditd setup, SSH Brute Force simulation, log investigation |

---

## References

- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [Elastic Security Guide](https://www.elastic.co/guide/en/security/current/index.html)
- [Sysmon Documentation — Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Auditd Documentation](https://linux.die.net/man/8/auditd)
- [Hydra — THC Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST SP 800-61 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

---

*Last updated: April 2026 — University at Albany, SUNY*
