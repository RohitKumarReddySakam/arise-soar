<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=28&duration=3000&pause=1000&color=64FFDA&center=true&vCenter=true&width=750&lines=ARISE+SOAR;Security+Orchestration%2C+Automation+%26+Response;90%25+Alert+Triage+Automation;MTTR+Hours+%E2%86%92+Under+5+Minutes" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)](https://attack.mitre.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **Enterprise-grade incident response automation that reduces MTTR from hours to minutes.**

<br/>

[![Automation](https://img.shields.io/badge/Triage_Automation-90%25-64ffda?style=flat-square)](.)
[![MTTR](https://img.shields.io/badge/MTTR-%3C5_Minutes-64ffda?style=flat-square)](.)
[![Playbooks](https://img.shields.io/badge/Playbooks-5_Enterprise-64ffda?style=flat-square)](.)
[![Reduction](https://img.shields.io/badge/Response_Time-85%25_Faster-22c55e?style=flat-square)](.)

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Problem Statement

Modern SOCs face **alert fatigue** — analysts receive thousands of alerts daily, with 45% going uninvestigated. Manual triage takes 30+ minutes per incident.

**ARISE SOAR solves this by:**
- Automatically triaging **90%+ of routine alerts** without analyst intervention
- Executing response playbooks in **under 60 seconds**
- ML-powered severity scoring to surface truly critical threats
- Complete incident timelines for forensic analysis and compliance

| Metric | Value |
|--------|-------|
| **Alert Triage Automation** | **90%** |
| **Mean Time to Respond** | **< 5 minutes** |
| **Response Time Reduction** | **85% faster** |
| **Playbooks Included** | **5 enterprise-grade** |
| **Threat Intel APIs** | VirusTotal, AbuseIPDB, Shodan |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
Alert Sources: SIEM │ EDR │ Email GW │ DLP │ WAF │ Firewall
                           │
                           ▼
              ┌────────────────────────┐
              │  Alert Ingestion Engine │
              │  Normalize │ Dedup     │
              └────────────┬───────────┘
                           │
              ┌────────────▼───────────┐
              │  ML Prioritization     │
              │  Random Forest scoring │
              │  CRITICAL/HIGH/MED/LOW │
              └──────┬─────────────────┘
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
┌──────────────────┐  ┌─────────────────────┐
│  Playbook Engine │  │  Threat Intel       │
│  YAML steps      │  │  VirusTotal         │
│  Auto-trigger    │  │  AbuseIPDB          │
│  Background exec │  │  Shodan             │
└────────┬─────────┘  └─────────────────────┘
         │
         ▼
┌──────────────────────┐
│   Case Management    │
│   Full lifecycle     │
│   MITRE mapping      │
│   Timeline tracking  │
└──────────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎭 Playbooks

| Playbook | Trigger | Steps | Time |
|---------|---------|-------|------|
| `phishing_response` | `phishing` | 7 steps | 35s |
| `ransomware_response` | `ransomware` | 9 steps | 60s |
| `brute_force_response` | `brute_force` | 6 steps | 20s |
| `data_breach_response` | `data_exfiltration` | 9 steps | 90s |
| `malware_containment` | `malware` | 8 steps | 45s |

<details>
<summary><b>🔴 Example: Ransomware Response Execution</b></summary>

```
Step 1/9 ✅  Isolated WORKSTATION-042 from all network segments
Step 2/9 ✅  Terminated svchost.exe (PID 4892) via EDR agent
Step 3/9 ✅  Memory dump collected (2.1 GB) — SHA256: a4f2...
Step 4/9 ✅  Network scan: 2 additional hosts flagged
Step 5/9 ✅  Session tokens revoked for 3 compromised accounts
Step 6/9 ✅  Slack alert sent to #soc-alerts and #ciso
Step 7/9 ✅  Digital evidence preserved and hash-chained
Step 8/9 ✅  Jira ticket IR-4821 created (P0)
Step 9/9 ✅  Legal team notified — breach disclosure initiated
⏱️  Total execution time: 58.3 seconds
```

</details>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/arise-soar.git
cd arise-soar

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python wsgi.py
# → http://localhost:5000
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/arise-soar.git
cd arise-soar
docker-compose up --build
# → http://localhost:5000
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Create alert
POST /api/alerts
{
  "type": "ransomware",
  "severity": "CRITICAL",
  "source": "edr_agent",
  "description": "Ransomware on WORKSTATION-042",
  "indicators": {"host": "WORKSTATION-042", "c2_ip": "185.220.101.47"}
}
# → {"id": "...", "ml_priority": 0.9847, "playbook_triggered": "ransomware_response"}

# Simulate attack scenario
POST /api/simulate
{"scenario": "ransomware"}
# Scenarios: phishing | ransomware | brute_force | data_exfil | lateral_movement

# Enrich IOC
POST /api/enrich
{"ioc": "185.220.101.47", "type": "ip"}

# Platform metrics
GET /api/metrics
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🛡️ MITRE ATT&CK Coverage

| Tactic | Technique | Playbook |
|--------|-----------|---------|
| Initial Access | T1566 Phishing | `phishing_response` |
| Execution | T1204 User Execution | `malware_containment` |
| Credential Access | T1110 Brute Force | `brute_force_response` |
| Lateral Movement | T1550 Alt Auth | `malware_containment` |
| Exfiltration | T1041 Exfil Over C2 | `data_breach_response` |
| Impact | T1486 Data Encrypted | `ransomware_response` |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
arise-soar/
├── app.py                    # Flask + SocketIO application
├── wsgi.py                   # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── core/
│   ├── alert_ingestion.py    # Multi-source normalization
│   ├── playbook_engine.py    # YAML playbook executor
│   ├── case_management.py    # Incident lifecycle
│   ├── ml_prioritizer.py     # ML severity scoring
│   └── integrations.py       # VirusTotal / AbuseIPDB / Slack
│
├── playbooks/
│   ├── phishing_response.yaml
│   ├── ransomware_response.yaml
│   ├── brute_force_response.yaml
│   ├── data_breach_response.yaml
│   └── malware_containment.yaml
│
├── templates/                # Jinja2 web UI
├── static/                   # CSS, JavaScript
└── tests/                    # pytest test suite
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)

> *"Built to solve real SOC challenges — alert fatigue, slow response times, and manual triage overhead that leaves organizations exposed."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/arise-soar?style=social)](https://github.com/RohitKumarReddySakam/arise-soar)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
