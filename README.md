# 🏥 Healthcare Security Lab — Lite Edition
### Single-VM · Docker-Based · HIPAA & NDPA Simulation
**Optimised for 4 GB RAM / 25 GB storage**

---

## Quick Start

```bash
# Step 1 — Run preflight checks (installs missing packages)
sudo bash preflight.sh

# Step 2 — Deploy everything
sudo bash setup.sh all

# Step 3 — Check status
sudo bash setup.sh status
```

---

## Pre-flight Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| OS | Ubuntu 20.04 / 22.04 LTS | Single VM or bare metal |
| RAM | 4 GB | 6 GB recommended for full OpenVAS |
| Disk | 25 GB free | Docker images ~8 GB |
| CPU | 2 cores | VT-x/AMD-V for best performance |
| Internet | Required | Docker Hub + package repos |

The `preflight.sh` script automatically installs:
- `docker.io`, `curl`, `wget`, `nftables`, `tshark`
- `yara`, `python3`, `python3-pip`, `python3-magic`, `file`
- `freeradius-utils` (for `radtest`)
- Docker daemon tuning (log limits, overlay2)
- Kernel tunables (`vm.max_map_count` for Elasticsearch)

---

## Architecture

```
┌─────────────── Ubuntu Host VM (4 GB RAM) ─────────────────┐
│                                                             │
│  ┌── lab-dmz  (172.20.10.0/24) ──────────────────────┐    │
│  │  lab-webserver (nginx:alpine)   128 MB RAM         │    │
│  └───────────────────────────────────────────────────-┘    │
│                    ↕  nftables Zero-Trust                   │
│  ┌── lab-internal (172.20.20.0/24) ──────────────────┐     │
│  │  lab-samba-ad      (Samba 4)    512 MB RAM         │     │
│  │  lab-freeradius    (RADIUS 3)   128 MB RAM         │     │
│  └────────────────────────────────────────────────────┘     │
│                    ↕  nftables Zero-Trust                   │
│  ┌── lab-mgmt (172.20.30.0/24) ──────────────────────┐     │
│  │  lab-elasticsearch (ES 8)       900 MB RAM         │     │
│  │  lab-kibana        (Kibana 8)   512 MB RAM         │     │
│  │  lab-wazuh         (Wazuh 4.7)  512 MB RAM         │     │
│  └────────────────────────────────────────────────────┘     │
│                                                             │
│  Host tools: tshark · YARA · nftables · Wazuh agent        │
│  Total RAM budget: ~2.7 GB containers + ~1.3 GB OS/Docker  │
└─────────────────────────────────────────────────────────────┘
```

---

## Module Commands

```bash
sudo bash setup.sh preflight   # Install all dependencies
sudo bash setup.sh network     # Session 1 — Docker networks + Zero-Trust firewall
sudo bash setup.sh siem        # Session 2 — Elasticsearch + Kibana + Wazuh
sudo bash setup.sh scanner     # Session 3 — Vulnerability scanning
sudo bash setup.sh malware     # Session 4 — YARA static malware analysis
sudo bash setup.sh iam         # Session 5 — Samba AD + FreeRADIUS RADIUS
sudo bash setup.sh traffic     # Session 6 — tshark traffic capture
sudo bash setup.sh evidence    # Collect HIPAA compliance artefacts
sudo bash setup.sh status      # Show all running services + memory
sudo bash setup.sh down        # Stop and remove all containers
```

---

## Session Exercises

### Session 1 — Network Segmentation
```bash
# Verify Zero-Trust rules
sudo nft list ruleset

# DMZ → Internal must FAIL
docker exec lab-webserver ping -c 3 172.20.20.10

# Host → DMZ must SUCCEED
curl http://172.20.10.10

# Watch drops in real time
sudo journalctl -kf | grep LAB_DROP
```

### Session 2 — SIEM & Logging
```bash
# Kibana: http://localhost:5601
# Check Elasticsearch
curl http://localhost:9200/_cat/indices?v
# Query logs
curl http://localhost:9200/healthcare-logs-*/_search?pretty
# Wazuh events
sudo tail -f /var/ossec/logs/ossec.log
```

### Session 3 — Vulnerability Scanning
```bash
# Lite mode (4 GB): runs nmap-based scanner
python3 /opt/healthcare-lab/scanner/scan.py

# Manual nmap scan
nmap -sV -p 80,443,22,9200,5601 172.20.10.10
nmap -sV --script vuln 172.20.10.10
```

### Session 4 — Malware Analysis
```bash
# Analyse EICAR test file
python3 /opt/healthcare-lab/malware-sim/analyze.py \
        /opt/healthcare-lab/malware-sim/eicar.com

# Analyse simulated PHI exfiltration script
python3 /opt/healthcare-lab/malware-sim/analyze.py \
        /opt/healthcare-lab/malware-sim/suspicious_export.sh

# CLI YARA
yara -m /opt/healthcare-lab/malware-sim/hospital_rules.yar /path/to/file
```

### Session 5 — IAM & RADIUS
```bash
# Test RADIUS auth
radtest jdoe 'Doctor@2024!' 127.0.0.1 0 'R@dius$ecret123'
radtest msmith 'Nurse@2024!' 127.0.0.1 0 'R@dius$ecret123'

# AD user management
docker exec lab-samba-ad samba-tool user list
docker exec lab-samba-ad samba-tool group listmembers Physicians
```

### Session 6 — Traffic Analysis
```bash
# Show all capture commands
bash /opt/healthcare-lab/capture_commands.sh

# Capture HTTP to DMZ
sudo tshark -i br-lab-dmz -f 'tcp port 80' -a duration:30

# Watch firewall blocks
sudo journalctl -kf | grep LAB_DROP

# Capture RADIUS auth
sudo tshark -i br-lab-int -f 'udp port 1812'
```

---

## Service Credentials

| Service | URL | Credentials |
|---|---|---|
| Kibana | http://localhost:5601 | no auth (lab mode) |
| Elasticsearch | http://localhost:9200 | no auth (lab mode) |
| DMZ Portal | http://localhost:8080 | public |
| Wazuh API | http://localhost:55000 | see Wazuh docs |
| OpenVAS (6GB+) | https://localhost:9392 | admin / admin |
| Samba AD | ldap://localhost:389 | Administrator / H0sp1t@l$ecure2024! |
| FreeRADIUS | localhost:1812/udp | see RADIUS_SECRET |

**RADIUS test users:**
| Username | Password | Role |
|---|---|---|
| jdoe | Doctor@2024! | Physician |
| msmith | Nurse@2024! | Nurse |
| bwhite | Radiol@gy2024! | Radiologist |
| admin | Admin@2024! | IT Admin |
| labtech | L@bTech2024! | Lab Technician |

---

## HIPAA Compliance Matrix

| Standard | Control | Tool | Evidence File |
|---|---|---|---|
| 164.308(a)(1) | Risk Analysis | nmap/OpenVAS | scanner_summary_*.txt |
| 164.308(a)(3) | Workforce Access | Samba AD OUs | ad_users_*.txt |
| 164.308(a)(4) | Access Control | nftables + RADIUS | nftables_rules_*.txt |
| 164.308(a)(6) | Incident Response | Wazuh | wazuh_agent_log_*.txt |
| 164.312(a)(1) | Technical Access | Zero-Trust firewall | nftables_rules_*.txt |
| 164.312(b) | Audit Controls | ELK Stack | elastic_indices_*.txt |
| 164.312(c)(1) | Integrity | YARA + Wazuh FIM | eicar_analysis_*.txt |
| 164.312(d) | Authentication | FreeRADIUS | running_services_*.txt |
| 164.312(e)(1) | Transmission Security | SSH + TLS | hipaa_summary_*.txt |

Evidence collected in: `~/compliance_evidence/`

---

## Teardown

```bash
# Stop everything (keeps volumes)
sudo bash setup.sh down

# Full clean
sudo bash setup.sh down && sudo docker volume prune -f
```

---

## File Layout

```
healthcare-lab-lite/
├── README.md
├── setup.sh                   ← Main entry point
├── preflight.sh               ← Dependency installer
├── lib/
│   └── common.sh              ← Shared functions, variables, helpers
└── sessions/
    ├── session1_network.sh    ← Docker VLANs + nftables
    ├── session2_siem.sh       ← Elasticsearch + Kibana + Wazuh
    ├── session3_scanner.sh    ← OpenVAS / nmap (RAM-aware)
    ├── session4_malware.sh    ← YARA + python-magic
    ├── session5_iam.sh        ← Samba AD + FreeRADIUS
    ├── session6_traffic.sh    ← tshark captures
    └── session_evidence.sh    ← HIPAA compliance artefacts
```

---

*For educational use only. Do not connect to live patient systems.*
