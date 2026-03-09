# 🏥 Securing a Regional Healthcare Provider's Network
### Open-Source Security Implementation — VirtualBox + Ubuntu
*A Complete Layered Defence Strategy for HIPAA & NDPA Compliance*

---

## Project Overview

| Field | Value |
|---|---|
| Classification | CONFIDENTIAL |
| Version | 1.0 |
| Platform | VirtualBox 7.x + Ubuntu 22.04 LTS |
| Compliance Targets | HIPAA, NDPA 2023 |
| Approach | Open-Source Toolstack |

**Goal:** Modernise and secure a regional hospital network by implementing a layered defence strategy, enabling safe digitisation of patient records and remote consultations while achieving full HIPAA and NDPA compliance.

---

## Repository Layout

```
healthcare-network-security/
├── README.md
├── session1/setup_host_and_vms.sh          ← Session 1: VirtualBox + all VMs
├── session2/configure_pfsense.sh           ← Session 2: pfSense firewall, VLANs, VPN
├── session3/setup_openvas.sh               ← Session 3: Greenbone Vulnerability Manager
├── session4/setup_cuckoo.sh                ← Session 4: Cuckoo Sandbox
├── session5/setup_elk_wazuh.sh             ← Session 5: ELK Stack + Wazuh SIEM
└── session6/configure_iam_and_compliance.sh← Session 6: Samba AD, FreeRADIUS, Compliance
```

---

## Tool Mapping (Enterprise to Open-Source)

| Enterprise Tool | Open-Source Replacement | Script |
|---|---|---|
| FortiGate (NGFW/IPS/VPN) | pfSense + Suricata | session2/configure_pfsense.sh |
| FortiAnalyzer (SIEM) | ELK Stack + Wazuh | session5/setup_elk_wazuh.sh |
| FortiSandbox | Cuckoo Sandbox | session4/setup_cuckoo.sh |
| Nessus / OpenVAS | Greenbone (OpenVAS) | session3/setup_openvas.sh |
| Active Directory / RADIUS | Samba AD + FreeRADIUS | session6/configure_iam_and_compliance.sh |
| Wireshark | Wireshark on Ubuntu Desktop | session6/configure_iam_and_compliance.sh |

---

## VM Inventory

| VM Name | OS | vCPU | RAM | IP | Purpose |
|---|---|---|---|---|---|
| pfSense-FW | pfSense CE (FreeBSD) | 2 | 2 GB | WAN+multi | NGFW, IPS, VPN |
| ELK-SIEM | Ubuntu 22.04 | 4 | 8 GB | 10.0.30.10 | ELK + Wazuh Manager |
| Samba-AD | Ubuntu 22.04 | 2 | 4 GB | 10.0.20.10 | Active Directory + FreeRADIUS |
| OpenVAS-Scanner | Ubuntu 22.04 | 2 | 4 GB | 10.0.30.20 | Greenbone VM |
| Cuckoo-Sandbox | Ubuntu 20.04 | 2 | 4 GB | 10.0.30.30 | Malware sandbox host |
| Web-Server-DMZ | Ubuntu 22.04 | 1 | 2 GB | 10.0.10.10 | Simulated hospital portal |
| Workstation-W10 | Windows 10 Pro | 2 | 4 GB | 10.0.20.50 | Domain-joined endpoint |
| Wireshark-VM | Ubuntu 22.04 Desktop | 1 | 2 GB | 10.0.30.40 | Packet capture |

---

## Network Segmentation

| Network | VLAN | Subnet | Hosts |
|---|---|---|---|
| DMZ | 10 | 10.0.10.0/24 | Web-Server-DMZ |
| Internal | 20 | 10.0.20.0/24 | Workstation-W10, Samba-AD |
| Management | 30 | 10.0.30.0/24 | ELK-SIEM, OpenVAS, Cuckoo, Wireshark-VM |
| VPN Pool | 50 | 10.0.50.0/24 | Remote clinicians via OpenVPN |

---

## Quick-Start Execution Order

```bash
# Session 1: Run on Ubuntu HOST machine
chmod +x session1/setup_host_and_vms.sh && ./session1/setup_host_and_vms.sh

# Session 2: pfSense is GUI-driven — script prints exact GUI steps
bash session2/configure_pfsense.sh

# Session 3: Run on OpenVAS-Scanner VM (10.0.30.20)
chmod +x session3/setup_openvas.sh && ./session3/setup_openvas.sh

# Session 4: Run on Cuckoo-Sandbox VM (Ubuntu 20.04, 10.0.30.30)
chmod +x session4/setup_cuckoo.sh && ./session4/setup_cuckoo.sh

# Session 5: Run on ELK-SIEM VM (10.0.30.10)
chmod +x session5/setup_elk_wazuh.sh && ./session5/setup_elk_wazuh.sh

# Session 6: Run on Samba-AD VM (10.0.20.10)
chmod +x session6/configure_iam_and_compliance.sh
./session6/configure_iam_and_compliance.sh all      # full run
./session6/configure_iam_and_compliance.sh samba    # Samba AD only
./session6/configure_iam_and_compliance.sh radius   # FreeRADIUS only
./session6/configure_iam_and_compliance.sh evidence # collect compliance evidence
```

---

## Environment Variables

```bash
# Session 1 — ISO paths and host NIC
export HOST_NIC="eth0"
export PFSENSE_ISO="/path/to/pfSense.iso"
export UBUNTU_22_ISO="/path/to/ubuntu-22.04-live-server-amd64.iso"
export UBUNTU_22_DESKTOP_ISO="/path/to/ubuntu-22.04-desktop-amd64.iso"
export UBUNTU_20_ISO="/path/to/ubuntu-20.04-live-server-amd64.iso"
export WIN10_ISO="/path/to/win10.iso"

# Session 6 — sensitive credentials
export AD_ADMINPASS='H0sp1t@l$ecure2024!'
export RADIUS_SECRET='R@dius$ecret123'
```

---

## HIPAA Compliance Matrix

| HIPAA Standard | Control | Tool |
|---|---|---|
| 164.308(a)(1) Risk Analysis | Vulnerability scanning | OpenVAS |
| 164.308(a)(3) Workforce Access | Role-based OUs | Samba AD |
| 164.308(a)(4) Access Control | VLANs + RADIUS | pfSense + FreeRADIUS |
| 164.308(a)(6) Incident Response | Real-time alerting | Wazuh |
| 164.312(a)(1) Technical Access | Zero-Trust firewall rules | pfSense |
| 164.312(b) Audit Controls | Centralised logging | ELK + Wazuh |
| 164.312(c)(1) Integrity | FIM + Sandbox | Wazuh + Cuckoo |
| 164.312(d) Authentication | 802.1X + VPN certs | FreeRADIUS + OpenVPN |
| 164.312(e)(1) Transmission Security | AES-256-GCM | OpenVPN |

---

## Host System Requirements

| Specification | Minimum | Recommended |
|---|---|---|
| CPU | 8-core with VT-x/AMD-V | 12+ core |
| RAM | 16 GB | 32 GB |
| Storage | 250 GB SSD | 500 GB NVMe SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |

*For educational lab use only. Do not connect to live patient systems.*
