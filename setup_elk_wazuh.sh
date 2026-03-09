#!/usr/bin/env bash
# =============================================================================
# SESSION 5: Cloud, Virtualisation Security, and Incident Response
# Goal   : Deploy ELK Stack + Wazuh SIEM on ELK-SIEM VM
#          (Ubuntu 22.04, VLAN 30 – 10.0.30.10)
#          Deploy Wazuh agents on all other Ubuntu VMs.
#
# RUN ON: ELK-SIEM VM (Ubuntu 22.04) with ≥ 8 GB RAM, 4 vCPUs, 50 GB disk
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $*"; exit 1; }

SIEM_IP="10.0.30.10"
KIBANA_PORT="5601"
WAZUH_PORT="443"
WAZUH_INSTALL_SCRIPT="wazuh-install.sh"
WAZUH_VERSION="4.7"

# =============================================================================
# STEP 1 — Set hostname and static IP
# =============================================================================
step1_set_hostname() {
    step "=== STEP 1: Setting hostname ==="
    sudo hostnamectl set-hostname elk-siem
    info "Hostname set to elk-siem."

    warn "Ensure this VM has static IP ${SIEM_IP}/24 in /etc/netplan/*.yaml"
    warn "  gateway: 10.0.30.1 (pfSense Management VLAN)"
    warn "  dns:     10.0.20.10 (Samba-AD), 8.8.8.8"
}

# =============================================================================
# STEP 2 — Update and install prerequisites
# =============================================================================
step2_update_prereqs() {
    step "=== STEP 2: Updating and installing prerequisites ==="
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y \
        apt-transport-https \
        curl \
        gnupg \
        lsb-release \
        ca-certificates
    info "Prerequisites installed."
}

# =============================================================================
# STEP 3 — Add Elastic 8.x repository
# =============================================================================
step3_add_elastic_repo() {
    step "=== STEP 3: Adding Elastic 8.x repository ==="

    curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
        | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg

    echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] \
https://artifacts.elastic.co/packages/8.x/apt stable main" \
        | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

    sudo apt update
    info "Elastic repository added."
}

# =============================================================================
# STEP 4 — Install Elasticsearch, Logstash, Kibana
# =============================================================================
step4_install_elk() {
    step "=== STEP 4: Installing Elasticsearch, Logstash, Kibana ==="
    sudo apt install -y elasticsearch logstash kibana
    info "ELK packages installed."
}

# =============================================================================
# STEP 5 — Configure Elasticsearch for single-node (lab) setup
# =============================================================================
step5_configure_elasticsearch() {
    step "=== STEP 5: Configuring Elasticsearch ==="

    local es_conf="/etc/elasticsearch/elasticsearch.yml"

    sudo tee "${es_conf}" > /dev/null <<EOF
# ── Basic cluster settings ─────────────────────────────────────────────────
cluster.name: hospital-siem
node.name: elk-siem-node1

# ── Network settings ───────────────────────────────────────────────────────
network.host: 0.0.0.0
http.port: 9200

# ── Discovery (single-node lab) ────────────────────────────────────────────
discovery.type: single-node

# ── Security (disable for lab; enable TLS in production) ───────────────────
xpack.security.enabled: false
xpack.security.enrollment.enabled: false

# ── Paths ──────────────────────────────────────────────────────────────────
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
EOF

    info "Elasticsearch configured."
}

# =============================================================================
# STEP 6 — Configure Kibana
# =============================================================================
step6_configure_kibana() {
    step "=== STEP 6: Configuring Kibana ==="

    local kb_conf="/etc/kibana/kibana.yml"

    sudo tee "${kb_conf}" > /dev/null <<EOF
# ── Server settings ────────────────────────────────────────────────────────
server.port: ${KIBANA_PORT}
server.host: "0.0.0.0"
server.name: "hospital-siem-kibana"

# ── Elasticsearch connection ────────────────────────────────────────────────
elasticsearch.hosts: ["http://localhost:9200"]

# ── Logging ────────────────────────────────────────────────────────────────
logging.root.level: warn
EOF

    info "Kibana configured."
}

# =============================================================================
# STEP 7 — Enable and start ELK services
# =============================================================================
step7_start_elk() {
    step "=== STEP 7: Enabling and starting ELK services ==="

    for svc in elasticsearch logstash kibana; do
        sudo systemctl enable --now "${svc}"
        info "${svc} started."
    done

    # Wait for Elasticsearch to be ready
    info "Waiting for Elasticsearch to become ready (up to 120 s) ..."
    local retries=24
    while [[ ${retries} -gt 0 ]]; do
        if curl -s http://localhost:9200 &>/dev/null; then
            info "Elasticsearch is ready."
            break
        fi
        sleep 5
        (( retries-- ))
    done
    [[ ${retries} -eq 0 ]] && warn "Elasticsearch did not respond in time — check service logs."
}

# =============================================================================
# STEP 8 — Install Wazuh Manager (all-in-one)
# =============================================================================
step8_install_wazuh() {
    step "=== STEP 8: Installing Wazuh Manager (all-in-one) ==="
    warn "This will overlay Elasticsearch/Kibana with Wazuh configuration."

    curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/${WAZUH_INSTALL_SCRIPT}"
    chmod +x "${WAZUH_INSTALL_SCRIPT}"

    # -a = all-in-one (manager + indexer + dashboard)
    sudo bash "${WAZUH_INSTALL_SCRIPT}" -a

    warn "SAVE the generated credentials displayed above!"
    # Capture credentials if they were written to a file
    if [[ -f wazuh-passwords.txt ]]; then
        sudo mv wazuh-passwords.txt /root/wazuh-passwords.txt
        sudo chmod 600 /root/wazuh-passwords.txt
        info "Wazuh credentials saved to /root/wazuh-passwords.txt"
    fi
}

# =============================================================================
# STEP 9 — Configure Logstash pfSense syslog pipeline
# =============================================================================
step9_configure_logstash_syslog() {
    step "=== STEP 9: Configuring Logstash pfSense syslog pipeline ==="

    sudo tee /etc/logstash/conf.d/10-pfsense-syslog.conf > /dev/null <<'EOF'
input {
  udp {
    port  => 5140
    type  => "pfsense"
    codec => "plain"
  }
}

filter {
  if [type] == "pfsense" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_host} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
    }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
  if [type] == "pfsense" {
    elasticsearch {
      hosts  => ["localhost:9200"]
      index  => "pfsense-logs-%{+YYYY.MM.dd}"
    }
  }
}
EOF

    sudo systemctl restart logstash
    info "Logstash pfSense pipeline configured (UDP 5140)."
    warn "In pfSense: Status → System Logs → Settings → Remote Logging"
    warn "  Remote Syslog Server: ${SIEM_IP}:5140   Facility: Everything"
}

# =============================================================================
# STEP 10 — Print Wazuh agent deployment instructions
# =============================================================================
step10_agent_deployment_guide() {
    step "=== STEP 10: Wazuh Agent Deployment Guide ==="

    cat <<EOF

  ── Deploy Wazuh agent on each Ubuntu VM ──────────────────────────────────────
  Run the following commands ON EACH Ubuntu VM (Web-Server-DMZ, Samba-AD, etc.):

    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \\
        | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \\
https://packages.wazuh.com/4.x/apt/ stable main" \\
        | sudo tee /etc/apt/sources.list.d/wazuh.list

    sudo apt update
    sudo apt install -y wazuh-agent

    sudo WAZUH_MANAGER='${SIEM_IP}' systemctl start wazuh-agent
    sudo systemctl enable wazuh-agent

  ── Deploy Wazuh agent on Windows 10 Workstation ────────────────────────────
  1. Download MSI from: https://packages.wazuh.com/4.x/windows/
  2. Run installer; set Manager IP: ${SIEM_IP}
  3. Start the Wazuh service from Services or via PowerShell:
       Start-Service WazuhSvc

  ── Verify agents in Wazuh Dashboard ────────────────────────────────────────
  Open: https://${SIEM_IP}:${WAZUH_PORT}
  Navigate: Management → Agents → check all agents show "Active"
EOF
}

# =============================================================================
# STEP 11 — Key Wazuh monitoring rules reference
# =============================================================================
step11_monitoring_rules() {
    step "=== STEP 11: Key Wazuh Monitoring Rules Reference ==="

    cat <<'EOF'

  Rule ID   Description
  ────────  ──────────────────────────────────────────────────────────────────
  5710      Failed SSH authentication (brute-force detection)
  5902      New user account created
  550       File integrity: new file added to monitored path
  554       File integrity: file modified
  5501      Host-based rootkit detection
  19103     Windows: failed logon attempt (Event ID 4625)
  73676     CIS Benchmark compliance failure

  ── File Integrity Monitoring (FIM) critical paths ──────────────────────────
  Linux:    /etc  /usr/bin  /usr/sbin  /bin  /sbin
  Windows:  C:\Windows\System32  C:\Windows\System32\drivers

  ── Enable FIM on all agents ─────────────────────────────────────────────────
  Edit /var/ossec/etc/ossec.conf on each Ubuntu VM (or push via Wazuh Groups):
    <syscheck>
      <frequency>300</frequency>
      <directories realtime="yes" report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>
    </syscheck>
EOF
}

# =============================================================================
# STEP 12 — Index Lifecycle Management (data retention)
# =============================================================================
step12_ilm_policy() {
    step "=== STEP 12: Configuring Index Lifecycle Management (ILM) ==="

    # Create ILM policy: 30 days hot, 180 days warm, delete after 7 years
    curl -s -X PUT "http://localhost:9200/_ilm/policy/hospital-logs-policy" \
        -H 'Content-Type: application/json' \
        -d '{
          "policy": {
            "phases": {
              "hot":    { "actions": {} },
              "warm":   { "min_age": "30d",  "actions": { "forcemerge": { "max_num_segments": 1 } } },
              "cold":   { "min_age": "180d", "actions": { "freeze": {} } },
              "delete": { "min_age": "2555d", "actions": { "delete": {} } }
            }
          }
        }' | python3 -m json.tool || warn "ILM policy creation failed — check Elasticsearch status."

    info "ILM policy 'hospital-logs-policy' created (7-year retention for HIPAA compliance)."
}

# =============================================================================
# Main
# =============================================================================
main() {
    info "============================================================"
    info "  Session 5 – ELK Stack + Wazuh SIEM"
    info "============================================================"

    [[ "$(id -u)" -eq 0 ]] && warn "Running as root is acceptable for this VM."

    step1_set_hostname
    step2_update_prereqs
    step3_add_elastic_repo
    step4_install_elk
    step5_configure_elasticsearch
    step6_configure_kibana
    step7_start_elk
    step8_install_wazuh
    step9_configure_logstash_syslog
    step10_agent_deployment_guide
    step11_monitoring_rules
    step12_ilm_policy

    info "============================================================"
    info "  Session 5 Complete"
    info "  Kibana:        http://${SIEM_IP}:${KIBANA_PORT}"
    info "  Wazuh Dashboard: https://${SIEM_IP}:${WAZUH_PORT}"
    info "============================================================"
    info "Proceed to session6/ for Samba AD + FreeRADIUS + Wireshark."
}

main "$@"
