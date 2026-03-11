#!/usr/bin/env bash
# =============================================================================
# sessions/session2_siem.sh
# Session 2 — SIEM & Log Monitoring (Elasticsearch + Wazuh — 4 GB optimised)
# Usage: sudo bash sessions/session2_siem.sh
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

require_root
banner "Session 2 — SIEM & Log Monitoring"

ensure_dirs

# ── Make sure Session 1 networks exist ───────────────────────────────────────
if ! network_exists lab-mgmt; then
  warn "lab-mgmt network not found. Running network setup first..."
  bash "$SCRIPT_DIR/sessions/session1_network.sh" || die "Network setup failed."
fi

# ── Kernel tunable required by Elasticsearch ─────────────────────────────────
step "Setting vm.max_map_count for Elasticsearch..."
sysctl -w vm.max_map_count=262144 >/dev/null
ok "vm.max_map_count = 262144"

# ── Deploy Elasticsearch (single-node, low-memory) ───────────────────────────
step "Deploying Elasticsearch (single-node, low-memory mode)..."
remove_container lab-elasticsearch

docker run -d \
  --name lab-elasticsearch \
  --network lab-mgmt \
  --ip "$IP_ELASTIC" \
  --memory="900m" \
  --memory-swap="1200m" \
  --cpus="1.0" \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -e "xpack.ml.enabled=false" \
  -e "ES_JAVA_OPTS=-Xms256m -Xmx512m" \
  -e "cluster.routing.allocation.disk.threshold_enabled=false" \
  -e "bootstrap.memory_lock=false" \
  --restart unless-stopped \
  "$IMG_ELASTIC" \
  && ok "lab-elasticsearch started" \
  || die "Failed to start lab-elasticsearch"

# ── Wait for Elasticsearch ────────────────────────────────────────────────────
step "Waiting for Elasticsearch to be ready (may take 60–90 s)..."
wait_for_url "http://localhost:9200/_cluster/health" 36 5
ok "Elasticsearch is up."

# ── Deploy Kibana ─────────────────────────────────────────────────────────────
step "Deploying Kibana..."
remove_container lab-kibana

mkdir -p "$LAB_BASE/kibana"
cat > "$LAB_BASE/kibana/kibana.yml" <<KEOF
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://$IP_ELASTIC:9200"]
telemetry.enabled: false
telemetry.optIn: false
xpack.reporting.enabled: false
xpack.security.enabled: false
logging.root.level: warn
KEOF

docker run -d \
  --name lab-kibana \
  --network lab-mgmt \
  --ip "$IP_KIBANA" \
  --memory="512m" \
  --memory-swap="768m" \
  --cpus="0.8" \
  -p 5601:5601 \
  -v "$LAB_BASE/kibana/kibana.yml:/usr/share/kibana/config/kibana.yml:ro" \
  -e "ELASTICSEARCH_HOSTS=http://$IP_ELASTIC:9200" \
  --restart unless-stopped \
  "$IMG_KIBANA" \
  && ok "lab-kibana started" \
  || die "Failed to start lab-kibana"

# ── Deploy Wazuh Manager (lightweight standalone) ────────────────────────────
step "Deploying Wazuh Manager..."
remove_container lab-wazuh

mkdir -p "$LAB_BASE/wazuh/"{ossec,logs,queue,var,etc}

docker run -d \
  --name lab-wazuh \
  --network lab-mgmt \
  --ip "$IP_WAZUH" \
  --memory="512m" \
  --memory-swap="768m" \
  --cpus="0.8" \
  -p 55000:55000 \
  -p 1514:1514/udp \
  -p 1515:1515 \
  -e WAZUH_MANAGER=localhost \
  -e WAZUH_REGISTRATION_SERVER=localhost \
  --restart unless-stopped \
  "$IMG_WAZUH" \
  && ok "lab-wazuh started" \
  || { warn "Wazuh Manager image may need to pull; this is normal on first run."; }

# ── Install Wazuh agent on host ───────────────────────────────────────────────
step "Installing Wazuh agent on host VM..."
if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
  # Add Wazuh repo
  curl -sS https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    gpg --dearmor -o /usr/share/keyrings/wazuh-keyring.gpg 2>/dev/null || true
  if [[ -f /usr/share/keyrings/wazuh-keyring.gpg ]]; then
    echo "deb [signed-by=/usr/share/keyrings/wazuh-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq >/dev/null 2>&1
    WAZUH_MANAGER_IP="127.0.0.1" \
      DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent >/dev/null 2>&1 \
      && ok "Wazuh agent installed." \
      || warn "Wazuh agent install skipped — proceeding without host agent."
  else
    warn "Could not add Wazuh repo — host agent skipped."
  fi
else
  ok "Wazuh agent already installed."
fi

# Start agent if installed
if dpkg -s wazuh-agent >/dev/null 2>&1; then
  sed -i "s/<address>.*<\/address>/<address>127.0.0.1<\/address>/" \
    /var/ossec/etc/ossec.conf 2>/dev/null || true
  systemctl enable --now wazuh-agent 2>/dev/null && \
    ok "Wazuh agent started." || warn "Could not start Wazuh agent."
fi

# ── Seed a test log into Elasticsearch ───────────────────────────────────────
step "Seeding test healthcare log event..."
sleep 5  # brief wait for ES
curl -s -X POST "http://localhost:9200/healthcare-logs-$(date +%Y.%m.%d)/_doc" \
  -H 'Content-Type: application/json' \
  -d '{
    "timestamp": "'"$(date -Iseconds)"'",
    "event_type": "login_attempt",
    "user": "jdoe",
    "src_ip": "172.20.10.50",
    "action": "ssh_login",
    "result": "success",
    "segment": "DMZ",
    "hipaa_category": "164.312(d) Authentication"
  }' >/dev/null 2>&1 && ok "Test event seeded into Elasticsearch." || true

curl -s -X POST "http://localhost:9200/healthcare-logs-$(date +%Y.%m.%d)/_doc" \
  -H 'Content-Type: application/json' \
  -d '{
    "timestamp": "'"$(date -Iseconds)"'",
    "event_type": "firewall_block",
    "src_ip": "172.20.10.10",
    "dst_ip": "172.20.20.10",
    "action": "LAB_DROP_DMZ2INT",
    "segment": "DMZ→Internal",
    "hipaa_category": "164.312(a)(1) Technical Access"
  }' >/dev/null 2>&1 || true

# ── Wait for Kibana ───────────────────────────────────────────────────────────
step "Waiting for Kibana UI (may take 60–120 s on first start)..."
wait_for_url "http://localhost:5601/api/status" 48 5 || \
  warn "Kibana not yet ready — check http://localhost:5601 in a minute."

# ── Lab exercises ─────────────────────────────────────────────────────────────
echo ""
banner "Session 2 — Lab Exercises"

echo -e "${BOLD}Exercise 2.1 — Open Kibana SIEM dashboard:${NC}"
echo -e "  Browser: ${CYAN}http://localhost:5601${NC}"
echo -e "  Go to: Discover → Select index 'healthcare-logs-*'"
echo ""

echo -e "${BOLD}Exercise 2.2 — Check Elasticsearch cluster health:${NC}"
echo -e "  ${CYAN}curl http://localhost:9200/_cluster/health?pretty${NC}"
echo ""

echo -e "${BOLD}Exercise 2.3 — List all indices:${NC}"
echo -e "  ${CYAN}curl http://localhost:9200/_cat/indices?v${NC}"
echo ""

echo -e "${BOLD}Exercise 2.4 — Query healthcare logs:${NC}"
echo -e "  ${CYAN}curl http://localhost:9200/healthcare-logs-*/_search?pretty${NC}"
echo ""

echo -e "${BOLD}Exercise 2.5 — Watch Wazuh agent logs (if installed):${NC}"
echo -e "  ${CYAN}sudo tail -f /var/ossec/logs/ossec.log${NC}"
echo ""

echo -e "${BOLD}Exercise 2.6 — Check running SIEM containers:${NC}"
echo -e "  ${CYAN}docker ps --filter name=lab-elastic --filter name=lab-kibana --filter name=lab-wazuh${NC}"
echo ""

# ── Evidence ──────────────────────────────────────────────────────────────────
step "Collecting compliance evidence..."
TS=$(date +%Y%m%d_%H%M%S)
{
  echo "=== Elasticsearch Indices — $TS ==="
  curl -s "http://localhost:9200/_cat/indices?v" 2>/dev/null || echo "(not yet available)"
  echo ""
  echo "=== Cluster Health ==="
  curl -s "http://localhost:9200/_cluster/health?pretty" 2>/dev/null || echo "(not yet available)"
  echo ""
  echo "=== Running SIEM Containers ==="
  docker ps --filter name=lab-elastic --filter name=lab-kibana --filter name=lab-wazuh \
    --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
} > "$EVIDENCE_DIR/elastic_indices_${TS}.txt"
ok "Evidence saved: $EVIDENCE_DIR/elastic_indices_${TS}.txt"

echo ""
ok "Session 2 complete."
echo -e "  Kibana:        ${CYAN}http://localhost:5601${NC}"
echo -e "  Elasticsearch: ${CYAN}http://localhost:9200${NC}"
echo -e "  Wazuh API:     ${CYAN}http://localhost:55000${NC}"
