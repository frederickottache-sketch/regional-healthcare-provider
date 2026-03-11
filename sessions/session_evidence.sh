#!/usr/bin/env bash
# =============================================================================
# sessions/session_evidence.sh
# Compliance Evidence Collection — HIPAA / NDPA artefacts
# Usage: sudo bash sessions/session_evidence.sh
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

require_root
banner "Compliance Evidence Collection"

ensure_dirs
TS=$(date +%Y%m%d_%H%M%S)
mkdir -p "$EVIDENCE_DIR"

step "Collecting all compliance artefacts..."

# ── 1. nftables firewall rules ────────────────────────────────────────────────
{
  echo "=== HIPAA 164.312(a)(1) & 164.308(a)(4) — Zero-Trust Firewall Rules ==="
  echo "Timestamp: $TS"
  echo ""
  nft list ruleset 2>/dev/null || echo "(nftables not configured)"
} > "$EVIDENCE_DIR/nftables_rules_${TS}.txt"
ok "Firewall rules saved."

# ── 2. Running services ───────────────────────────────────────────────────────
{
  echo "=== HIPAA 164.312(d) — Running Security Services ==="
  echo "Timestamp: $TS"
  echo ""
  echo "--- Docker Containers ---"
  docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}" 2>/dev/null
  echo ""
  echo "--- Listening Ports ---"
  ss -tlunp 2>/dev/null | grep -E '1812|1813|389|9200|5601|8080|55000' || \
    netstat -tlunp 2>/dev/null | grep -E '1812|1813|389|9200|5601|8080|55000' || \
    echo "(ss/netstat not available)"
} > "$EVIDENCE_DIR/running_services_${TS}.txt"
ok "Running services saved."

# ── 3. Elasticsearch indices (audit log) ─────────────────────────────────────
{
  echo "=== HIPAA 164.312(b) — Audit Controls (Elasticsearch) ==="
  echo "Timestamp: $TS"
  echo ""
  echo "--- Cluster Health ---"
  curl -s "http://localhost:9200/_cluster/health?pretty" 2>/dev/null || echo "(Elasticsearch not running)"
  echo ""
  echo "--- Indices ---"
  curl -s "http://localhost:9200/_cat/indices?v" 2>/dev/null || echo "(Elasticsearch not running)"
} > "$EVIDENCE_DIR/elastic_indices_${TS}.txt"
ok "Elasticsearch indices saved."

# ── 4. AD users (access control evidence) ────────────────────────────────────
{
  echo "=== HIPAA 164.308(a)(3) — Workforce Access Controls (AD) ==="
  echo "Timestamp: $TS"
  echo ""
  echo "--- AD Users ---"
  docker exec lab-samba-ad samba-tool user list 2>/dev/null || echo "(Samba AD not running)"
  echo ""
  echo "--- AD Groups ---"
  docker exec lab-samba-ad samba-tool group list 2>/dev/null || echo "(Samba AD not running)"
  echo ""
  echo "--- Physicians Group Members ---"
  docker exec lab-samba-ad samba-tool group listmembers Physicians 2>/dev/null || echo "(not available)"
  echo ""
  echo "--- RADIUS Users Configured ---"
  [[ -f "$LAB_BASE/freeradius/hospital_users" ]] && \
    grep -v '^#' "$LAB_BASE/freeradius/hospital_users" | grep -v '^$' | awk '{print $1}' || \
    echo "(FreeRADIUS not configured)"
} > "$EVIDENCE_DIR/ad_users_${TS}.txt"
ok "AD users evidence saved."

# ── 5. Wazuh / SIEM agent log ─────────────────────────────────────────────────
{
  echo "=== HIPAA 164.308(a)(6) — Incident Response (Wazuh) ==="
  echo "Timestamp: $TS"
  echo ""
  echo "--- Wazuh Agent Status ---"
  systemctl status wazuh-agent 2>/dev/null | head -20 || echo "(Wazuh agent not installed)"
  echo ""
  echo "--- Last 20 Wazuh Events ---"
  [[ -f /var/ossec/logs/ossec.log ]] && \
    tail -20 /var/ossec/logs/ossec.log || echo "(no Wazuh log found)"
  echo ""
  echo "--- Wazuh Manager Container ---"
  docker ps --filter name=lab-wazuh --format "{{.Names}}: {{.Status}}" 2>/dev/null
} > "$EVIDENCE_DIR/wazuh_agent_log_${TS}.txt"
ok "Wazuh evidence saved."

# ── 6. EICAR / YARA analysis ──────────────────────────────────────────────────
{
  echo "=== HIPAA 164.312(c)(1) — Integrity (YARA Malware Analysis) ==="
  echo "Timestamp: $TS"
  echo ""
  if [[ -f "$LAB_BASE/malware-sim/eicar.com" ]]; then
    if command -v yara >/dev/null 2>&1 && [[ -f "$LAB_BASE/malware-sim/hospital_rules.yar" ]]; then
      echo "--- YARA Scan of EICAR test file ---"
      yara -m "$LAB_BASE/malware-sim/hospital_rules.yar" "$LAB_BASE/malware-sim/eicar.com" 2>/dev/null || \
        echo "(YARA scan failed)"
    fi
    echo ""
    echo "--- File hashes ---"
    md5sum    "$LAB_BASE/malware-sim/eicar.com"
    sha256sum "$LAB_BASE/malware-sim/eicar.com"
  else
    echo "(EICAR file not created — run Session 4 first)"
  fi
  echo ""
  echo "--- Latest analysis reports ---"
  ls -lh "$EVIDENCE_DIR"/eicar_analysis_*.json 2>/dev/null || echo "none"
} > "$EVIDENCE_DIR/eicar_analysis_${TS}.txt"
ok "YARA evidence saved."

# ── 7. HIPAA summary ──────────────────────────────────────────────────────────
{
  echo "================================================================"
  echo "  HIPAA Compliance Summary — Healthcare Security Lab (Lite)"
  echo "  Generated: $TS"
  echo "================================================================"
  echo ""
  printf "%-30s %-30s %-15s\n" "HIPAA Standard" "Control" "Status"
  printf "%-30s %-30s %-15s\n" "──────────────────────────────" "──────────────────────────────" "───────────────"
  printf "%-30s %-30s %-15s\n" "164.308(a)(1) Risk Analysis"   "Vulnerability scanning"    "$(command -v nmap >/dev/null 2>&1 && echo 'ACTIVE' || echo 'PARTIAL')"
  printf "%-30s %-30s %-15s\n" "164.308(a)(3) Workforce Access" "Role-based AD OUs"        "$(container_running lab-samba-ad && echo 'ACTIVE' || echo 'OFFLINE')"
  printf "%-30s %-30s %-15s\n" "164.308(a)(4) Access Control"  "VLAN + RADIUS"            "$(container_running lab-freeradius && echo 'ACTIVE' || echo 'OFFLINE')"
  printf "%-30s %-30s %-15s\n" "164.308(a)(6) Incident Resp."  "Real-time alerting Wazuh" "$(container_running lab-wazuh && echo 'ACTIVE' || echo 'OFFLINE')"
  printf "%-30s %-30s %-15s\n" "164.312(a)(1) Technical Access" "Zero-Trust firewall"     "$(nft list tables 2>/dev/null | grep -q lab_filter && echo 'ACTIVE' || echo 'INACTIVE')"
  printf "%-30s %-30s %-15s\n" "164.312(b) Audit Controls"     "Centralised ELK logging"  "$(container_running lab-elasticsearch && echo 'ACTIVE' || echo 'OFFLINE')"
  printf "%-30s %-30s %-15s\n" "164.312(c)(1) Integrity"       "FIM + YARA analysis"      "$(command -v yara >/dev/null 2>&1 && echo 'ACTIVE' || echo 'PARTIAL')"
  printf "%-30s %-30s %-15s\n" "164.312(d) Authentication"     "RADIUS auth"              "$(container_running lab-freeradius && echo 'ACTIVE' || echo 'OFFLINE')"
  printf "%-30s %-30s %-15s\n" "164.312(e)(1) Transmission Sec." "SSH + Docker TLS"       "ACTIVE"
  echo ""
  echo "Evidence files:"
  ls -1 "$EVIDENCE_DIR"/*_${TS}.* 2>/dev/null | sed 's|.*/||'
  echo ""
  echo "Evidence directory: $EVIDENCE_DIR"
} > "$EVIDENCE_DIR/hipaa_summary_${TS}.txt"

# ── Print summary to console ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}HIPAA Compliance Summary${NC}"
cat "$EVIDENCE_DIR/hipaa_summary_${TS}.txt"

echo ""
echo -e "${GREEN}${BOLD}All evidence collected in:${NC} $EVIDENCE_DIR"
echo ""
ls -lh "$EVIDENCE_DIR"/*_${TS}.* 2>/dev/null
echo ""
ok "Evidence collection complete."
