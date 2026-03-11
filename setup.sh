#!/usr/bin/env bash
# =============================================================================
# setup.sh — Healthcare Security Lab (Lite) — Main Entry Point
# Single-VM · Docker-Based · HIPAA & NDPA Simulation
# Optimised for 4 GB RAM / 25 GB disk
#
# Usage:
#   sudo bash setup.sh all         # Full setup (all modules)
#   sudo bash setup.sh preflight   # Check & install dependencies only
#   sudo bash setup.sh network     # Module 1 — Networks + nftables
#   sudo bash setup.sh siem        # Module 2 — ELK + Wazuh
#   sudo bash setup.sh scanner     # Module 3 — Vulnerability scanner
#   sudo bash setup.sh malware     # Module 4 — YARA malware analysis
#   sudo bash setup.sh iam         # Module 5 — Samba AD + FreeRADIUS
#   sudo bash setup.sh traffic     # Module 6 — tshark capture
#   sudo bash setup.sh evidence    # Collect compliance artefacts
#   sudo bash setup.sh status      # Show running services
#   sudo bash setup.sh down        # Stop and remove all containers
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

require_root

# ── Print usage ───────────────────────────────────────────────────────────────
usage() {
  echo -e "${BOLD}Healthcare Security Lab — Lite Edition${NC}"
  echo ""
  echo "Usage: sudo bash setup.sh <command>"
  echo ""
  echo "Commands:"
  echo "  all        — Full deployment (all modules)"
  echo "  preflight  — Install dependencies only"
  echo "  network    — Session 1: Docker networks + nftables"
  echo "  siem       — Session 2: ELK Stack + Wazuh"
  echo "  scanner    — Session 3: Vulnerability scanning"
  echo "  malware    — Session 4: YARA malware analysis"
  echo "  iam        — Session 5: Samba AD + FreeRADIUS"
  echo "  traffic    — Session 6: tshark captures"
  echo "  evidence   — Collect compliance artefacts"
  echo "  status     — Show all running services"
  echo "  down       — Stop and remove all containers"
  echo ""
  exit 0
}

# ── Status report ─────────────────────────────────────────────────────────────
show_status() {
  banner "Healthcare Lab — Service Status"

  echo -e "${BOLD}Docker Containers:${NC}"
  docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" \
    --filter name=lab- 2>/dev/null || echo "  (none running)"
  echo ""

  echo -e "${BOLD}Network Segments:${NC}"
  docker network ls --filter name=lab- --format "  {{.Name}}\t{{.Driver}}" 2>/dev/null
  echo ""

  echo -e "${BOLD}Firewall:${NC}"
  if nft list tables 2>/dev/null | grep -q lab_filter; then
    echo -e "  ${GREEN}nftables lab_filter active${NC}"
  else
    echo -e "  ${YELLOW}nftables lab_filter not loaded${NC}"
  fi
  echo ""

  echo -e "${BOLD}Service URLs:${NC}"
  check_url() {
    local label="$1" url="$2"
    if curl -sk --max-time 2 "$url" >/dev/null 2>&1; then
      echo -e "  ${GREEN}✓${NC} $label — $url"
    else
      echo -e "  ${YELLOW}✗${NC} $label — $url  (not responding)"
    fi
  }
  check_url "Kibana (SIEM)"      "http://localhost:5601"
  check_url "Elasticsearch"      "http://localhost:9200"
  check_url "DMZ Web Portal"     "http://localhost:8080"
  check_url "Wazuh Manager"      "http://localhost:55000"
  check_url "OpenVAS (if used)"  "https://localhost:9392"
  echo ""

  echo -e "${BOLD}Memory Usage:${NC}"
  docker stats --no-stream --format "  {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}" \
    $(docker ps --filter name=lab- -q 2>/dev/null) 2>/dev/null || echo "  (no containers)"
  echo ""

  echo -e "${BOLD}Evidence Files:${NC}"
  if [[ -d "$EVIDENCE_DIR" ]]; then
    ls -lh "$EVIDENCE_DIR/"*.txt "$EVIDENCE_DIR/"*.json 2>/dev/null | \
      awk '{print "  " $NF " (" $5 ")"}' || echo "  (none collected yet)"
  else
    echo "  (evidence dir not created yet)"
  fi
}

# ── Teardown ──────────────────────────────────────────────────────────────────
do_down() {
  banner "Tearing Down Healthcare Lab"

  step "Stopping and removing containers..."
  for cname in lab-webserver lab-elasticsearch lab-kibana lab-wazuh \
                lab-openvas lab-samba-ad lab-freeradius; do
    remove_container "$cname"
  done

  step "Removing networks..."
  for net in lab-dmz lab-internal lab-mgmt; do
    remove_network "$net"
  done

  step "Flushing nftables lab rules..."
  nft delete table inet lab_filter 2>/dev/null && \
    ok "nftables lab_filter removed." || info "nftables lab_filter was not loaded."

  ok "Lab torn down. Docker volumes and data preserved."
  echo -e "  For full clean: ${CYAN}sudo docker volume prune -f${NC}"
}

# ── Main dispatcher ───────────────────────────────────────────────────────────
CMD="${1:-help}"

case "$CMD" in
  help|--help|-h)
    usage
    ;;

  preflight)
    bash "$SCRIPT_DIR/preflight.sh"
    ;;

  network)
    bash "$SCRIPT_DIR/preflight.sh"
    bash "$SCRIPT_DIR/sessions/session1_network.sh"
    ;;

  siem)
    bash "$SCRIPT_DIR/sessions/session2_siem.sh"
    ;;

  scanner)
    bash "$SCRIPT_DIR/sessions/session3_scanner.sh"
    ;;

  malware)
    bash "$SCRIPT_DIR/sessions/session4_malware.sh"
    ;;

  iam)
    bash "$SCRIPT_DIR/sessions/session5_iam.sh"
    ;;

  traffic)
    bash "$SCRIPT_DIR/sessions/session6_traffic.sh"
    ;;

  evidence)
    bash "$SCRIPT_DIR/sessions/session_evidence.sh"
    ;;

  status)
    show_status
    ;;

  down)
    do_down
    ;;

  all)
    banner "Full Healthcare Lab Deployment"
    echo -e "  RAM optimised for ${BOLD}4 GB${NC}, storage for ${BOLD}25 GB${NC}"
    echo ""

    # Preflight
    bash "$SCRIPT_DIR/preflight.sh"

    # Session 1 — Networks
    echo ""
    step "=== MODULE 1: Network Segmentation ==="
    bash "$SCRIPT_DIR/sessions/session1_network.sh"

    # Session 2 — SIEM (heaviest — deploy early)
    echo ""
    step "=== MODULE 2: SIEM & Log Monitoring ==="
    bash "$SCRIPT_DIR/sessions/session2_siem.sh"

    # Session 4 — Malware (no containers, fast)
    echo ""
    step "=== MODULE 4: Static Malware Analysis ==="
    bash "$SCRIPT_DIR/sessions/session4_malware.sh"

    # Session 5 — IAM
    echo ""
    step "=== MODULE 5: IAM & RADIUS ==="
    bash "$SCRIPT_DIR/sessions/session5_iam.sh"

    # Session 3 — Scanner (RAM-aware)
    echo ""
    step "=== MODULE 3: Vulnerability Scanning ==="
    bash "$SCRIPT_DIR/sessions/session3_scanner.sh"

    # Session 6 — Traffic
    echo ""
    step "=== MODULE 6: Traffic Analysis ==="
    bash "$SCRIPT_DIR/sessions/session6_traffic.sh"

    # Evidence
    echo ""
    step "=== EVIDENCE: Collecting Compliance Artefacts ==="
    bash "$SCRIPT_DIR/sessions/session_evidence.sh"

    # Final status
    echo ""
    show_status

    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  Healthcare Security Lab is READY                    ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Service URLs:${NC}"
    echo -e "    Kibana (SIEM)    : ${CYAN}http://localhost:5601${NC}"
    echo -e "    Elasticsearch    : ${CYAN}http://localhost:9200${NC}"
    echo -e "    DMZ Web Portal   : ${CYAN}http://localhost:8080${NC}"
    echo -e "    Wazuh API        : ${CYAN}http://localhost:55000${NC}"
    echo ""
    echo -e "  ${BOLD}Run individual sessions:${NC}"
    echo -e "    ${CYAN}sudo bash sessions/session1_network.sh${NC}"
    echo -e "    ${CYAN}sudo bash sessions/session2_siem.sh${NC}"
    echo -e "    ${CYAN}sudo bash sessions/session3_scanner.sh${NC}"
    echo -e "    ${CYAN}sudo bash sessions/session4_malware.sh${NC}"
    echo -e "    ${CYAN}sudo bash sessions/session5_iam.sh${NC}"
    echo -e "    ${CYAN}sudo bash sessions/session6_traffic.sh${NC}"
    echo ""
    echo -e "  ${BOLD}Evidence:${NC} ${CYAN}$EVIDENCE_DIR${NC}"
    echo ""
    ;;

  *)
    err "Unknown command: $CMD"
    usage
    ;;
esac
