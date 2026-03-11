#!/usr/bin/env bash
# =============================================================================
# sessions/session6_traffic.sh
# Session 6 — Traffic Analysis (tshark + Wireshark)
# Usage: sudo bash sessions/session6_traffic.sh
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

require_root
banner "Session 6 — Network Traffic Analysis"

ensure_dirs
mkdir -p "$LAB_BASE/captures"

# ── Install tshark ────────────────────────────────────────────────────────────
step "Ensuring tshark is installed..."
if ! command -v tshark >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y tshark >/dev/null 2>&1 \
    && ok "tshark installed." \
    || die "Cannot install tshark."
else
  ok "tshark already installed: $(tshark --version 2>&1 | head -1)"
fi

# Allow tshark for non-root (add user to wireshark group)
if getent group wireshark >/dev/null 2>&1; then
  usermod -aG wireshark "${SUDO_USER:-root}" 2>/dev/null || true
  # Grant dumpcap setuid-like capability
  setcap cap_net_raw,cap_net_admin=eip "$(which tshark)" 2>/dev/null || true
  setcap cap_net_raw,cap_net_admin=eip "$(which dumpcap)" 2>/dev/null || true
fi

# ── Resolve Docker bridge interface names ─────────────────────────────────────
step "Resolving Docker bridge interface names..."

get_bridge_iface() {
  local netname="$1"
  # First try the bridge name we set with com.docker.network.bridge.name
  local custom="br-lab-${2:-}"
  if ip link show "$custom" >/dev/null 2>&1; then
    echo "$custom"; return
  fi
  # Fallback: find via docker network inspect
  local netid
  netid=$(docker network inspect "$netname" --format '{{.Id}}' 2>/dev/null | cut -c1-12)
  if [[ -n "$netid" ]]; then
    echo "br-${netid}"
  else
    echo ""
  fi
}

IFACE_DMZ=$(get_bridge_iface lab-dmz dmz)
IFACE_INT=$(get_bridge_iface lab-internal int)
IFACE_MGT=$(get_bridge_iface lab-mgmt mgt)

echo "  DMZ bridge      : ${IFACE_DMZ:-not found}"
echo "  Internal bridge : ${IFACE_INT:-not found}"
echo "  Mgmt bridge     : ${IFACE_MGT:-not found}"

# ── Generate some lab traffic to capture ──────────────────────────────────────
step "Generating lab traffic for capture exercises..."

# Ping from host to DMZ webserver
if container_running lab-webserver; then
  ping -c 3 -q "$IP_WEBSERVER" >/dev/null 2>&1 && ok "Pinged DMZ webserver." || true
  curl -s "http://$IP_WEBSERVER" >/dev/null 2>&1 && ok "HTTP request to DMZ webserver." || true
fi

# Attempt blocked traffic (DMZ → Internal) to generate firewall drops
if container_running lab-webserver; then
  docker exec lab-webserver ping -c 2 -W 1 "$IP_SAMBA" >/dev/null 2>&1 || \
    info "Generated LAB_DROP_DMZ2INT firewall drop event (expected)."
fi

# ── Create capture command scripts ────────────────────────────────────────────
step "Creating capture command scripts..."

cat > "$LAB_BASE/capture_commands.sh" <<CAPEOF
#!/usr/bin/env bash
# ============================================================
# Healthcare Lab — tshark Capture Commands
# Run any of these to capture specific traffic types.
# Requires: sudo or wireshark group membership
# ============================================================

IFACE_DMZ="${IFACE_DMZ:-br-lab-dmz}"
IFACE_INT="${IFACE_INT:-br-lab-int}"
IFACE_MGT="${IFACE_MGT:-br-lab-mgt}"
CAP_DIR="${LAB_BASE}/captures"

echo "Available capture interfaces:"
echo "  DMZ bridge:      \$IFACE_DMZ"
echo "  Internal bridge: \$IFACE_INT"
echo "  Mgmt bridge:     \$IFACE_MGT"
echo ""
echo "Example capture commands:"
echo ""

echo "# 1. Capture all DMZ traffic (30 seconds):"
echo "   sudo tshark -i \$IFACE_DMZ -a duration:30 -w \$CAP_DIR/dmz_traffic.pcap"
echo ""

echo "# 2. Capture HTTP on DMZ:"
echo "   sudo tshark -i \$IFACE_DMZ -f 'tcp port 80'"
echo ""

echo "# 3. Watch firewall drops in real time:"
echo "   sudo journalctl -kf | grep 'LAB_DROP'"
echo ""

echo "# 4. Capture RADIUS authentication:"
echo "   sudo tshark -i \$IFACE_INT -f 'udp port 1812'"
echo ""

echo "# 5. Capture LDAP traffic:"
echo "   sudo tshark -i \$IFACE_INT -f 'tcp port 389'"
echo ""

echo "# 6. Capture Elasticsearch queries:"
echo "   sudo tshark -i \$IFACE_MGT -f 'tcp port 9200'"
echo ""

echo "# 7. Live traffic summary on all lab interfaces:"
echo "   sudo tshark -i \$IFACE_DMZ -i \$IFACE_INT -i \$IFACE_MGT -q -z io,stat,5"
echo ""

echo "# 8. Export to readable text:"
echo "   sudo tshark -r \$CAP_DIR/dmz_traffic.pcap -T fields -e ip.src -e ip.dst -e frame.protocols"
echo ""

echo "# 9. Filter for denied packets (check nft log):"
echo "   sudo dmesg | grep 'LAB_DROP'"
echo ""

echo "# 10. Open pcap in Wireshark (GUI):"
echo "   wireshark \$CAP_DIR/dmz_traffic.pcap &"
CAPEOF

chmod +x "$LAB_BASE/capture_commands.sh"
ok "Capture commands script: $LAB_BASE/capture_commands.sh"

# ── Do a live 10-second capture (non-blocking evidence) ──────────────────────
step "Performing 10-second traffic capture for evidence..."

PCAP_FILE="$LAB_BASE/captures/lab_traffic_$(date +%Y%m%d_%H%M%S).pcap"

# Capture on whichever interface is available
CAPTURE_IFACE=""
for iface in "$IFACE_DMZ" "$IFACE_INT" "$IFACE_MGT" "any"; do
  if [[ -n "$iface" ]] && ip link show "$iface" >/dev/null 2>&1; then
    CAPTURE_IFACE="$iface"
    break
  fi
done

if [[ -n "$CAPTURE_IFACE" ]]; then
  info "Capturing on interface: $CAPTURE_IFACE for 10 seconds..."
  timeout 12 tshark -i "$CAPTURE_IFACE" -a duration:10 -w "$PCAP_FILE" >/dev/null 2>&1 || true
  if [[ -f "$PCAP_FILE" ]] && [[ -s "$PCAP_FILE" ]]; then
    PKT_COUNT=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l || echo "0")
    ok "Captured $PKT_COUNT packets → $PCAP_FILE"
  else
    warn "Capture file empty — may need traffic or interface not ready."
  fi
else
  warn "No lab bridge interfaces found yet — run Session 1 first."
fi

# ── Lab exercises ─────────────────────────────────────────────────────────────
echo ""
banner "Session 6 — Lab Exercises"

echo -e "${BOLD}Exercise 6.1 — Show all available capture commands:${NC}"
echo -e "  ${CYAN}bash $LAB_BASE/capture_commands.sh${NC}"
echo ""

echo -e "${BOLD}Exercise 6.2 — Live watch firewall drop events:${NC}"
echo -e "  ${CYAN}sudo journalctl -kf | grep LAB_DROP${NC}"
echo -e "  Then in another terminal: ${CYAN}docker exec lab-webserver ping $IP_SAMBA${NC}"
echo ""

echo -e "${BOLD}Exercise 6.3 — Capture HTTP traffic to DMZ:${NC}"
DISP_DMZ="${IFACE_DMZ:-br-lab-dmz}"
echo -e "  ${CYAN}sudo tshark -i $DISP_DMZ -f 'tcp port 80' -a duration:30${NC}"
echo ""

echo -e "${BOLD}Exercise 6.4 — Generate and capture RADIUS auth:${NC}"
DISP_INT="${IFACE_INT:-br-lab-int}"
echo -e "  Terminal 1: ${CYAN}sudo tshark -i $DISP_INT -f 'udp port 1812'${NC}"
echo -e "  Terminal 2: ${CYAN}radtest jdoe 'Doctor@2024!' 127.0.0.1 0 '${RADIUS_SECRET}'${NC}"
echo ""

echo -e "${BOLD}Exercise 6.5 — Capture and display packet fields:${NC}"
echo -e "  ${CYAN}sudo tshark -i $DISP_DMZ -T fields -e ip.src -e ip.dst -e tcp.dstport -a duration:15${NC}"
echo ""

echo -e "${BOLD}Exercise 6.6 — Check nftables drop log:${NC}"
echo -e "  ${CYAN}sudo dmesg | grep LAB_DROP | tail -20${NC}"
echo ""

echo -e "${BOLD}Exercise 6.7 — View captured pcap:${NC}"
if [[ -f "$PCAP_FILE" ]]; then
  echo -e "  ${CYAN}tshark -r $PCAP_FILE${NC}"
fi
echo ""

# ── Evidence ──────────────────────────────────────────────────────────────────
step "Collecting compliance evidence..."
TS=$(date +%Y%m%d_%H%M%S)
{
  echo "=== Traffic Analysis Evidence — $TS ==="
  echo ""
  echo "=== Lab Network Interfaces ==="
  ip link show | grep -E 'br-lab|br-[0-9a-f]{12}' | awk '{print $2}' || echo "none found"
  echo ""
  echo "=== Active nftables Drop Rules ==="
  nft list ruleset 2>/dev/null | grep -A2 'LAB_DROP' || echo "(none)"
  echo ""
  echo "=== Recent Firewall Drops ==="
  dmesg 2>/dev/null | grep 'LAB_DROP' | tail -20 || echo "(none yet)"
  echo ""
  echo "=== tshark Version ==="
  tshark --version 2>&1 | head -2
  echo ""
  echo "=== Captured Files ==="
  ls -lh "$LAB_BASE/captures/" 2>/dev/null || echo "none"
} > "$EVIDENCE_DIR/traffic_analysis_${TS}.txt"
ok "Evidence saved: $EVIDENCE_DIR/traffic_analysis_${TS}.txt"

echo ""
ok "Session 6 complete."
echo -e "  Capture scripts: ${CYAN}bash $LAB_BASE/capture_commands.sh${NC}"
echo -e "  Capture dir:     ${CYAN}$LAB_BASE/captures/${NC}"
