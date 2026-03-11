#!/usr/bin/env bash
# =============================================================================
# sessions/session1_network.sh
# Session 1 — Network Segmentation (Docker VLANs + Zero-Trust nftables)
# Usage: sudo bash sessions/session1_network.sh
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

require_root
banner "Session 1 — Network Segmentation & Zero-Trust Firewall"

# ── Step 1: Tear down stale networks ─────────────────────────────────────────
step "Cleaning up any stale lab networks..."
for net in lab-dmz lab-internal lab-mgmt; do
  if network_exists "$net"; then
    # Disconnect any stale containers first
    docker network inspect "$net" \
      --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | \
      tr ' ' '\n' | grep -v '^$' | \
      xargs -r -I{} docker network disconnect -f "$net" {} 2>/dev/null || true
    remove_network "$net"
  fi
done

# ── Step 2: Create Docker bridge networks ─────────────────────────────────────
step "Creating Docker bridge networks..."

docker network create \
  --driver bridge \
  --subnet "$NET_DMZ" \
  --gateway "$NET_DMZ_GW" \
  --opt "com.docker.network.bridge.name=br-lab-dmz" \
  lab-dmz \
  && ok "Created: lab-dmz ($NET_DMZ)" \
  || die "Failed to create lab-dmz"

docker network create \
  --driver bridge \
  --subnet "$NET_INT" \
  --gateway "$NET_INT_GW" \
  --opt "com.docker.network.bridge.name=br-lab-int" \
  lab-internal \
  && ok "Created: lab-internal ($NET_INT)" \
  || die "Failed to create lab-internal"

docker network create \
  --driver bridge \
  --subnet "$NET_MGT" \
  --gateway "$NET_MGT_GW" \
  --opt "com.docker.network.bridge.name=br-lab-mgt" \
  lab-mgmt \
  && ok "Created: lab-mgmt ($NET_MGT)" \
  || die "Failed to create lab-mgmt"

# ── Step 3: Enable IP forwarding ──────────────────────────────────────────────
step "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
grep -qx 'net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || \
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
ok "IP forwarding enabled."

# ── Step 4: Apply Zero-Trust nftables ruleset ─────────────────────────────────
apply_nftables

# ── Step 5: Deploy DMZ web server (lightweight test node) ────────────────────
step "Deploying DMZ web server..."
ensure_dirs

cat > "$LAB_BASE/webserver/index.html" <<'HTML'
<!DOCTYPE html>
<html>
<head><title>Hospital Patient Portal</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:40px auto">
  <h1>🏥 St. Digital Hospital</h1>
  <p>Patient Portal — <strong>DEMO ENVIRONMENT</strong></p>
  <p>This simulated DMZ web server is part of the Healthcare Security Lab.</p>
  <ul>
    <li>Network: lab-dmz (172.20.10.0/24)</li>
    <li>IP: 172.20.10.10</li>
    <li>Segment: DMZ (untrusted)</li>
  </ul>
</body>
</html>
HTML

remove_container lab-webserver
docker run -d \
  --name lab-webserver \
  --network lab-dmz \
  --ip "$IP_WEBSERVER" \
  --memory="128m" \
  --cpus="0.5" \
  -p 8080:80 \
  -v "$LAB_BASE/webserver/index.html:/usr/share/nginx/html/index.html:ro" \
  --restart unless-stopped \
  "$IMG_NGINX" \
  && ok "lab-webserver running at http://localhost:8080" \
  || die "Failed to start lab-webserver"

wait_for_container lab-webserver 12 3

# ── Step 6: Lab exercises ─────────────────────────────────────────────────────
echo ""
banner "Session 1 — Lab Exercises"

echo -e "${BOLD}Exercise 1.1 — View firewall rules:${NC}"
echo -e "  ${CYAN}sudo nft list ruleset${NC}"
echo ""

echo -e "${BOLD}Exercise 1.2 — Verify DMZ cannot reach Internal (Zero-Trust):${NC}"
echo -e "  ${CYAN}docker exec lab-webserver ping -c 3 $IP_SAMBA${NC}"
echo -e "  Expected: ${RED}FAIL / 100% packet loss${NC}"
echo ""

echo -e "${BOLD}Exercise 1.3 — Host can reach DMZ (management access):${NC}"
echo -e "  ${CYAN}curl -s http://$IP_WEBSERVER | grep Hospital${NC}"
echo -e "  Expected: ${GREEN}HTML response with 'Hospital'${NC}"
echo ""

echo -e "${BOLD}Exercise 1.4 — Watch firewall drops in real time:${NC}"
echo -e "  ${CYAN}sudo journalctl -kf | grep LAB_DROP${NC}"
echo -e "  Then in another terminal: docker exec lab-webserver ping $IP_SAMBA"
echo ""

echo -e "${BOLD}Exercise 1.5 — Confirm network topology:${NC}"
echo -e "  ${CYAN}docker network ls | grep lab${NC}"
echo -e "  ${CYAN}docker network inspect lab-dmz --format '{{.IPAM.Config}}'${NC}"
echo ""

# ── Evidence collection ───────────────────────────────────────────────────────
step "Collecting compliance evidence..."
TS=$(date +%Y%m%d_%H%M%S)
mkdir -p "$EVIDENCE_DIR"
{
  echo "=== nftables Ruleset — $TS ==="
  nft list ruleset
  echo ""
  echo "=== Docker Networks ==="
  docker network ls | grep lab
  echo ""
  echo "=== DMZ Webserver ==="
  docker inspect lab-webserver --format '{{.NetworkSettings.Networks}}' 2>/dev/null
} > "$EVIDENCE_DIR/nftables_rules_${TS}.txt"
ok "Evidence saved: $EVIDENCE_DIR/nftables_rules_${TS}.txt"

echo ""
ok "Session 1 complete. Networks are up and Zero-Trust rules are active."
echo -e "  DMZ Web Portal: ${CYAN}http://localhost:8080${NC}"
