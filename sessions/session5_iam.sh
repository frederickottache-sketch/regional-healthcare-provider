#!/usr/bin/env bash
# =============================================================================
# sessions/session5_iam.sh
# Session 5 — IAM & RADIUS Authentication (Samba AD + FreeRADIUS)
# Usage: sudo bash sessions/session5_iam.sh
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

require_root
banner "Session 5 — Identity & Access Management (Samba AD + FreeRADIUS)"

ensure_dirs

# ── Ensure lab-internal network ───────────────────────────────────────────────
if ! network_exists lab-internal; then
  warn "lab-internal not found — running network setup first..."
  bash "$SCRIPT_DIR/sessions/session1_network.sh" || die "Network setup failed."
fi

# ── FreeRADIUS users file ─────────────────────────────────────────────────────
step "Creating FreeRADIUS hospital users..."
mkdir -p "$LAB_BASE/freeradius"

cat > "$LAB_BASE/freeradius/hospital_users" <<USERSEOF
# FreeRADIUS users file — Healthcare Lab
# Format: username  Cleartext-Password := "password"
#         Reply-Message = "Access granted to <role>"

jdoe        Cleartext-Password := "Doctor@2024!"
            Reply-Message = "Access granted: Physician - Ward A"

msmith      Cleartext-Password := "Nurse@2024!"
            Reply-Message = "Access granted: Nurse - ICU"

bwhite      Cleartext-Password := "Radiol@gy2024!"
            Reply-Message = "Access granted: Radiologist"

admin       Cleartext-Password := "Admin@2024!"
            Reply-Message = "Access granted: IT Administrator"

labtech     Cleartext-Password := "L@bTech2024!"
            Reply-Message = "Access granted: Lab Technician"
USERSEOF

# FreeRADIUS clients.conf for lab
cat > "$LAB_BASE/freeradius/clients.conf" <<CLIENTSEOF
# FreeRADIUS clients — Healthcare Lab
client localhost {
    ipaddr  = 127.0.0.1
    secret  = ${RADIUS_SECRET}
    shortname = localhost
}
client lab-internal {
    ipaddr  = 172.20.20.0/24
    secret  = ${RADIUS_SECRET}
    shortname = lab-internal
}
client lab-mgmt {
    ipaddr  = 172.20.30.0/24
    secret  = ${RADIUS_SECRET}
    shortname = lab-mgmt
}
CLIENTSEOF
ok "FreeRADIUS config created."

# ── Deploy FreeRADIUS ─────────────────────────────────────────────────────────
step "Deploying FreeRADIUS container..."
remove_container lab-freeradius

docker run -d \
  --name lab-freeradius \
  --network lab-internal \
  --ip "$IP_RADIUS" \
  --memory="128m" \
  --cpus="0.5" \
  -p 1812:1812/udp \
  -p 1813:1813/udp \
  -e TZ=UTC \
  -v "$LAB_BASE/freeradius/hospital_users:/etc/raddb/users:ro" \
  -v "$LAB_BASE/freeradius/clients.conf:/etc/raddb/clients.conf:ro" \
  --restart unless-stopped \
  "$IMG_RADIUS" \
  && ok "lab-freeradius started" \
  || die "Failed to start FreeRADIUS"

wait_for_container lab-freeradius 15 3

# ── Deploy Samba AD ───────────────────────────────────────────────────────────
step "Deploying Samba AD Domain Controller..."
remove_container lab-samba-ad

mkdir -p "$LAB_DATA/samba"

docker run -d \
  --name lab-samba-ad \
  --network lab-internal \
  --ip "$IP_SAMBA" \
  --memory="512m" \
  --memory-swap="768m" \
  --cpus="1.0" \
  -p 389:389 \
  -p 636:636 \
  -p 445:445 \
  -e DOMAIN="$AD_DOMAIN" \
  -e DOMAINPASS="$AD_ADMINPASS" \
  -e DNSFORWARDER="8.8.8.8" \
  -e HOSTIP="$IP_SAMBA" \
  -v "$LAB_DATA/samba:/var/lib/samba" \
  --restart unless-stopped \
  "$IMG_SAMBA" \
  && ok "lab-samba-ad started" \
  || { warn "Samba AD may need longer to start — check: docker logs lab-samba-ad"; }

# ── Wait for Samba to be available ────────────────────────────────────────────
step "Waiting for Samba AD to initialise (30–60 s)..."
sleep 15
i=0
while ! docker exec lab-samba-ad samba-tool domain info "$AD_DOMAIN" >/dev/null 2>&1; do
  ((i++)); [[ $i -gt 20 ]] && { warn "Samba AD not ready after 60 s — continuing."; break; }
  echo -n "."; sleep 3
done
echo ""

# ── Create AD OUs and users ───────────────────────────────────────────────────
step "Provisioning AD organisational units and users..."

# Helper: run samba-tool safely (ignore errors from duplicates)
samba_cmd() {
  docker exec lab-samba-ad samba-tool "$@" 2>/dev/null || true
}

# Create OUs
samba_cmd ou create "OU=Medical,DC=${AD_DOMAIN//.*/},DC=${AD_DOMAIN#*.}" || true
samba_cmd ou create "OU=Physicians,OU=Medical,DC=${AD_DOMAIN//.*/},DC=${AD_DOMAIN#*.}" || true
samba_cmd ou create "OU=Nurses,OU=Medical,DC=${AD_DOMAIN//.*/},DC=${AD_DOMAIN#*.}" || true
samba_cmd ou create "OU=ITAdmin,DC=${AD_DOMAIN//.*/},DC=${AD_DOMAIN#*.}" || true

# Create users (matching RADIUS users for integration exercise)
create_ad_user() {
  local user="$1" pass="$2" ou="$3"
  samba_cmd user create "$user" "$pass" --use-username-as-cn 2>/dev/null || true
  ok "AD user: $user"
}

create_ad_user "jdoe"    "Doctor@2024!"  "Physicians"
create_ad_user "msmith"  "Nurse@2024!"   "Nurses"
create_ad_user "bwhite"  "Radiol@gy2024!" "Physicians"
create_ad_user "labtech" "L@bTech2024!"  "Medical"

# Create groups
samba_cmd group add "Physicians" 2>/dev/null || true
samba_cmd group add "Nurses"     2>/dev/null || true
samba_cmd group add "ITAdmins"   2>/dev/null || true
samba_cmd group addmembers "Physicians" "jdoe,bwhite" 2>/dev/null || true
samba_cmd group addmembers "Nurses"     "msmith"      2>/dev/null || true

ok "AD users and groups provisioned."

# ── Install RADIUS test client ────────────────────────────────────────────────
step "Installing RADIUS test utilities..."
install_if_missing freeradius-utils || true

# ── Wait for FreeRADIUS UDP to be listening ───────────────────────────────────
step "Testing RADIUS authentication..."
sleep 5  # Allow FreeRADIUS to fully start

if command -v radtest >/dev/null 2>&1; then
  # Test with jdoe
  RESULT=$(radtest "jdoe" "Doctor@2024!" 127.0.0.1 0 "${RADIUS_SECRET}" 2>&1 || true)
  if echo "$RESULT" | grep -q "Access-Accept"; then
    ok "RADIUS auth test PASSED: jdoe → Access-Accept"
  elif echo "$RESULT" | grep -q "Access-Reject"; then
    warn "RADIUS test returned Access-Reject (check users file permissions)"
  else
    warn "RADIUS test inconclusive — FreeRADIUS may still be starting."
    info "Retry with: radtest jdoe 'Doctor@2024!' 127.0.0.1 0 '${RADIUS_SECRET}'"
  fi
else
  warn "radtest not installed — install with: apt install freeradius-utils"
fi

# ── Lab exercises ─────────────────────────────────────────────────────────────
echo ""
banner "Session 5 — Lab Exercises"

echo -e "${BOLD}Exercise 5.1 — Test RADIUS authentication:${NC}"
echo -e "  ${CYAN}radtest jdoe 'Doctor@2024!' 127.0.0.1 0 '${RADIUS_SECRET}'${NC}"
echo -e "  Expected: ${GREEN}Access-Accept${NC}"
echo ""

echo -e "${BOLD}Exercise 5.2 — Test RADIUS rejection (wrong password):${NC}"
echo -e "  ${CYAN}radtest jdoe 'WrongPassword' 127.0.0.1 0 '${RADIUS_SECRET}'${NC}"
echo -e "  Expected: ${RED}Access-Reject${NC}"
echo ""

echo -e "${BOLD}Exercise 5.3 — List all AD users:${NC}"
echo -e "  ${CYAN}docker exec lab-samba-ad samba-tool user list${NC}"
echo ""

echo -e "${BOLD}Exercise 5.4 — List AD OUs:${NC}"
echo -e "  ${CYAN}docker exec lab-samba-ad samba-tool ou list${NC}"
echo ""

echo -e "${BOLD}Exercise 5.5 — Query AD group membership:${NC}"
echo -e "  ${CYAN}docker exec lab-samba-ad samba-tool group listmembers Physicians${NC}"
echo ""

echo -e "${BOLD}Exercise 5.6 — LDAP query (requires ldap-utils):${NC}"
echo -e "  ${CYAN}apt install ldap-utils -y${NC}"
echo -e "  ${CYAN}ldapsearch -x -H ldap://127.0.0.1 -D 'Administrator@$AD_DOMAIN' -w '$AD_ADMINPASS' -b 'DC=${AD_DOMAIN//.*/},DC=${AD_DOMAIN#*.}' '(objectClass=user)' cn${NC}"
echo ""

echo -e "${BOLD}Exercise 5.7 — Test all RADIUS users:${NC}"
for user_pw in "jdoe:Doctor@2024!" "msmith:Nurse@2024!" "bwhite:Radiol@gy2024!" "admin:Admin@2024!"; do
  u="${user_pw%%:*}"; p="${user_pw##*:}"
  echo -e "  ${CYAN}radtest $u '$p' 127.0.0.1 0 '${RADIUS_SECRET}'${NC}"
done
echo ""

# ── Evidence ──────────────────────────────────────────────────────────────────
step "Collecting compliance evidence..."
TS=$(date +%Y%m%d_%H%M%S)
{
  echo "=== AD Users — $TS ==="
  docker exec lab-samba-ad samba-tool user list 2>/dev/null || echo "(Samba not ready)"
  echo ""
  echo "=== AD Groups ==="
  docker exec lab-samba-ad samba-tool group list 2>/dev/null || echo "(Samba not ready)"
  echo ""
  echo "=== RADIUS Users Configured ==="
  cat "$LAB_BASE/freeradius/hospital_users" | grep -v '^#' | grep -v '^$' | awk -F' ' '{print $1}'
  echo ""
  echo "=== IAM Containers ==="
  docker ps --filter name=lab-samba --filter name=lab-freeradius \
    --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
} > "$EVIDENCE_DIR/ad_users_${TS}.txt"
ok "Evidence saved: $EVIDENCE_DIR/ad_users_${TS}.txt"

echo ""
ok "Session 5 complete."
echo -e "  Samba AD LDAP: ${CYAN}ldap://localhost:389${NC}"
echo -e "  RADIUS:        ${CYAN}localhost:1812/udp${NC} (secret: ${RADIUS_SECRET})"
