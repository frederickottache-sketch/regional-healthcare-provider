#!/usr/bin/env bash
# =============================================================================
# lib/common.sh — Shared utilities for Healthcare Security Lab (Lite)
# Sourced by all session scripts and setup.sh
# =============================================================================

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[1;34m'; BOLD='\033[1m'; NC='\033[0m'

# ── Logging helpers ───────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
step()    { echo -e "${BLUE}[STEP]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERR ]${NC}  $*" >&2; }
die()     { err "$*"; exit 1; }
banner()  {
  echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${BLUE}  $*${NC}"
  echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════${NC}\n"
}

# ── Root guard ────────────────────────────────────────────────────────────────
require_root() {
  [[ $EUID -eq 0 ]] || die "This script must be run as root.  Try: sudo $0 $*"
}

# ── Variable defaults (can be overridden by exporting before running) ─────────
export LAB_BASE="${LAB_BASE:-/opt/healthcare-lab}"
export LAB_DATA="${LAB_DATA:-/opt/healthcare-lab/data}"
export EVIDENCE_DIR="${EVIDENCE_DIR:-$HOME/compliance_evidence}"
export COMPOSE_DIR="${COMPOSE_DIR:-/opt/healthcare-lab/compose}"

# Network CIDRs
export NET_DMZ="172.20.10.0/24"
export NET_INT="172.20.20.0/24"
export NET_MGT="172.20.30.0/24"
export NET_DMZ_GW="172.20.10.1"
export NET_INT_GW="172.20.20.1"
export NET_MGT_GW="172.20.30.1"

# Container IPs
export IP_WEBSERVER="172.20.10.10"
export IP_SAMBA="172.20.20.10"
export IP_RADIUS="172.20.20.11"
export IP_ELASTIC="172.20.30.10"
export IP_KIBANA="172.20.30.11"
export IP_WAZUH="172.20.30.12"

# Credentials (override via env)
export AD_ADMINPASS="${AD_ADMINPASS:-H0sp1t@l\$ecure2024!}"
export RADIUS_SECRET="${RADIUS_SECRET:-R@dius\$ecret123}"
export AD_DOMAIN="${AD_DOMAIN:-hospital.local}"
export AD_REALM="${AD_REALM:-HOSPITAL.LOCAL}"

# Docker image pins (lightweight / verified)
export IMG_NGINX="nginx:1.25-alpine"
export IMG_ELASTIC="docker.elastic.co/elasticsearch/elasticsearch:8.13.4"
export IMG_KIBANA="docker.elastic.co/kibana/kibana:8.13.4"
export IMG_WAZUH="wazuh/wazuh-manager:4.7.4"
export OPENVAS_IMG="immauss/openvas:latest"
export IMG_SAMBA="dockurr/samba:latest"
export IMG_RADIUS="freeradius/freeradius-server:latest"

# ── Docker helpers ────────────────────────────────────────────────────────────
container_running() { docker ps --format '{{.Names}}' | grep -qx "$1"; }
container_exists()  { docker ps -a --format '{{.Names}}' | grep -qx "$1"; }
network_exists()    { docker network ls --format '{{.Name}}' | grep -qx "$1"; }

wait_for_url() {
  local url="$1" attempts="${2:-30}" delay="${3:-5}"
  local i=0
  while ! curl -sk --max-time 3 "$url" >/dev/null 2>&1; do
    ((i++))
    [[ $i -ge $attempts ]] && { warn "Timeout waiting for $url"; return 1; }
    echo -n "."
    sleep "$delay"
  done
  echo; ok "Service ready: $url"
}

wait_for_container() {
  local name="$1" attempts="${2:-40}" delay="${3:-5}"
  local i=0
  while ! container_running "$name"; do
    ((i++))
    [[ $i -ge $attempts ]] && { warn "Timeout waiting for container $name"; return 1; }
    echo -n "."
    sleep "$delay"
  done
  echo; ok "Container running: $name"
}

remove_container() {
  local name="$1"
  if container_exists "$name"; then
    docker rm -f "$name" >/dev/null 2>&1 && info "Removed container: $name"
  fi
}

remove_network() {
  local name="$1"
  if network_exists "$name"; then
    docker network rm "$name" >/dev/null 2>&1 && info "Removed network: $name" || \
      warn "Could not remove network $name (containers still attached?)"
  fi
}

# ── Resource checks ───────────────────────────────────────────────────────────
check_resources() {
  step "Checking system resources..."
  local ram_mb
  ram_mb=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo)
  local disk_gb
  disk_gb=$(df -BG / | awk 'NR==2{gsub(/G/,"",$4); print $4}')

  info "RAM available : ${ram_mb} MB"
  info "Disk free     : ${disk_gb} GB"

  [[ $ram_mb -lt 3500 ]] && warn "Less than 4 GB RAM detected — some services may be slow."
  [[ $disk_gb -lt 10  ]] && warn "Less than 10 GB disk free — image pulls may fail."
  ok "Resource check complete."
}

# ── Package preflight ─────────────────────────────────────────────────────────
REQUIRED_PKGS=(docker.io curl wget nftables tshark yara python3 python3-pip python3-magic file)
OPTIONAL_PKGS=(freeradius-utils wireshark ldap-utils)

install_if_missing() {
  local pkg="$1"
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    info "Installing missing package: $pkg"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1 \
      && ok "Installed: $pkg" \
      || warn "Could not install $pkg — some lab features may be limited."
  fi
}

preflight_packages() {
  step "Running package preflight checks..."
  apt-get update -qq >/dev/null 2>&1

  for pkg in "${REQUIRED_PKGS[@]}"; do
    install_if_missing "$pkg"
  done

  for pkg in "${OPTIONAL_PKGS[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      warn "Optional package not installed: $pkg  (install with: apt install $pkg)"
    fi
  done

  # Ensure python-magic pip package is present
  python3 -c "import magic" 2>/dev/null || \
    pip3 install python-magic --quiet 2>/dev/null || true

  # Ensure Docker daemon is running
  if ! systemctl is-active --quiet docker; then
    info "Starting Docker daemon..."
    systemctl enable --now docker >/dev/null 2>&1 || die "Cannot start Docker."
  fi

  ok "Preflight checks complete."
}

# ── nftables Zero-Trust rules ─────────────────────────────────────────────────
apply_nftables() {
  step "Applying Zero-Trust nftables rules..."
  nft flush ruleset 2>/dev/null || true

  nft -f - <<'NFTEOF'
table inet lab_filter {

  # ── Sets ──────────────────────────────────────────────────────────────────
  set dmz_net  { type ipv4_addr; flags interval; elements = { 172.20.10.0/24 } }
  set int_net  { type ipv4_addr; flags interval; elements = { 172.20.20.0/24 } }
  set mgt_net  { type ipv4_addr; flags interval; elements = { 172.20.30.0/24 } }

  # ── Forward chain (inter-segment) ─────────────────────────────────────────
  chain forward {
    type filter hook forward priority 0; policy drop;

    # Allow established / related
    ct state established,related accept

    # DMZ → Internal: DENY (Zero-Trust)
    ip saddr @dmz_net ip daddr @int_net \
      log prefix "LAB_DROP_DMZ2INT " drop

    # DMZ → Mgmt: DENY
    ip saddr @dmz_net ip daddr @mgt_net \
      log prefix "LAB_DROP_DMZ2MGT " drop

    # Internal → Mgmt: RADIUS reply only (UDP 1812/1813 responses) + LDAP
    ip saddr @int_net ip daddr @mgt_net \
      tcp dport { 389, 636 } accept
    ip saddr @int_net ip daddr @mgt_net \
      udp dport { 1812, 1813 } accept
    ip saddr @int_net ip daddr @mgt_net \
      log prefix "LAB_DROP_INT2MGT " drop

    # Mgmt → all: allow (monitoring)
    ip saddr @mgt_net accept

    # Host → all: allow
    accept
  }

  # ── Input chain (SSH brute-force protection) ──────────────────────────────
  chain input {
    type filter hook input priority 0; policy accept;

    tcp dport 22 ct state new \
      limit rate over 5/minute burst 10 packets \
      log prefix "LAB_SSH_BRUTE " drop
  }
}
NFTEOF

  ok "nftables Zero-Trust rules applied."
}

# ── Mkdirs ────────────────────────────────────────────────────────────────────
ensure_dirs() {
  mkdir -p "$LAB_BASE" "$LAB_DATA" "$EVIDENCE_DIR" "$COMPOSE_DIR"
  mkdir -p "$LAB_BASE"/{freeradius,webserver,malware-sim,yara}
}
