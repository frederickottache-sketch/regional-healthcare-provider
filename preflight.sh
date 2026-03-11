#!/usr/bin/env bash
# =============================================================================
# preflight.sh — Pre-flight checks and dependency installer
# Run this FIRST before any session script.
# Usage: sudo bash preflight.sh
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

require_root

banner "Healthcare Security Lab — Pre-flight Checker"

# ── 1. OS Check ───────────────────────────────────────────────────────────────
step "Checking operating system..."
. /etc/os-release
if [[ "$ID" != "ubuntu" ]] || [[ "${VERSION_ID%%.*}" -lt 20 ]]; then
  warn "Tested on Ubuntu 20.04/22.04. Current: $PRETTY_NAME — proceeding anyway."
else
  ok "OS: $PRETTY_NAME"
fi

# ── 2. Resource check ─────────────────────────────────────────────────────────
check_resources

# ── 3. Virtualisation check (for Docker perf) ─────────────────────────────────
step "Checking CPU virtualisation..."
if grep -qE 'vmx|svm' /proc/cpuinfo; then
  ok "VT-x / AMD-V detected."
else
  warn "No hardware virtualisation flag found — Docker will still work but may be slower."
fi

# ── 4. Install packages ───────────────────────────────────────────────────────
preflight_packages

# ── 5. Docker version ─────────────────────────────────────────────────────────
step "Checking Docker..."
DOCKER_VER=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')
ok "Docker version: ${DOCKER_VER:-unknown}"

# Ensure current user is in docker group (for non-root use after setup)
if ! groups "$SUDO_USER" 2>/dev/null | grep -q docker; then
  usermod -aG docker "$SUDO_USER" 2>/dev/null && \
    info "Added $SUDO_USER to docker group. Re-login to take effect."
fi

# ── 6. nftables kernel module ─────────────────────────────────────────────────
step "Checking nftables kernel support..."
if modprobe nf_tables 2>/dev/null; then
  ok "nf_tables kernel module loaded."
else
  warn "nf_tables module not loaded — nftables rules may not apply."
fi

# ── 7. Docker daemon tweaks for low-RAM ───────────────────────────────────────
step "Configuring Docker daemon for low-RAM environment..."
DAEMON_JSON="/etc/docker/daemon.json"
if [[ ! -f "$DAEMON_JSON" ]] || ! grep -q '"log-driver"' "$DAEMON_JSON"; then
  cat > "$DAEMON_JSON" <<'DOCKEREOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
DOCKEREOF
  systemctl restart docker
  ok "Docker daemon configured (log limits + overlay2)."
else
  ok "Docker daemon config already present."
fi

# ── 8. Kernel tuning for Elasticsearch ───────────────────────────────────────
step "Applying kernel tunables..."
sysctl -w vm.max_map_count=262144 >/dev/null
sysctl -w net.core.somaxconn=1024 >/dev/null
# Make persistent
grep -qx 'vm.max_map_count=262144' /etc/sysctl.conf 2>/dev/null || \
  echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
ok "Kernel tunables applied."

# ── 9. Create lab directory structure ────────────────────────────────────────
ensure_dirs
ok "Lab directories created under $LAB_BASE"

# ── 10. Python deps ───────────────────────────────────────────────────────────
step "Installing Python dependencies..."
pip3 install python-magic --quiet 2>/dev/null && ok "python-magic installed." || \
  warn "python-magic install failed — YARA session may be limited."

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  Pre-flight complete. System is ready.       ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Next step:  ${CYAN}sudo bash setup.sh all${NC}"
echo -e "  Or run individual sessions:"
echo -e "    ${CYAN}sudo bash sessions/session1_network.sh${NC}"
echo -e "    ${CYAN}sudo bash sessions/session2_siem.sh${NC}"
echo -e "    ${CYAN}sudo bash sessions/session3_scanner.sh${NC}"
echo -e "    ${CYAN}sudo bash sessions/session4_malware.sh${NC}"
echo -e "    ${CYAN}sudo bash sessions/session5_iam.sh${NC}"
echo -e "    ${CYAN}sudo bash sessions/session6_traffic.sh${NC}"
echo ""
