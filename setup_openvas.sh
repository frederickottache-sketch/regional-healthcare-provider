#!/usr/bin/env bash
# =============================================================================
# SESSION 3: Threat Intelligence, Vulnerability Management & Secure Protocols
# Goal   : Install and configure OpenVAS (Greenbone Vulnerability Manager)
#          on the OpenVAS-Scanner VM (Ubuntu 22.04, VLAN 30 – 10.0.30.20)
#
# RUN ON: OpenVAS-Scanner VM as a regular user with sudo privileges
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

MGMT_IP="10.0.30.20"          # This VM's static IP on Management VLAN
GVM_WEB_PORT="9392"
CRON_HOUR_DATA=2
CRON_HOUR_SCAP=3
CRON_HOUR_CERT=4

# =============================================================================
# STEP 1 — Set hostname and configure static IP
# =============================================================================
step1_set_hostname() {
    step "=== STEP 1: Setting hostname and static IP ==="

    sudo hostnamectl set-hostname gvm-scanner
    info "Hostname set to gvm-scanner."

    # Static IP configuration via netplan (Ubuntu 22.04)
    local netplan_file
    netplan_file=$(sudo ls /etc/netplan/*.yaml 2>/dev/null | head -1)

    if [[ -z "${netplan_file}" ]]; then
        netplan_file="/etc/netplan/50-cloud-init.yaml"
    fi

    warn "Ensure your netplan config assigns static IP ${MGMT_IP}/24."
    warn "Example /etc/netplan/50-cloud-init.yaml snippet:"
    cat <<EOF
  network:
    version: 2
    ethernets:
      enp0s3:               # adjust interface name as needed
        addresses:
          - ${MGMT_IP}/24
        routes:
          - to: default
            via: 10.0.30.1  # pfSense Management gateway
        nameservers:
          addresses:
            - 10.0.20.10    # Samba-AD DNS
            - 8.8.8.8       # fallback
EOF
    warn "Run: sudo netplan apply   (after editing the file)"
}

# =============================================================================
# STEP 2 — Update and install prerequisites
# =============================================================================
step2_update_and_prereqs() {
    step "=== STEP 2: Updating system and installing prerequisites ==="
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y \
        curl wget gnupg \
        software-properties-common \
        apt-transport-https
    info "System updated."
}

# =============================================================================
# STEP 3 — Install GVM (Greenbone Vulnerability Management)
# =============================================================================
step3_install_gvm() {
    step "=== STEP 3: Installing GVM package ==="
    sudo apt install -y gvm
    info "GVM package installed."
}

# =============================================================================
# STEP 4 — Run gvm-setup (downloads feeds — takes 1-2 hours first run)
# =============================================================================
step4_run_gvm_setup() {
    step "=== STEP 4: Running gvm-setup (feed download — be patient) ==="
    warn "This step may take 1-2 hours on a first run (feed download)."
    sudo gvm-setup

    info "Retrieving auto-generated admin password ..."
    local pw_file="/var/lib/gvm/gvmd/users/admin/password"
    if [[ -f "${pw_file}" ]]; then
        local admin_pw
        admin_pw=$(sudo cat "${pw_file}")
        info "GVM admin password: ${admin_pw}"
        warn "SAVE THIS PASSWORD — store it securely before proceeding!"
        echo "${admin_pw}" > "${HOME}/.gvm_admin_password"
        chmod 600 "${HOME}/.gvm_admin_password"
        info "Password also saved to ~/.gvm_admin_password (chmod 600)."
    else
        warn "Password file not found. Check the end of the gvm-setup output."
    fi
}

# =============================================================================
# STEP 5 — Start GVM services
# =============================================================================
step5_start_gvm() {
    step "=== STEP 5: Starting GVM services ==="
    sudo gvm-start
    info "GVM started. Access Greenbone Security Assistant at:"
    info "  https://${MGMT_IP}:${GVM_WEB_PORT}"
}

# =============================================================================
# STEP 6 — Verify GVM health
# =============================================================================
step6_check_setup() {
    step "=== STEP 6: Running gvm-check-setup ==="
    sudo gvm-check-setup || warn "Check above output for any issues."
}

# =============================================================================
# STEP 7 — Schedule daily feed updates via cron
# =============================================================================
step7_schedule_feed_updates() {
    step "=== STEP 7: Scheduling daily vulnerability feed updates ==="

    # Write cron entries for root
    local cron_entries
    cron_entries=$(printf \
        "0 %d * * * /usr/bin/greenbone-feed-sync --type GVMD_DATA\n\
0 %d * * * /usr/bin/greenbone-feed-sync --type SCAP\n\
0 %d * * * /usr/bin/greenbone-feed-sync --type CERT\n" \
        "${CRON_HOUR_DATA}" "${CRON_HOUR_SCAP}" "${CRON_HOUR_CERT}")

    # Append to root crontab (avoid duplicates)
    (sudo crontab -l 2>/dev/null || true; echo "${cron_entries}") \
        | sudo sort -u | sudo crontab -

    info "Cron jobs added for root:"
    sudo crontab -l | grep greenbone || true
}

# =============================================================================
# STEP 8 — Print scan setup guide (GUI steps)
# =============================================================================
step8_scan_setup_guide() {
    step "=== STEP 8: Greenbone Security Assistant – Scan Setup Guide ==="

    cat <<'EOF'

  Open https://10.0.30.20:9392 in a browser on the Management network.
  ─────────────────────────────────────────────────────────────────────────────

  A. Create Credentials (for authenticated scans):
       Configuration → Credentials → New Credential
         Name:      Ubuntu-Scan-Account
         Type:      Username + Password
         Username:  <scan_service_account>   ← pre-create on target VMs
         Password:  <password>
         Comment:   Used for GVM authenticated scans

  B. Create Targets:
       Configuration → Targets → New Target
         Name:      DMZ-Segment      Hosts: 10.0.10.0/24   (unauthenticated)
         Name:      Internal-Segment Hosts: 10.0.20.0/24   Creds: Ubuntu-Scan-Account
         Name:      Management-Seg   Hosts: 10.0.30.0/24   Creds: Ubuntu-Scan-Account

  C. Create Scan Tasks:
       Scans → Tasks → New Task
         Name:          Full-Scan-Internal
         Target:        Internal-Segment
         Scan Config:   Full and fast
         Schedule:      Every Sunday at 02:00

  D. Download reports:
       Reports → select a completed report → Export as PDF
       Store PDFs in your compliance portfolio folder.

  ─────────────────────────────────────────────────────────────────────────────
  REMEDIATION WORKFLOW (CVSS scoring):
    Critical  9.0–10.0  → Patch within 24 hours; isolate host if needed
    High      7.0–8.9   → Patch within 7 days
    Medium    4.0–6.9   → Patch within 30 days
    Low       0.1–3.9   → Next maintenance window
EOF
}

# =============================================================================
# Main
# =============================================================================
main() {
    info "============================================================"
    info "  Session 3 – OpenVAS / Greenbone Vulnerability Manager"
    info "============================================================"

    [[ "$(id -u)" -eq 0 ]] && { \
        warn "Running as root. Consider running as a regular sudo user."; }

    step1_set_hostname
    step2_update_and_prereqs
    step3_install_gvm
    step4_run_gvm_setup
    step5_start_gvm
    step6_check_setup
    step7_schedule_feed_updates
    step8_scan_setup_guide

    info "Session 3 complete. GVM is running at https://${MGMT_IP}:${GVM_WEB_PORT}"
    info "Proceed to session4/ for Cuckoo Sandbox setup."
}

main "$@"
