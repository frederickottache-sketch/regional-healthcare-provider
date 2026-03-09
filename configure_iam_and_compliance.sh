#!/usr/bin/env bash
# =============================================================================
# SESSION 6: Governance, Compliance, and Emerging Trends
# Goal   : 1. Configure Samba Active Directory Domain Controller
#          2. Install and configure FreeRADIUS for 802.1X / VPN auth
#          3. Set up Wireshark for traffic analysis
#          4. Gather compliance evidence
#
# RUN ON: Samba-AD VM (Ubuntu 22.04, VLAN 20 – 10.0.20.10)
#         Wireshark-VM section runs on Wireshark-VM (Ubuntu 22.04 Desktop)
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $*"; exit 1; }

# ── Samba AD settings ─────────────────────────────────────────────────────────
SAMBA_VM_IP="10.0.20.10"
AD_REALM="HOSPITAL.LOCAL"
AD_DOMAIN="HOSPITAL"
AD_ADMINPASS="${AD_ADMINPASS:-H0sp1t@l\$ecure2024!}"   # override via env var
DNS_FORWARDER="8.8.8.8"

# ── FreeRADIUS / RADIUS settings ─────────────────────────────────────────────
PFSENSE_IP="10.0.10.1"
RADIUS_SECRET="${RADIUS_SECRET:-R@dius\$ecret123}"

# ── Wireshark-VM IP ───────────────────────────────────────────────────────────
WIRESHARK_VM_IP="10.0.30.40"

# =============================================================================
# ════════════════════  PART A: SAMBA ACTIVE DIRECTORY  ══════════════════════
# =============================================================================

# ── A1. Set hostname and static IP ────────────────────────────────────────────
partA_step1_set_hostname() {
    step "=== A1: Setting hostname and static IP ==="
    sudo hostnamectl set-hostname samba-ad

    # Update /etc/hosts for AD DNS resolution
    if ! grep -q "${AD_REALM,,}" /etc/hosts; then
        echo "${SAMBA_VM_IP}  samba-ad.${AD_REALM,,}  samba-ad" \
            | sudo tee -a /etc/hosts
    fi
    info "Hostname set to samba-ad."

    warn "Static IP must be configured in /etc/netplan/*.yaml:"
    cat <<EOF
  network:
    version: 2
    ethernets:
      enp0s3:
        addresses:
          - ${SAMBA_VM_IP}/24
        routes:
          - to: default
            via: 10.0.20.1
        nameservers:
          search: [${AD_REALM,,}]
          addresses:
            - 127.0.0.1    ← Samba serves DNS for the domain
            - ${DNS_FORWARDER}
EOF
    warn "Run: sudo netplan apply"
}

# ── A2. Install Samba and dependencies ────────────────────────────────────────
partA_step2_install_samba() {
    step "=== A2: Installing Samba and related packages ==="
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y \
        samba \
        winbind \
        libpam-winbind \
        libnss-winbind \
        smbclient \
        krb5-user \
        python3-samba
    info "Samba installed."
}

# ── A3. Provision the domain ──────────────────────────────────────────────────
partA_step3_provision_domain() {
    step "=== A3: Provisioning Active Directory domain ==="

    # Back up default smb.conf if present
    [[ -f /etc/samba/smb.conf ]] && \
        sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.bak

    sudo samba-tool domain provision \
        --realm="${AD_REALM}" \
        --domain="${AD_DOMAIN}" \
        --adminpass="${AD_ADMINPASS}" \
        --dns-backend=SAMBA_INTERNAL \
        --server-role=dc \
        --use-rfc2307

    info "Domain ${AD_REALM} provisioned."
}

# ── A4. Configure Kerberos ────────────────────────────────────────────────────
partA_step4_configure_kerberos() {
    step "=== A4: Configuring Kerberos client ==="

    sudo tee /etc/krb5.conf > /dev/null <<EOF
[libdefaults]
    default_realm = ${AD_REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    ${AD_REALM} = {
        kdc = samba-ad.${AD_REALM,,}
        admin_server = samba-ad.${AD_REALM,,}
    }

[domain_realm]
    .${AD_REALM,,} = ${AD_REALM}
    ${AD_REALM,,}  = ${AD_REALM}
EOF
    info "Kerberos configured."
}

# ── A5. Start Samba AD DC ─────────────────────────────────────────────────────
partA_step5_start_samba() {
    step "=== A5: Enabling and starting Samba AD DC ==="

    # Disable conflicting services
    for svc in smbd nmbd winbind; do
        sudo systemctl disable --now "${svc}" 2>/dev/null || true
    done

    sudo systemctl unmask samba-ad-dc
    sudo systemctl enable --now samba-ad-dc
    info "Samba AD DC started."
}

# ── A6. Verify domain controller ─────────────────────────────────────────────
partA_step6_verify_domain() {
    step "=== A6: Verifying domain controller ==="

    sleep 5  # give Samba a moment to fully start

    samba-tool domain info 127.0.0.1 || warn "Domain info query failed — check samba-ad-dc service."
    samba-tool user list           || warn "User list query failed."
    info "Domain verification complete."
}

# ── A7. Create OUs and sample users ──────────────────────────────────────────
partA_step7_create_ous_and_users() {
    step "=== A7: Creating Organisational Units and sample users ==="

    # Create OUs
    samba-tool ou create "OU=Medical Staff,DC=${AD_DOMAIN,,},DC=local" 2>/dev/null || \
        warn "OU 'Medical Staff' may already exist."
    samba-tool ou create "OU=Admin Staff,DC=${AD_DOMAIN,,},DC=local"   2>/dev/null || \
        warn "OU 'Admin Staff' may already exist."
    samba-tool ou create "OU=IT Security,DC=${AD_DOMAIN,,},DC=local"   2>/dev/null || \
        warn "OU 'IT Security' may already exist."

    # Sample medical staff user
    samba-tool user create jdoe \
        --given-name=John \
        --surname=Doe \
        --mail-address=jdoe@${AD_REALM,,} \
        --userou="OU=Medical Staff,DC=${AD_DOMAIN,,},DC=local" \
        --newpassword="Doctor@2024!" \
        2>/dev/null || warn "User jdoe may already exist."

    # Sample IT user (VPN access)
    samba-tool user create itadmin \
        --given-name=IT \
        --surname=Admin \
        --mail-address=itadmin@${AD_REALM,,} \
        --userou="OU=IT Security,DC=${AD_DOMAIN,,},DC=local" \
        --newpassword="ITAdmin@2024!" \
        2>/dev/null || warn "User itadmin may already exist."

    # Sample remote clinician (VPN user)
    samba-tool user create rdoctor \
        --given-name=Remote \
        --surname=Doctor \
        --mail-address=rdoctor@${AD_REALM,,} \
        --userou="OU=Medical Staff,DC=${AD_DOMAIN,,},DC=local" \
        --newpassword="Remote@2024!" \
        2>/dev/null || warn "User rdoctor may already exist."

    info "OUs and users created."
    samba-tool user list
}

# =============================================================================
# ════════════════════  PART B: FREERADIUS  ═══════════════════════════════════
# =============================================================================

# ── B1. Install FreeRADIUS ────────────────────────────────────────────────────
partB_step1_install_freeradius() {
    step "=== B1: Installing FreeRADIUS ==="
    sudo apt install -y freeradius freeradius-ldap
    info "FreeRADIUS installed."
}

# ── B2. Configure LDAP module to query Samba AD ──────────────────────────────
partB_step2_configure_ldap() {
    step "=== B2: Configuring FreeRADIUS LDAP module ==="

    local ldap_conf="/etc/freeradius/3.0/mods-available/ldap"

    sudo tee "${ldap_conf}" > /dev/null <<EOF
ldap {
    server    = '${SAMBA_VM_IP}'
    port      = 389
    #tls { ... }     # Uncomment for LDAPS in production

    # Credentials for LDAP bind (use a read-only service account in production)
    identity  = 'CN=Administrator,CN=Users,DC=${AD_DOMAIN,,},DC=local'
    password  = '${AD_ADMINPASS}'

    base_dn   = 'DC=${AD_DOMAIN,,},DC=local'

    # Find user by their Windows logon name
    filter    = '(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}})'

    # Attribute mapping
    user {
        base_dn = "OU=Medical Staff,DC=${AD_DOMAIN,,},DC=local"
    }

    pool {
        start    = 5
        min      = 4
        max      = 10
        spare    = 3
        uses     = 0
        lifetime = 0
        idle_timeout = 60
    }
}
EOF

    # Enable the LDAP module by creating a symlink
    sudo ln -sf \
        /etc/freeradius/3.0/mods-available/ldap \
        /etc/freeradius/3.0/mods-enabled/ldap

    info "LDAP module configured and enabled."
}

# ── B3. Add pfSense as a RADIUS client ────────────────────────────────────────
partB_step3_add_radius_client() {
    step "=== B3: Adding pfSense as a RADIUS client ==="

    local clients_conf="/etc/freeradius/3.0/clients.conf"

    # Append pfSense client block if not already present
    if ! grep -q "client pfsense" "${clients_conf}"; then
        sudo tee -a "${clients_conf}" > /dev/null <<EOF

# pfSense firewall — RADIUS client for VPN authentication
client pfsense {
    ipaddr    = ${PFSENSE_IP}
    secret    = '${RADIUS_SECRET}'
    shortname = pfsense
    nastype   = other
}
EOF
        info "pfSense RADIUS client added."
    else
        warn "pfSense client block already exists in clients.conf."
    fi
}

# ── B4. Configure default virtual server to use LDAP ─────────────────────────
partB_step4_configure_sites() {
    step "=== B4: Configuring FreeRADIUS default site for LDAP auth ==="

    local default_site="/etc/freeradius/3.0/sites-available/default"

    # Ensure ldap appears in the authorize section (idempotent)
    if ! sudo grep -q "^[[:space:]]*ldap$" "${default_site}"; then
        sudo sed -i '/^authorize {/a\        ldap' "${default_site}"
        info "LDAP added to authorize section."
    fi

    # Ensure ldap appears in authenticate section
    if ! sudo grep -q "Auth-Type LDAP" "${default_site}"; then
        sudo sed -i '/^authenticate {/a\        Auth-Type LDAP {\n            ldap\n        }' \
            "${default_site}"
        info "LDAP Auth-Type added to authenticate section."
    fi
}

# ── B5. Start FreeRADIUS ──────────────────────────────────────────────────────
partB_step5_start_freeradius() {
    step "=== B5: Starting FreeRADIUS ==="
    sudo systemctl enable --now freeradius
    sudo systemctl status freeradius --no-pager | head -15
    info "FreeRADIUS started."
}

# ── B6. Test RADIUS locally ───────────────────────────────────────────────────
partB_step6_test_radius() {
    step "=== B6: Testing RADIUS authentication (local test) ==="

    warn "Run the following test after creating user 'rdoctor' in AD:"
    echo ""
    echo "  radtest rdoctor 'Remote@2024!' 127.0.0.1 0 '${RADIUS_SECRET}'"
    echo ""
    warn "Expected output contains: Access-Accept"
    warn "If you see Access-Reject, check /var/log/freeradius/radius.log"
}

# ── B7. pfSense RADIUS integration guide ─────────────────────────────────────
partB_step7_pfsense_radius_guide() {
    step "=== B7: pfSense RADIUS Integration (GUI Steps) ==="

    cat <<EOF

  In the pfSense Web GUI:
  ─────────────────────────────────────────────────────────────────────────────
  1. System → User Manager → Authentication Servers → Add
       Type:             RADIUS
       Descriptive Name: HospitalAD-RADIUS
       Hostname:         ${SAMBA_VM_IP}
       Shared Secret:    ${RADIUS_SECRET}
       Services offered: Authentication and Accounting
       RADIUS Auth Port: 1812
       RADIUS Acct Port: 1813
       → Save

  2. VPN → OpenVPN → Edit server (the one created in Session 2)
       Backend for authentication: HospitalAD-RADIUS
       → Save → Apply Changes

  3. Test: attempt a VPN connection using rdoctor / Remote@2024!
       The request flows: pfSense → FreeRADIUS → Samba AD → Access-Accept
  ─────────────────────────────────────────────────────────────────────────────
EOF
}

# =============================================================================
# ════════════════════  PART C: WIRESHARK VM  ═════════════════════════════════
# =============================================================================

partC_wireshark_setup() {
    step "=== PART C: Wireshark Setup Guide (run on Wireshark-VM) ==="

    cat <<'EOF'

  Run on Wireshark-VM (Ubuntu 22.04 Desktop, VLAN 30 – 10.0.30.40):
  ─────────────────────────────────────────────────────────────────────────────
  sudo apt update && sudo apt install -y wireshark

  # Allow non-root users to capture packets
  sudo usermod -aG wireshark $USER
  sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

  # Apply group membership without logging out
  newgrp wireshark

  # In VirtualBox: ensure the VM NIC is set to Promiscuous Mode → Allow All
  # (already done in Session 1 via --nicpromisc1 allow-all)
  ─────────────────────────────────────────────────────────────────────────────

  Useful Wireshark display filters for healthcare security analysis:

  Filter                              Purpose
  ──────────────────────────────────  ─────────────────────────────────────────
  radius                              Monitor RADIUS authentication traffic
  http.authbasic                      Detect cleartext HTTP basic auth
  dns                                 Monitor all DNS queries
  tcp.flags.syn==1 && tcp.flags.ack==0   Detect port scans (SYN scan)
  vlan                                Capture and inspect VLAN-tagged frames
  ssl.handshake                       Monitor TLS handshakes (VPN/HTTPS)
  arp                                 Detect ARP spoofing attempts
  icmp                                Monitor ICMP / ping traffic

  RADIUS packet verification:
    1. Start capture on the Management interface
    2. Initiate a VPN login from a remote client
    3. Filter: radius
       You should see: Access-Request → Access-Accept (or Access-Reject)
    4. Expand RADIUS AVPs to verify:
       - User-Name attribute
       - NAS-IP-Address = pfSense IP
       - Message-Authenticator
  ─────────────────────────────────────────────────────────────────────────────
EOF
}

# =============================================================================
# ════════════════════  PART D: COMPLIANCE EVIDENCE  ══════════════════════════
# =============================================================================

partD_collect_evidence() {
    step "=== PART D: Collecting Compliance Evidence ==="

    local evidence_dir="${HOME}/compliance_evidence"
    mkdir -p "${evidence_dir}"

    info "Collecting Samba AD evidence ..."

    # User list
    samba-tool user list > "${evidence_dir}/ad_user_list.txt" 2>&1 || true

    # Group memberships
    for group in "Domain Admins" "Domain Users"; do
        samba-tool group listmembers "${group}" \
            >> "${evidence_dir}/ad_group_memberships.txt" 2>&1 || true
    done

    # OU list
    samba-tool ou list >> "${evidence_dir}/ad_ou_list.txt" 2>&1 || true

    # FreeRADIUS client list
    grep -A5 "client " /etc/freeradius/3.0/clients.conf \
        > "${evidence_dir}/radius_clients.txt" 2>&1 || true

    info "Evidence collected in ${evidence_dir}/"
    ls -lh "${evidence_dir}/"

    cat <<'EOF'

  Additional evidence to collect manually:
  ─────────────────────────────────────────────────────────────────────────────
  pfSense:
    Diagnostics → Backup & Restore → Download configuration XML
    Firewall → Rules → (screenshot all interface rule tables)

  Wazuh Dashboard:
    Modules → Security Events → (screenshot showing active log collection)
    Modules → Integrity Monitoring → (screenshot)
    Management → Agents → (screenshot showing all agents Active)

  OpenVAS:
    Reports → select completed scan → Export as PDF
    Save to compliance_evidence/openvas_scan_<date>.pdf

  Cuckoo:
    .cuckoo/storage/analyses/<task_id>/reports/report.json
    Copy to compliance_evidence/cuckoo_eicar_report.json

  VPN:
    Export a client .ovpn file as evidence of PKI implementation
  ─────────────────────────────────────────────────────────────────────────────
EOF
}

# =============================================================================
# ════════════════════  PART E: HIPAA COMPLIANCE SUMMARY  ═════════════════════
# =============================================================================

partE_hipaa_summary() {
    step "=== PART E: HIPAA / NDPA Compliance Control Summary ==="

    cat <<'EOF'

  HIPAA Standard        Control Implemented                Evidence Location
  ────────────────────  ─────────────────────────────────  ─────────────────────────────
  164.308(a)(1)         OpenVAS vulnerability scanning     openvas_scan_*.pdf
  164.308(a)(3)         Samba AD OUs + Group Policies      ad_user_list.txt
  164.308(a)(4)         VLANs, RADIUS, least privilege     pfSense config XML
  164.308(a)(6)         Wazuh alerting + IR playbook       wazuh_alerts_screenshot
  164.312(a)(1)         VLANs, Zero-Trust firewall rules   pfSense config XML
  164.312(b)            ELK + Wazuh centralised logging    kibana_dashboard_screenshot
  164.312(c)(1)         Wazuh FIM + Cuckoo sandbox         fim_alerts + cuckoo report
  164.312(d)            FreeRADIUS 802.1X + VPN certs      radius_clients.txt + .ovpn
  164.312(e)(1)         OpenVPN AES-256-GCM, HTTPS/TLS     VPN config export

  NDPA Obligations:
  ─────────────────
  Data Minimisation   : AD role-based access (Medical Staff / Admin / IT OUs)
  Purpose Limitation  : VLANs isolate billing from clinical systems
  Data Security       : OpenVPN encrypts all ePHI in transit
  Breach Notification : Wazuh real-time alerts → 72-hour NITDA window
  DPO Role            : Documented in Security Policy document (docs/ folder)
EOF
}

# =============================================================================
# Main
# =============================================================================
main() {
    info "============================================================"
    info "  Session 6 – Governance, Compliance & Identity Management"
    info "============================================================"

    local mode="${1:-all}"

    case "${mode}" in
        samba)
            partA_step1_set_hostname
            partA_step2_install_samba
            partA_step3_provision_domain
            partA_step4_configure_kerberos
            partA_step5_start_samba
            partA_step6_verify_domain
            partA_step7_create_ous_and_users
            ;;
        radius)
            partB_step1_install_freeradius
            partB_step2_configure_ldap
            partB_step3_add_radius_client
            partB_step4_configure_sites
            partB_step5_start_freeradius
            partB_step6_test_radius
            partB_step7_pfsense_radius_guide
            ;;
        wireshark)
            partC_wireshark_setup
            ;;
        evidence)
            partD_collect_evidence
            partE_hipaa_summary
            ;;
        all|*)
            partA_step1_set_hostname
            partA_step2_install_samba
            partA_step3_provision_domain
            partA_step4_configure_kerberos
            partA_step5_start_samba
            partA_step6_verify_domain
            partA_step7_create_ous_and_users
            partB_step1_install_freeradius
            partB_step2_configure_ldap
            partB_step3_add_radius_client
            partB_step4_configure_sites
            partB_step5_start_freeradius
            partB_step6_test_radius
            partB_step7_pfsense_radius_guide
            partC_wireshark_setup
            partD_collect_evidence
            partE_hipaa_summary
            ;;
    esac

    info "============================================================"
    info "  Session 6 Complete — Capstone Project Implementation Done"
    info "  Review docs/README.md for the full project overview."
    info "============================================================"
}

main "$@"
