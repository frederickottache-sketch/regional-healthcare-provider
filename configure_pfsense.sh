#!/usr/bin/env bash
# =============================================================================
# SESSION 2: Secure Network Architecture, Wireless, and Mobile Security
# Goal   : Configure pfSense — VLANs, Zero-Trust firewall rules,
#          Suricata IPS, and OpenVPN for remote consultations.
#
# NOTE: pfSense runs on FreeBSD and is primarily configured via its
#       web GUI (https://<pfSense_LAN_IP>). This script documents every
#       required step with exact GUI paths AND where possible provides
#       the equivalent pfSense shell (pfSsh.php) commands so you can
#       automate or verify settings from the console.
#
# RUN ON: The Ubuntu host or any machine that can reach pfSense's LAN IP.
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }
note()  { echo -e "${YELLOW}[NOTE]${NC}  $*"; }

PFSENSE_IP="${PFSENSE_IP:-10.0.10.1}"
PFSENSE_USER="${PFSENSE_USER:-admin}"

# =============================================================================
# PHASE A — Verify connectivity to pfSense
# =============================================================================
phase_a_check_connectivity() {
    step "=== PHASE A: Checking connectivity to pfSense ==="
    if ping -c 2 -W 3 "${PFSENSE_IP}" &>/dev/null; then
        info "pfSense is reachable at ${PFSENSE_IP}"
    else
        note "Cannot reach ${PFSENSE_IP}. Ensure:"
        note "  1. pfSense is booted and interfaces are assigned."
        note "  2. Your host has an IP on the same subnet as ${PFSENSE_IP}."
        note "  3. The VirtualBox internal network is correctly named."
    fi
}

# =============================================================================
# PHASE B — VLAN configuration (GUI walkthrough)
# =============================================================================
phase_b_vlan_config() {
    step "=== PHASE B: VLAN Configuration (GUI Steps) ==="

    cat <<'EOF'

  pfSense Web GUI → Interfaces → VLANs → Add
  ─────────────────────────────────────────────────────────────────────────────
  Create each VLAN below (Parent Interface = em1 in all cases):

    VLAN Tag   Description    Assigned IP      Purpose
    ─────────  ─────────────  ───────────────  ─────────────────────────────
    10         DMZ            10.0.10.1/24     Public-facing servers
    20         Internal       10.0.20.1/24     Staff workstations & Samba-AD
    30         Management     10.0.30.1/24     ELK, OpenVAS, Cuckoo, Wireshark
    50         VPN_Pool       10.0.50.1/24     Remote VPN client pool

  After creating VLANs:
    Interfaces → Interface Assignments → Add each VLAN as an OPT interface
    For each interface:
      ✓ Enable Interface
      ✓ Set Description (DMZ / Internal / Management / VPN_Pool)
      ✓ IPv4 Configuration Type: Static IPv4
      ✓ Enter the IP address shown above
      ✓ Save → Apply Changes
EOF
}

# =============================================================================
# PHASE C — Firewall rules (Zero-Trust policy)
# =============================================================================
phase_c_firewall_rules() {
    step "=== PHASE C: Zero-Trust Firewall Rules (GUI Steps) ==="

    cat <<'EOF'

  Firewall → Rules  (configure per-interface)
  ─────────────────────────────────────────────────────────────────────────────
  DMZ interface rules:
    ALLOW  TCP  Source=DMZ net   Dest=any          Port=80,443   (web servers)
    BLOCK  any  Source=DMZ net   Dest=Internal net  Port=any     (isolation)
    BLOCK  any  Source=DMZ net   Dest=Management net Port=any    (isolation)

  Internal interface rules:
    ALLOW  TCP  Source=Internal  Dest=any           Port=80,443  (web browsing)
    BLOCK  any  Source=Internal  Dest=Management net Port=any    (no lateral move)
    BLOCK  any  Source=Internal  Dest=DMZ net        Port=any    (no lateral move)

  Management interface rules:
    ALLOW  any  Source=Management Dest=any           Port=any    (full admin access)

  VPN_Pool interface rules:
    ALLOW  any  Source=VPN_Pool  Dest=Internal net  Port=any    (remote consult)
    BLOCK  any  Source=VPN_Pool  Dest=DMZ net       Port=any    (VPN cannot reach DMZ)

  Floating rules (last resort):
    BLOCK  any  Source=any       Dest=any           Port=any    (implicit deny-all)
  ─────────────────────────────────────────────────────────────────────────────
  TIP: Use Aliases (Firewall → Aliases) to group IPs before creating rules.
       e.g., Alias "MGMT_SERVERS" = 10.0.30.10, 10.0.30.20, 10.0.30.30
EOF
}

# =============================================================================
# PHASE D — Suricata IPS installation
# =============================================================================
phase_d_suricata() {
    step "=== PHASE D: Suricata IPS (GUI Steps) ==="

    cat <<'EOF'

  System → Package Manager → Available Packages
    Search "suricata" → Click Install → Confirm

  After installation: Services → Suricata

  1. Global Settings:
       ✓ Enable Emerging Threats Open (ET Open)   [free, updated daily]
       ✓ Enable Snort Community Rules
       Click "Update Rules" to download immediately.

  2. Interfaces → Add (repeat for each interface below):
       Interface: WAN        Enable: ✓   IPS Mode: ✓ (Inline)
       Interface: DMZ        Enable: ✓   IPS Mode: ✓
       Interface: Internal   Enable: ✓   IPS Mode: ✓

  3. Per-interface settings (for each interface above):
       Block Offenders: ✓
       Block Duration:  3600 (1 hour)

  4. (Optional) pfBlockerNG for geo-blocking:
       System → Package Manager → Install "pfBlockerNG-devel"
       After install: Firewall → pfBlockerNG → configure DNSBL & IP feeds
EOF
}

# =============================================================================
# PHASE E — OpenVPN server for remote consultations
# =============================================================================
phase_e_openvpn() {
    step "=== PHASE E: OpenVPN Server (GUI Steps) ==="

    cat <<'EOF'

  VPN → OpenVPN → Wizards → Local User Access
  ─────────────────────────────────────────────────────────────────────────────
  Step 1 – Certificate Authority
    Descriptive Name:  HospitalCA
    Key Length:        4096
    Digest Algorithm:  SHA-256
    Lifetime:          3650 days

  Step 2 – Server Certificate
    Descriptive Name:  HospitalVPN-Server
    (Sign with HospitalCA)

  Step 3 – Server Configuration
    Interface:          WAN
    Protocol:           UDP on IPv4 only
    Local Port:         1194
    Description:        Remote Consultation VPN
    TLS Authentication: ✓ (auto-generate shared key)
    DH Parameter Len:   4096
    Encryption Algo:    AES-256-GCM
    Auth Digest:        SHA256
    IPv4 Tunnel Net:    10.0.50.0/24      ← matches VLAN 50 / VPN_Pool
    Redirect Gateway:   ✗                  (split tunnel — users keep local internet)
    DNS Server 1:       10.0.20.10         ← Samba-AD DNS

  Step 4 – Firewall Rules
    ✓ Add firewall rule (automatically adds WAN UDP 1194 → OpenVPN)
    ✓ Add OpenVPN rule (automatically allows traffic from VPN clients)

  Creating VPN users:
    System → User Manager → Add
    Username:  remote_doctor   Password: <strong_password>
    ✓ Click the lock icon to create a certificate for this user

  Exporting client configs:
    System → Package Manager → Install "openvpn-client-export"
    VPN → OpenVPN → Client Export
    For each user → Download "Bundled Configurations (Most Clients)"
EOF
}

# =============================================================================
# PHASE F — Post-config checklist
# =============================================================================
phase_f_checklist() {
    step "=== PHASE F: Session 2 Validation Checklist ==="

    cat <<'EOF'

  Run these from an Internal-network VM to verify rules:

  ✓ Ping pfSense LAN gateway from Workstation-W10:
      ping 10.0.20.1

  ✓ Attempt ping from Internal to Management (MUST FAIL):
      ping 10.0.30.10    ← should time out

  ✓ Attempt ping from Internal to DMZ (MUST FAIL):
      ping 10.0.10.10    ← should time out

  ✓ Management can reach everything:
      (from Wireshark-VM) ping 10.0.20.10   ← Samba-AD
      (from Wireshark-VM) ping 10.0.10.10   ← Web-Server-DMZ

  ✓ OpenVPN: connect a client, verify IP in 10.0.50.x range,
      then ping 10.0.20.1 (Internal gateway) — should succeed.

  Save pfSense config backup:
      Diagnostics → Backup & Restore → Download configuration XML
EOF
}

# =============================================================================
# Main
# =============================================================================
main() {
    info "============================================================"
    info "  Session 2 – pfSense: VLANs, Firewall, IPS, OpenVPN"
    info "============================================================"
    note "This session is GUI-driven. The script prints exact steps."
    echo ""

    phase_a_check_connectivity
    echo ""
    phase_b_vlan_config
    echo ""
    phase_c_firewall_rules
    echo ""
    phase_d_suricata
    echo ""
    phase_e_openvpn
    echo ""
    phase_f_checklist

    info "Session 2 guidance complete. Proceed to session3/ when done."
}

main "$@"
