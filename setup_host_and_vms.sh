#!/usr/bin/env bash
# =============================================================================
# SESSION 1: Foundations of Advanced Network Security and Cryptography
# Goal   : Install VirtualBox, create all VMs, prepare host networking
# Author : Healthcare Network Security Project
# Run as : Regular user with sudo privileges on Ubuntu 22.04 LTS host
# =============================================================================
set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Configuration ─────────────────────────────────────────────────────────────
VM_BASE_DIR="$HOME/VirtualBox VMs"
VBX_VERSION="7.0.20"

# ISO paths — update these before running
PFSENSE_ISO="${PFSENSE_ISO:-/path/to/pfSense.iso}"
UBUNTU_22_ISO="${UBUNTU_22_ISO:-/path/to/ubuntu-22.04-live-server-amd64.iso}"
UBUNTU_22_DESKTOP_ISO="${UBUNTU_22_DESKTOP_ISO:-/path/to/ubuntu-22.04-desktop-amd64.iso}"
UBUNTU_20_ISO="${UBUNTU_20_ISO:-/path/to/ubuntu-20.04-live-server-amd64.iso}"
WIN10_ISO="${WIN10_ISO:-/path/to/win10.iso}"

# Host bridge adapter — update to your physical NIC name
HOST_NIC="${HOST_NIC:-eth0}"

# ── Helper: create a VM with SATA controller + attach disk + attach ISO ────────
create_vm() {
    local name="$1"   ostype="$2"   ram="$3"   cpus="$4"
    local disk_gb="$5" iso="$6"     network="$7"
    local vdi="${VM_BASE_DIR}/${name}/${name}.vdi"

    info "Creating VM: ${name}"
    VBoxManage createvm --name "${name}" --ostype "${ostype}" --register

    VBoxManage modifyvm "${name}" \
        --memory "${ram}" \
        --cpus   "${cpus}" \
        --audio  none

    # Attach to the requested internal network (or bridged for pfSense WAN)
    if [[ "${network}" == "bridged" ]]; then
        VBoxManage modifyvm "${name}" \
            --nic1 bridged --bridgeadapter1 "${HOST_NIC}"
    else
        VBoxManage modifyvm "${name}" \
            --nic1 intnet --intnet1 "${network}"
    fi

    # Storage
    mkdir -p "${VM_BASE_DIR}/${name}"
    VBoxManage createmedium disk \
        --filename "${vdi}" \
        --size     $(( disk_gb * 1024 )) \
        --format   VDI

    VBoxManage storagectl "${name}" \
        --name       "SATA" \
        --add        sata \
        --controller IntelAhci

    VBoxManage storageattach "${name}" \
        --storagectl SATA --port 0 --device 0 \
        --type hdd --medium "${vdi}"

    # Attach ISO only if path exists
    if [[ -f "${iso}" ]]; then
        VBoxManage storageattach "${name}" \
            --storagectl SATA --port 1 --device 0 \
            --type dvddrive --medium "${iso}"
    else
        warn "ISO not found for ${name}: ${iso}"
        warn "Attach the ISO manually before first boot."
    fi

    info "VM ${name} created successfully."
}

# =============================================================================
# STEP 1 — Update host system
# =============================================================================
step1_update_host() {
    info "=== STEP 1: Updating host system ==="
    sudo apt update && sudo apt upgrade -y
}

# =============================================================================
# STEP 2 — Install VirtualBox 7.x from Oracle repository
# =============================================================================
step2_install_virtualbox() {
    info "=== STEP 2: Installing VirtualBox 7.x ==="

    # Add Oracle GPG key
    wget -q -O- https://www.virtualbox.org/download/oracle_vbox_2016.asc \
        | sudo gpg --dearmor --yes \
            --output /usr/share/keyrings/oracle-virtualbox-2016.gpg

    # Add repository
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/oracle-virtualbox-2016.gpg] \
https://download.virtualbox.org/virtualbox/debian jammy contrib" \
        | sudo tee /etc/apt/sources.list.d/virtualbox.list

    sudo apt update && sudo apt install -y virtualbox-7.0
    info "VirtualBox 7.0 installed."
}

# =============================================================================
# STEP 3 — Install VirtualBox Extension Pack
# =============================================================================
step3_install_extension_pack() {
    info "=== STEP 3: Installing VirtualBox Extension Pack ==="
    local extpack="Oracle_VM_VirtualBox_Extension_Pack-${VBX_VERSION}.vbox-extpack"
    local url="https://download.virtualbox.org/virtualbox/${VBX_VERSION}/${extpack}"

    if [[ ! -f "/tmp/${extpack}" ]]; then
        wget -q -O "/tmp/${extpack}" "${url}"
    fi

    echo "y" | sudo VBoxManage extpack install \
        --replace "/tmp/${extpack}" || \
    warn "Extension Pack install returned non-zero (may already be installed)."

    info "Extension Pack installed."
}

# =============================================================================
# STEP 4 — Add current user to vboxusers group
# =============================================================================
step4_add_user_to_vboxusers() {
    info "=== STEP 4: Adding ${USER} to vboxusers group ==="
    sudo usermod -aG vboxusers "${USER}"
    warn "Log out and back in (or run 'newgrp vboxusers') for group membership to take effect."
}

# =============================================================================
# STEP 5 — Create all VMs
# =============================================================================
step5_create_vms() {
    info "=== STEP 5: Creating all virtual machines ==="

    # ── pfSense-FW ────────────────────────────────────────────────────────────
    # WAN=bridged; additional NICs added below
    info "Creating pfSense-FW ..."
    create_vm "pfSense-FW" "FreeBSD_64" "2048" "2" "10" "${PFSENSE_ISO}" "bridged"
    VBoxManage modifyvm "pfSense-FW" \
        --nic2 intnet --intnet2 intnet-dmz \
        --nic3 intnet --intnet3 intnet-internal \
        --nic4 intnet --intnet4 intnet-mgmt \
        --nic5 intnet --intnet5 intnet-vpn

    # ── ELK-SIEM ──────────────────────────────────────────────────────────────
    create_vm "ELK-SIEM"       "Ubuntu_64"    "8192" "4" "50" "${UBUNTU_22_ISO}"         "intnet-mgmt"

    # ── Samba-AD ──────────────────────────────────────────────────────────────
    create_vm "Samba-AD"       "Ubuntu_64"    "4096" "2" "30" "${UBUNTU_22_ISO}"         "intnet-internal"

    # ── OpenVAS-Scanner ───────────────────────────────────────────────────────
    create_vm "OpenVAS-Scanner" "Ubuntu_64"   "4096" "2" "50" "${UBUNTU_22_ISO}"         "intnet-mgmt"

    # ── Cuckoo-Sandbox (Ubuntu 20.04) ─────────────────────────────────────────
    create_vm "Cuckoo-Sandbox" "Ubuntu_64"    "4096" "2" "100" "${UBUNTU_20_ISO}"        "intnet-mgmt"

    # ── Web-Server-DMZ ────────────────────────────────────────────────────────
    create_vm "Web-Server-DMZ" "Ubuntu_64"    "2048" "1" "20" "${UBUNTU_22_ISO}"         "intnet-dmz"

    # ── Workstation-W10 ───────────────────────────────────────────────────────
    create_vm "Workstation-W10" "Windows10_64" "4096" "2" "60" "${WIN10_ISO}"            "intnet-internal"

    # ── Wireshark-VM (Desktop) with promiscuous mode ──────────────────────────
    create_vm "Wireshark-VM"   "Ubuntu_64"    "2048" "1" "20" "${UBUNTU_22_DESKTOP_ISO}" "intnet-mgmt"
    VBoxManage modifyvm "Wireshark-VM" --nicpromisc1 allow-all

    info "All VMs created."
}

# =============================================================================
# STEP 6 — Verify
# =============================================================================
step6_verify() {
    info "=== STEP 6: Verifying VM inventory ==="
    VBoxManage list vms
    info "Next: Install operating systems on each VM, then proceed to session2/configure_pfsense.sh"
}

# =============================================================================
# Main
# =============================================================================
main() {
    info "============================================================"
    info "  Session 1 – Host Environment & VM Setup"
    info "============================================================"

    # Guard: must not run as root
    [[ "$(id -u)" -eq 0 ]] && error "Do NOT run this script as root."

    step1_update_host
    step2_install_virtualbox
    step3_install_extension_pack
    step4_add_user_to_vboxusers
    step5_create_vms
    step6_verify
}

main "$@"
