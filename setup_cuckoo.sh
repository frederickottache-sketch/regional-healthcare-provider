#!/usr/bin/env bash
# =============================================================================
# SESSION 4: Firewalls, IDS/IPS, and Advanced Malware Defence
# Goal   : Deploy Cuckoo Sandbox on the Cuckoo-Sandbox VM
#          (Ubuntu 20.04, VLAN 30 – 10.0.30.30)
#
# RUN ON: Cuckoo-Sandbox VM as a regular user with sudo privileges
#         NOTE: Ubuntu 20.04 is required for Cuckoo compatibility
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

CUCKOO_USER="cuckoo"
CUCKOO_WEB_PORT="8000"
CUCKOO_HOST_ONLY_IP="192.168.56.1"   # VirtualBox Host-Only adapter IP
ANALYSIS_VM_IP="192.168.56.101"       # Windows 10 guest IP
ANALYSIS_VM_NAME="cuckoo1"
MGMT_IP="10.0.30.30"

# =============================================================================
# STEP 1 — System update and core dependencies
# =============================================================================
step1_install_dependencies() {
    step "=== STEP 1: Installing core dependencies ==="
    sudo apt update && sudo apt upgrade -y

    sudo apt install -y \
        python3 python3-pip python3-venv python3-dev \
        tcpdump libcap2-bin \
        mongodb \
        libffi-dev \
        libssl-dev \
        libjpeg-dev \
        zlib1g-dev \
        swig \
        build-essential \
        git \
        virtualbox

    # Grant tcpdump raw-packet capture capability without root
    sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
    info "Dependencies installed."
}

# =============================================================================
# STEP 2 — Create dedicated cuckoo user
# =============================================================================
step2_create_cuckoo_user() {
    step "=== STEP 2: Creating 'cuckoo' user ==="

    if id "${CUCKOO_USER}" &>/dev/null; then
        warn "User '${CUCKOO_USER}' already exists — skipping creation."
    else
        sudo adduser --disabled-password --gecos "" "${CUCKOO_USER}"
        info "User '${CUCKOO_USER}' created."
    fi

    sudo usermod -aG vboxusers "${CUCKOO_USER}"
    info "User '${CUCKOO_USER}' added to vboxusers."
}

# =============================================================================
# STEP 3 — Install Cuckoo as the cuckoo user
# =============================================================================
step3_install_cuckoo() {
    step "=== STEP 3: Installing Cuckoo Sandbox (as cuckoo user) ==="

    sudo -u "${CUCKOO_USER}" bash -lc '
        set -euo pipefail
        # Upgrade pip first
        pip3 install --upgrade pip setuptools wheel

        # Install Cuckoo and its Python dependencies
        pip3 install cuckoo

        echo "Cuckoo installed successfully."
    '
}

# =============================================================================
# STEP 4 — Initialise Cuckoo working directory and download community sigs
# =============================================================================
step4_init_cuckoo() {
    step "=== STEP 4: Initialising Cuckoo and downloading community signatures ==="

    sudo -u "${CUCKOO_USER}" bash -lc '
        set -euo pipefail
        cuckoo init
        cuckoo community
        echo "Cuckoo initialised."
    '
}

# =============================================================================
# STEP 5 — Configure virtualbox.conf
# =============================================================================
step5_configure_virtualbox_conf() {
    step "=== STEP 5: Configuring Cuckoo virtualbox.conf ==="

    local conf_file="/home/${CUCKOO_USER}/.cuckoo/conf/virtualbox.conf"

    if [[ ! -f "${conf_file}" ]]; then
        warn "Cuckoo working directory not found. Did step 4 succeed?"
        return 1
    fi

    sudo -u "${CUCKOO_USER}" bash -c "
        cat > '${conf_file}' <<'CONF'
[virtualbox]
# Specify which VirtualBox machines will be used
machines = ${ANALYSIS_VM_NAME}

# Specify the path to the VBoxManage executable
vboxmanage = /usr/bin/VBoxManage

# Maximum wait time for VM power-on (seconds)
timeout = 300

# Path to the Cuckoo agent that runs inside the analysis VM
# The agent.py file should be placed in the guest at startup
[${ANALYSIS_VM_NAME}]
# VM label in VirtualBox
label = ${ANALYSIS_VM_NAME}

# Guest operating system
platform = windows

# IP address of the guest OS on the Host-Only network
ip = ${ANALYSIS_VM_IP}

# Name of the clean snapshot to revert to before each analysis
snapshot = Snapshot1

# Interface for network monitoring (leave blank to auto-detect)
interface =
CONF
"
    info "virtualbox.conf written."
}

# =============================================================================
# STEP 6 — Print Windows Guest VM setup instructions
# =============================================================================
step6_print_guest_instructions() {
    step "=== STEP 6: Windows 10 Analysis VM Setup Instructions ==="

    cat <<'EOF'

  Complete these steps INSIDE VirtualBox (running as the cuckoo user):
  ─────────────────────────────────────────────────────────────────────────────
  1. Start VirtualBox:
       su - cuckoo
       virtualbox &

  2. Create a new VM named "cuckoo1":
       Type: Windows, Version: Windows 10 (64-bit)
       RAM: 2048 MB   CPUs: 2   Disk: 50 GB (dynamic)

  3. Network Adapter:
       Adapter 1 → Host-Only Adapter → select vboxnet0 (or create one at
       VirtualBox → File → Host Network Manager)
       Set guest IP to 192.168.56.101/24; gateway 192.168.56.1

  4. Install Windows 10 (trial ISO):
       Attach Windows 10 ISO → boot → install

  5. Harden the guest for analysis:
       a. Disable Windows Update (Services → Windows Update → Disabled)
       b. Disable screensaver and sleep (Power Options → Never)
       c. Disable Windows Defender real-time protection
       d. Install Python 2.7 (required for Cuckoo agent)
          → https://www.python.org/ftp/python/2.7.18/python-2.7.18.amd64.msi

  6. Install and start Cuckoo Agent:
       On the HOST (as cuckoo user):
         pip3 show cuckoo | grep Location
         # Copy agent.py from <cuckoo_location>/cuckoo/data/agent/agent.py
         # Transfer it to the Windows guest (e.g., via shared folder)
       On the Windows GUEST:
         Place agent.py in C:\Python27\
         Configure it to start on boot:
           taskschd.msc → Create Task → Action: python C:\Python27\agent.py

  7. Take the "Snapshot1" snapshot:
       Power off the VM → Machine → Take Snapshot → Name: Snapshot1

  8. Verify Cuckoo can reach the guest:
       As cuckoo user on host:
         cuckoo -d       ← debug mode, check for VM connectivity errors
  ─────────────────────────────────────────────────────────────────────────────
EOF
}

# =============================================================================
# STEP 7 — Create Cuckoo service scripts
# =============================================================================
step7_create_service_scripts() {
    step "=== STEP 7: Creating Cuckoo startup scripts ==="

    # Daemon launcher
    cat << 'EOF' | sudo tee /usr/local/bin/cuckoo-start.sh > /dev/null
#!/usr/bin/env bash
# Start Cuckoo daemon and web interface as the cuckoo user
set -euo pipefail

CUCKOO_USER="cuckoo"
LOG_DIR="/var/log/cuckoo"
sudo mkdir -p "${LOG_DIR}"
sudo chown "${CUCKOO_USER}:${CUCKOO_USER}" "${LOG_DIR}"

echo "Starting Cuckoo daemon..."
sudo -u "${CUCKOO_USER}" bash -lc \
    "cuckoo > ${LOG_DIR}/cuckoo-daemon.log 2>&1 &"

sleep 3

echo "Starting Cuckoo web interface on 0.0.0.0:8000 ..."
sudo -u "${CUCKOO_USER}" bash -lc \
    "cuckoo web runserver 0.0.0.0:8000 > ${LOG_DIR}/cuckoo-web.log 2>&1 &"

echo "Cuckoo started. Web UI: http://$(hostname -I | awk '{print $1}'):8000"
EOF
    sudo chmod +x /usr/local/bin/cuckoo-start.sh

    # Stop script
    cat << 'EOF' | sudo tee /usr/local/bin/cuckoo-stop.sh > /dev/null
#!/usr/bin/env bash
echo "Stopping Cuckoo processes..."
sudo pkill -f "cuckoo web" 2>/dev/null || true
sudo pkill -f "cuckoo"     2>/dev/null || true
echo "Cuckoo stopped."
EOF
    sudo chmod +x /usr/local/bin/cuckoo-stop.sh

    info "Scripts created: /usr/local/bin/cuckoo-start.sh and cuckoo-stop.sh"
}

# =============================================================================
# STEP 8 — Test with EICAR file
# =============================================================================
step8_test_eicar() {
    step "=== STEP 8: Creating EICAR test file for sandbox validation ==="

    # NOTE: Run this AFTER cuckoo-start.sh and after the Windows guest is ready
    local eicar_path="/tmp/eicar.com"

    # The EICAR string must be exact — write via printf to avoid shell expansion
    printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
        > "${eicar_path}"

    warn "EICAR file created at ${eicar_path}"
    warn "To submit to Cuckoo (run AFTER starting Cuckoo and the analysis VM):"
    echo ""
    echo "  su - cuckoo"
    echo "  cuckoo submit ${eicar_path}"
    echo ""
    warn "Reports are generated at: /home/${CUCKOO_USER}/.cuckoo/storage/analyses/<task_id>/"
    warn "Browse to http://${MGMT_IP}:${CUCKOO_WEB_PORT} to view results."
}

# =============================================================================
# STEP 9 — Cuckoo API usage example
# =============================================================================
step9_api_example() {
    step "=== STEP 9: Cuckoo REST API example ==="

    cat <<'EOF'

  Automate Cuckoo submissions via Python (runs from any Management VM):
  ─────────────────────────────────────────────────────────────────────────────
  #!/usr/bin/env python3
  import requests, sys, json

  CUCKOO_API = "http://10.0.30.30:8080"   # Cuckoo API port (default 8090)

  def submit_file(path):
      with open(path, "rb") as f:
          resp = requests.post(
              f"{CUCKOO_API}/tasks/create/file",
              files={"file": (path, f)},
              timeout=30
          )
      data = resp.json()
      print(f"Submitted task ID: {data['task_id']}")
      return data["task_id"]

  def get_report(task_id):
      resp = requests.get(
          f"{CUCKOO_API}/tasks/report/{task_id}",
          timeout=60
      )
      return resp.json()

  if __name__ == "__main__":
      tid = submit_file(sys.argv[1])
      print(f"Task {tid} queued. Check http://10.0.30.30:8000 for results.")
  ─────────────────────────────────────────────────────────────────────────────
  Usage:  python3 submit_to_cuckoo.py /path/to/suspicious.exe
EOF
}

# =============================================================================
# Main
# =============================================================================
main() {
    info "============================================================"
    info "  Session 4 – Cuckoo Sandbox: Advanced Malware Defence"
    info "============================================================"

    [[ "$(id -u)" -eq 0 ]] && { \
        warn "Running as root — some steps will still su to '${CUCKOO_USER}'."; }

    step1_install_dependencies
    step2_create_cuckoo_user
    step3_install_cuckoo
    step4_init_cuckoo
    step5_configure_virtualbox_conf
    step6_print_guest_instructions
    step7_create_service_scripts
    step8_test_eicar
    step9_api_example

    info "Session 4 complete."
    info "Start Cuckoo: sudo /usr/local/bin/cuckoo-start.sh"
    info "Web UI:  http://${MGMT_IP}:${CUCKOO_WEB_PORT}"
    info "Proceed to session5/ for ELK Stack + Wazuh SIEM setup."
}

main "$@"
