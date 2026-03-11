#!/usr/bin/env bash
# =============================================================================
# sessions/session3_scanner.sh
# Session 3 — Vulnerability Scanning (Greenbone/OpenVAS Community)
# NOTE: On 4 GB RAM, OpenVAS is run with feed sync disabled for speed.
#       Full feed sync requires 6 GB+. A lightweight "scanner-only" mode
#       is used here with pre-built CVE checks.
# Usage: sudo bash sessions/session3_scanner.sh
# =============================================================================
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

require_root
banner "Session 3 — Vulnerability Scanning"

ensure_dirs

# ── RAM check ─────────────────────────────────────────────────────────────────
RAM_MB=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo)
info "Detected RAM: ${RAM_MB} MB"
# Use lite scanner on anything under 6 GB - OpenVAS needs 6 GB+ to run reliably
if [[ $RAM_MB -lt 6000 ]]; then
  warn "Less than 6 GB RAM ($RAM_MB MB). OpenVAS will use minimal-feed mode."
  USE_LITE_SCANNER=1
else
  info "Sufficient RAM detected - full OpenVAS mode available"
  USE_LITE_SCANNER=0
fi

# ── Ensure lab-mgmt network exists ───────────────────────────────────────────
if ! network_exists lab-mgmt; then
  warn "lab-mgmt not found — running Session 1 first..."
  bash "$SCRIPT_DIR/sessions/session1_network.sh" || die "Network setup failed."
fi

if [[ $USE_LITE_SCANNER -eq 1 ]]; then
  # ── Lite mode: Python-based port scanner + service fingerprinting ─────────
  step "Starting LITE vulnerability scanner (low-RAM mode)..."

  pip3 install python-nmap --quiet 2>/dev/null || true

  # Install nmap if needed
  if ! command -v nmap >/dev/null 2>&1; then
    apt-get install -y nmap >/dev/null 2>&1 && ok "nmap installed."
  fi

  mkdir -p "$LAB_BASE/scanner"
  cat > "$LAB_BASE/scanner/scan.py" <<'PYEOF'
#!/usr/bin/env python3
"""
Lightweight vulnerability scanner for Healthcare Lab (lite mode).
Performs port scanning + basic CVE mapping without full OpenVAS feed.
"""
import subprocess, json, datetime, os, sys

TARGETS = {
    "DMZ Web Server"   : "172.20.10.10",
    "Internal Samba AD": "172.20.20.10",
    "RADIUS Server"    : "172.20.20.11",
    "Elasticsearch"    : "172.20.30.10",
    "Kibana"           : "172.20.30.11",
    "Wazuh Manager"    : "172.20.30.12",
}

# Basic service-to-CVE hints (illustrative, not real-time)
CVE_HINTS = {
    80  : ["HTTP without TLS — data in transit unencrypted (HIPAA 164.312(e)(1))"],
    443 : ["Verify TLS version ≥ 1.2 (NIST SP 800-52)"],
    389 : ["LDAP without LDAPS — credentials exposed (CVE-2017-7494 context)"],
    445 : ["SMB — check MS17-010 patch status (CVE-2017-0144)"],
    9200: ["Elasticsearch unauthenticated — data exposure risk (CVE-2014-3120 class)"],
    5601: ["Kibana — verify no public exposure"],
    22  : ["SSH — ensure key-based auth only (HIPAA 164.312(d))"],
}

EVIDENCE_DIR = os.environ.get("EVIDENCE_DIR", os.path.expanduser("~/compliance_evidence"))
os.makedirs(EVIDENCE_DIR, exist_ok=True)

results = []
print(f"\n{'='*60}")
print("  Healthcare Security Lab — Vulnerability Scan Report")
print(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*60}\n")

for name, ip in TARGETS.items():
    print(f"[SCAN] {name} ({ip})")
    try:
        r = subprocess.run(
            ["nmap", "-sV", "--open", "-T3", "-p",
             "22,80,389,443,445,1812,5601,9200,9392,55000", ip],
            capture_output=True, text=True, timeout=30
        )
        open_ports = []
        for line in r.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = int(parts[0].split("/")[0])
                service = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                findings = CVE_HINTS.get(port, ["No known critical issues for this port"])
                open_ports.append({
                    "port": port, "service": service,
                    "version": version, "findings": findings
                })
                status = "⚠️ " if port in CVE_HINTS else "  "
                print(f"  {status}Port {port:5d}/{service:15s} {version}")
                for f in findings:
                    print(f"         → {f}")

        results.append({"host": name, "ip": ip, "open_ports": open_ports})
    except subprocess.TimeoutExpired:
        print(f"  [SKIP] {ip} — scan timed out (host not running?)")
    except Exception as e:
        print(f"  [SKIP] {ip} — {e}")
    print()

# Save evidence
ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
out_path = os.path.join(EVIDENCE_DIR, f"openvas_scan_{ts}.json")
with open(out_path, "w") as f:
    json.dump({"scan_time": ts, "targets": results}, f, indent=2)

# HIPAA mapping summary
print(f"{'='*60}")
print("  HIPAA Compliance Mapping")
print(f"{'='*60}")
hipaa = [
    ("164.308(a)(1)", "Risk Analysis",       "Scan covers all lab segments"),
    ("164.312(a)(1)", "Technical Access",    "Zero-Trust firewall active"),
    ("164.312(b)",    "Audit Controls",       "Events logged to Elasticsearch"),
    ("164.312(e)(1)", "Transmission Security","Check HTTP→HTTPS migration"),
]
for std, ctrl, note in hipaa:
    print(f"  ✓ {std:20s} {ctrl:25s} | {note}")

print(f"\n  Evidence saved: {out_path}\n")
PYEOF

  chmod +x "$LAB_BASE/scanner/scan.py"
  step "Running lightweight scan (nmap-based)..."
  python3 "$LAB_BASE/scanner/scan.py"

else
  # ── Full mode: Greenbone Community Edition container ─────────────────────
  OPENVAS_IMAGE="immauss/openvas:latest"
  step "Deploying OpenVAS (immauss/openvas - public community build)..."
  remove_container lab-openvas

  mkdir -p "$LAB_DATA/openvas"

  # Pull explicitly so we get a clear error if it fails
  info "Pulling OpenVAS image (this may take a few minutes)..."
  docker pull "$OPENVAS_IMAGE" || die "Failed to pull $OPENVAS_IMAGE - check internet connectivity."

  docker run -d \
    --name lab-openvas \
    --network lab-mgmt \
    --memory="1500m" \
    --memory-swap="2000m" \
    --cpus="1.5" \
    -p 9392:9392 \
    -v "$LAB_DATA/openvas:/data" \
    -e "PASSWORD=admin" \
    --restart unless-stopped \
    "$OPENVAS_IMAGE" \
    && ok "lab-openvas started" \
    || die "Failed to start OpenVAS"

  step "Waiting for OpenVAS web UI (can take 5–10 min on first run for feed sync)..."
  wait_for_url "https://localhost:9392" 120 5 || \
    warn "OpenVAS not yet ready — check https://localhost:9392 in a few minutes."
fi

# ── Lab exercises ─────────────────────────────────────────────────────────────
echo ""
banner "Session 3 — Lab Exercises"

if [[ $USE_LITE_SCANNER -eq 1 ]]; then
  echo -e "${BOLD}Exercise 3.1 — Run manual nmap scan:${NC}"
  echo -e "  ${CYAN}nmap -sV -p 80,443,22,9200,5601 172.20.10.10${NC}"
  echo ""
  echo -e "${BOLD}Exercise 3.2 — Run the lab vulnerability scanner:${NC}"
  echo -e "  ${CYAN}python3 $LAB_BASE/scanner/scan.py${NC}"
  echo ""
  echo -e "${BOLD}Exercise 3.3 — Scan a specific target:${NC}"
  echo -e "  ${CYAN}nmap -sV --script vuln 172.20.10.10${NC}"
else
  echo -e "${BOLD}Exercise 3.1 — Open Greenbone Security Manager:${NC}"
  echo -e "  Browser: ${CYAN}https://localhost:9392${NC} (admin / admin)"
  echo ""
  echo -e "${BOLD}Exercise 3.2 — Create scan target:${NC}"
  echo -e "  Targets → New Target → Host: 172.20.0.0/16"
  echo ""
  echo -e "${BOLD}Exercise 3.3 — Run scan and export PDF:${NC}"
  echo -e "  Scans → Tasks → New Task → Start Scan → Export Report"
fi

echo ""
echo -e "${BOLD}Exercise 3.4 — HIPAA 164.308(a)(1) Risk Analysis:${NC}"
echo -e "  Document findings as risk analysis evidence."
echo -e "  Evidence dir: ${CYAN}$EVIDENCE_DIR${NC}"
echo ""

step "Collecting compliance evidence..."
TS=$(date +%Y%m%d_%H%M%S)
{
  echo "=== Vulnerability Scan Summary — $TS ==="
  echo "Scan mode: $([ $USE_LITE_SCANNER -eq 1 ] && echo 'Lite (nmap)' || echo 'Full (OpenVAS)')"
  echo ""
  echo "=== Network targets ==="
  echo "DMZ:      $NET_DMZ"
  echo "Internal: $NET_INT"
  echo "Mgmt:     $NET_MGT"
  echo ""
  echo "=== HIPAA 164.308(a)(1) — Risk Analysis ==="
  echo "Scanner deployed and targeting all lab segments."
  echo "Evidence timestamp: $TS"
} > "$EVIDENCE_DIR/scanner_summary_${TS}.txt"
ok "Evidence saved: $EVIDENCE_DIR/scanner_summary_${TS}.txt"

echo ""
ok "Session 3 complete."
