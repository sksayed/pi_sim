#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICE_NAME="mqtt_firewall"
SERVICE_FILE="$SCRIPT_DIR/mqtt_firewall.service"

echo "[1/4] Installing only required system runtime packages..."
sudo apt update
sudo apt install -y libnfnetlink-dev libnetfilter-queue-dev iptables-persistent

echo "[2/4] Skipping Python package install (already installed in .venv)."
echo "        If needed later: source \"$REPO_ROOT/.venv/bin/activate\" && pip install -r \"$REPO_ROOT/requirements.txt\""

echo "[3/4] Setting up iptables rules..."
# Intercept NEW + ESTABLISHED MQTT connections (TCP)
sudo iptables -I INPUT -p tcp --dport 1883 -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -p tcp --sport 1883 -j NFQUEUE --queue-num 0

# UDP on 1883 — needed for attack_clients/udp_flood_client.py (default UDP_FLOOD_TARGET_PORT=1883).
# If you use another port, add matching rules or NFQUEUE will not see those datagrams.
sudo iptables -I INPUT -p udp --dport 1883 -j NFQUEUE --queue-num 0
sudo iptables -I OUTPUT -p udp --sport 1883 -j NFQUEUE --queue-num 0

# Persist iptables rules across reboots
sudo netfilter-persistent save

echo "[4/4] Installing systemd service..."
sudo cp "$SERVICE_FILE" "/etc/systemd/system/${SERVICE_NAME}.service"
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"

echo "Done. Start with: sudo systemctl start $SERVICE_NAME"