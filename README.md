# Quantum IoT — MQTT Encryption Simulation

A multi-node simulation across Raspberry Pi 4 devices where each client Pi
encrypts sensor data with a different cryptographic scheme before sending it
to a Gateway Pi over MQTT. The Gateway decrypts every message and prints
the original plaintext.

---

## Architecture

```
Pi A (client-a)  ──AES-256-GCM──────────────────────────────┐
Pi B (client-b)  ──Kyber-512 + AES-256-GCM ─────────────────┤  MQTT / WiFi
Pi C (client-c)  ──Kyber-768 + Dilithium-3 + AES-256-GCM ───┤
                                                              ▼
                                               Pi G (Gateway)
                                               Mosquitto broker
                                               + gateway.py (decrypt & print)
```

All keys are derived from a single `MASTER_SECRET` via HKDF-SHA256. No key
material is ever transmitted over the network.

---

## Clients at a Glance

| Pi  | Script           | Scheme                                  | Topic                  |
|-----|------------------|-----------------------------------------|------------------------|
| A   | client/client_a.py | AES-256-GCM                           | nodes/client-a/data    |
| B   | client/client_b.py | Kyber-512 KEM + AES-256-GCM           | nodes/client-b/data    |
| C   | client/client_c.py | Kyber-768 KEM + Dilithium-3 + AES-GCM | nodes/client-c/data    |
| G   | gateway/gateway.py | Decryption router (all three)          | nodes/+/data           |

---

## Project Structure

```
pi_sim/
├── client/
│   ├── base_client.py       # shared MQTT connect / publish loop
│   ├── client_a.py          # AES-256-GCM
│   ├── client_b.py          # Kyber-512 + AES-256-GCM
│   └── client_c.py          # Kyber-768 + AES-256-GCM + Dilithium-3
├── gateway/
│   └── gateway.py           # unified subscriber + decryption router
├── shared/
│   ├── topics.py            # MQTT topic constants
│   └── key_manager.py       # HKDF derivation + pyoqs wrappers
├── .env                     # secrets — gitignored, same file on every Pi
├── .env.example             # template committed to the repo
├── client_requirements.txt
├── gateway_requirements.txt
└── README.md
```

---

## Prerequisites

### 1. Install Mosquitto on the Gateway Pi

```bash
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
```

### 2. Install Python dependencies

On each **Client Pi**:
```bash
pip install -r client_requirements.txt
```

On the **Gateway Pi**:
```bash
pip install -r gateway_requirements.txt
```

### 3. (Optional) Install liboqs for real post-quantum crypto

Without this the code runs in **simulation mode** — the MQTT pipeline, AES
encryption, and replay protection all work, but Kyber/Dilithium use
deterministic stubs instead of real PQC.

```bash
sudo apt install -y cmake ninja-build libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs
cmake -GNinja -DBUILD_SHARED_LIBS=ON .
ninja
sudo ninja install
sudo ldconfig
cd ..
pip install pyoqs
```

---

## Configuration

Copy `.env.example` to `.env` on **every Pi** and fill in the same values:

```bash
cp .env.example .env
nano .env
```

Minimum required fields:

```ini
MASTER_SECRET=<64-char hex — same on all Pis>
GATEWAY_IP=<IP of the Gateway Pi>    # run `hostname -I` on the Gateway Pi
GATEWAY_PORT=1883
PUBLISH_INTERVAL=2
```

Generate a secret:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Running

### Step 1 — Gateway Pi: verify Mosquitto, then start the gateway

```bash
sudo systemctl start mosquitto        # ensure broker is up
python gateway/gateway.py
```

### Step 2 — Client Pis (one script per Pi)

```bash
# Pi A
python client/client_a.py

# Pi B
python client/client_b.py

# Pi C
python client/client_c.py
```

All three clients can run simultaneously; the Gateway handles all of them.

---

## Expected Output

### Gateway terminal

```
[GATEWAY] Crypto mode : SIMULATION (no pyoqs)
[GATEWAY] Replay protection : enabled (per-device seq tracking)
[GATEWAY] Connecting to broker at 192.168.1.10:1883 …
[GATEWAY] Connected to broker at 192.168.1.10:1883
[GATEWAY] Subscribed to: nodes/+/data
[GATEWAY] ACCEPTED  device=client-a  crypto=AES-256-GCM
          payload → Temperature reading #1: 20.1 C
[GATEWAY] ACCEPTED  device=client-b  crypto=Kyber512-AES-GCM
          payload → Humidity reading #1: 55.2 %RH
[GATEWAY] ACCEPTED  device=client-c  crypto=Kyber768-Dilithium3-AES-GCM
          payload → Pressure reading #1: 1013.30 hPa
```

### Client A terminal

```
[CLIENT-A] Crypto: AES-256-GCM
[CLIENT-A] Connecting to 192.168.1.10:1883 …
[CLIENT-A] Connected to broker at 192.168.1.10:1883
[CLIENT-A] Published seq=1 to 'nodes/client-a/data'
[CLIENT-A] Delivered (mid=1)
```

---

## Security Notes

| Feature | Detail |
|---|---|
| Key derivation | HKDF-SHA256 from a single MASTER_SECRET |
| AES | AES-256-GCM with a fresh 12-byte random nonce per message |
| KEM | Kyber-512 / Kyber-768 (CRYSTALS-Kyber, NIST PQC round 3 winner) |
| Signatures | Dilithium-3 (CRYSTALS-Dilithium, NIST PQC round 3 winner) |
| Replay protection | Per-device monotonic sequence number checked on the Gateway |
| `.env` | Never committed to git; contains all secrets |
