# Pi MQTT Simulation

A minimal two-node MQTT simulation designed to run across two Raspberry Pi 4 devices on the same WiFi network.

| Device | Role | Script |
|---|---|---|
| Pi #1 | MQTT Publisher (Client) | `client/client.py` |
| Pi #2 | MQTT Broker + Subscriber (Gateway) | `gateway/gateway.py` |

---

## Prerequisites

Both Pis must be on the same WiFi network and have Python 3.7+ installed.

### On Pi #2 (Gateway) — install Mosquitto broker

```bash
sudo apt update
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto
sudo systemctl start mosquitto
```

### On both Pis — install Python dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:

```ini
GATEWAY_IP=192.168.1.XX     # IP address of Pi #2
GATEWAY_PORT=1883
CLIENT_ID=pi-client-01
MQTT_TOPIC=pi/sensor/data
PUBLISH_INTERVAL=2          # seconds between publishes
```

> Find Pi #2's IP with: `hostname -I`

---

## Running

### Step 1 — On Pi #2 (Gateway)

```bash
python gateway/gateway.py
```

### Step 2 — On Pi #1 (Client)

```bash
python client/client.py
```

---

## Expected Output

**Pi #2 (Gateway)**
```
[GATEWAY] Connecting to broker at 192.168.1.XX:1883 …
[GATEWAY] Connected to broker at 192.168.1.XX:1883
[GATEWAY] Subscribed to topic: pi/sensor/data
[GATEWAY] Received on 'pi/sensor/data': {"client_id": "pi-client-01", "sequence": 1, ...}
[GATEWAY] Received on 'pi/sensor/data': {"client_id": "pi-client-01", "sequence": 2, ...}
```

**Pi #1 (Client)**
```
[CLIENT] Connecting to broker at 192.168.1.XX:1883 …
[CLIENT] Connected to broker at 192.168.1.XX:1883
[CLIENT] Published to 'pi/sensor/data': {"client_id": "pi-client-01", "sequence": 1, ...}
[CLIENT] Message delivered (mid=1)
```

---

## Project Structure

```
pi_sim/
├── client/
│   └── client.py          # MQTT publisher
├── gateway/
│   └── gateway.py         # MQTT subscriber
├── shared/
│   └── topics.py          # Shared topic constants
├── .env                   # Local config (gitignored)
├── .env.example           # Config template
├── requirements.txt
└── README.md
```
