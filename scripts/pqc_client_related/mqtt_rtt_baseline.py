#!/usr/bin/env python3
"""
Measure MQTT broker + gateway echo latency without cryptography.

Requires gateway/gateway.py running (subscribes to benchmark/rtt/request and
replies on benchmark/rtt/reply with t_gateway_recv_ns).

Usage (repo root):
  python scripts/mqtt_rtt_baseline.py
  python scripts/mqtt_rtt_baseline.py -n 50
  python scripts/mqtt_rtt_baseline.py -n 50 -o /path/to/custom.csv

By default writes ``benchmarks/client/mqtt_rtt_samples.csv`` (creates the file with a
header even when no replies arrive, so the path exists for the analyzer).
Use ``--no-out`` to skip writing any CSV.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv

_REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=_REPO_ROOT / ".env")

GATEWAY_IP = os.getenv("GATEWAY_IP", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", 1883))
RTT_REQUEST_TOPIC = "benchmark/rtt/request"
RTT_REPLY_TOPIC = "benchmark/rtt/reply"
DEFAULT_RTT_CSV = _REPO_ROOT / "benchmarks" / "client" / "mqtt_rtt_samples.csv"
_RTT_CSV_HEADER = ["ts_unix_ns", "rtt_ns", "t_client_send_ns", "t_client_recv_ns"]


def _ensure_rtt_csv(path: Path, samples: list[tuple[int, int, int]]) -> None:
    """Append RTT rows, adding a header if the file is new/empty; if no samples, create header-only when missing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if samples:
        need_header = not path.exists() or path.stat().st_size == 0
        with path.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if need_header:
                w.writerow(_RTT_CSV_HEADER)
            for rtt, t0, t1 in samples:
                w.writerow([t1, rtt, t0, t1])
        return
    if not path.exists():
        with path.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(_RTT_CSV_HEADER)


def main() -> int:
    p = argparse.ArgumentParser(description="MQTT RTT baseline (no crypto)")
    p.add_argument("-n", "--count", type=int, default=20)
    p.add_argument(
        "-o",
        "--out",
        type=Path,
        default=DEFAULT_RTT_CSV,
        help=(
            "CSV path (default: benchmarks/client/mqtt_rtt_samples.csv under the repo root). "
            "Header-only file is created when there are no replies."
        ),
    )
    p.add_argument(
        "--no-out",
        action="store_true",
        help="Do not write a CSV file (measurement + console only).",
    )
    args = p.parse_args()

    samples: list[tuple[int, int, int]] = []  # rtt_ns, t_client_send, t_client_recv
    ev = threading.Event()
    last_rtt: list[int | None] = [None]

    def on_msg(c, ud, m):
        try:
            body = json.loads(m.payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        t_recv = time.time_ns()
        t_send = int(body.get("t_client_send_ns", 0))
        if t_send:
            last_rtt[0] = t_recv - t_send
        ev.set()

    cid = f"rtt-{uuid.uuid4().hex[:8]}"
    client = mqtt.Client(client_id=cid, clean_session=True)

    def on_connect(c, ud, flags, rc):
        if rc == 0:
            c.subscribe(RTT_REPLY_TOPIC, qos=0)

    client.on_connect = on_connect
    client.on_message = on_msg

    try:
        client.connect(GATEWAY_IP, GATEWAY_PORT, keepalive=30)
    except Exception as exc:
        print(f"Connect failed: {exc}", file=sys.stderr)
        if not args.no_out:
            _ensure_rtt_csv(args.out, [])
            print(
                f"CSV: header-only (broker unreachable) → {args.out.resolve()}",
                file=sys.stderr,
            )
        return 1

    client.loop_start()
    time.sleep(0.3)

    for i in range(args.count):
        ev.clear()
        last_rtt[0] = None
        t0 = time.time_ns()
        payload = json.dumps(
            {"run_id": uuid.uuid4().hex, "seq": i, "t_client_send_ns": t0},
            separators=(",", ":"),
        )
        client.publish(RTT_REQUEST_TOPIC, payload, qos=0)
        if not ev.wait(timeout=5.0):
            print(f"Sample {i}: timeout", file=sys.stderr)
            continue
        if last_rtt[0] is not None:
            rtt = last_rtt[0]
            t1 = time.time_ns()
            samples.append((rtt, t0, t1))
            print(f"  sample {i+1}/{args.count}: RTT ≈ {rtt/1e6:.3f} ms (wall, needs clock sync for accuracy)")

    client.loop_stop()
    client.disconnect()

    if samples:
        rs = [s[0] for s in samples]
        mean = sum(rs) / len(rs)
        print(f"\nSummary: n={len(rs)}  mean_RTT={mean/1e6:.3f} ms  min={min(rs)/1e6:.3f} ms  max={max(rs)/1e6:.3f} ms")
        print("Note: RTT uses client wall clock; for crypto E2E use analyzer ts_unix_ns delta on matched rows.")
    else:
        print(
            "\nNo RTT samples (timeouts or no gateway echo on benchmark/rtt/reply). "
            "Ensure gateway/gateway.py is running.",
            file=sys.stderr,
        )

    if not args.no_out:
        _ensure_rtt_csv(args.out, samples)
        if samples:
            print(f"CSV: wrote {len(samples)} rows → {args.out.resolve()}")
        else:
            print(
                f"CSV: header-only (no data rows) → {args.out.resolve()}",
                file=sys.stderr,
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
