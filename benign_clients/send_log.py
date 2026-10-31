"""
send_log.py — Optional ground-truth logging for benign clients.

Enabled only when BENIGN_LOG_DIR is set (experiments/client_runner.py sets it).
Rows are appended to CSV files whose headers the runner writes beforehand:

  benign_conns.csv  ts_unix_ns,client,device_id,local_ip,local_port
  benign_sends.csv  ts_unix_ns,client,device_id,seq,qos,rc,msg_id
"""

from __future__ import annotations

import os
import time
from pathlib import Path

_LOG_DIR = os.getenv("BENIGN_LOG_DIR", "")


def _append(name: str, fields: list) -> None:
    if not _LOG_DIR:
        return
    line = ",".join(str(f) for f in fields) + "\n"
    with open(Path(_LOG_DIR) / name, "a", encoding="utf-8") as f:
        f.write(line)


def log_connect(client_name: str, device_id: str, mqtt_client) -> None:
    try:
        local_ip, local_port = mqtt_client.socket().getsockname()[:2]
    except Exception:
        local_ip, local_port = "", 0
    _append("benign_conns.csv", [time.time_ns(), client_name, device_id, local_ip, local_port])


def log_send(client_name: str, device_id: str, seq: int, qos: int, rc: int,
             msg_id: str = "") -> None:
    _append("benign_sends.csv", [time.time_ns(), client_name, device_id, seq, qos, rc, msg_id])
