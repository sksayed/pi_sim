"""
live_segments.py — Rebuild the firewall's classified flow segments from a session log.

Replays the packet_parsed events in results/gateway/<session>/firewall.jsonl.gz
with the same triggers as firewall/mqtt_firewall.py (FIN/RST, every N packets,
idle timeout) and returns one row of cic_features per segment the firewall
would have classified. Sessions logged before TTL was recorded use TTL 64.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "firewall"))

import cic_features  # noqa: E402


def _settings(session_dir: Path) -> tuple[int, int, float]:
    meta = json.loads((session_dir / "meta.json").read_text())
    fw = meta.get("fw_settings", {})
    return (int(fw.get("FW_MIN_PKTS_CLASSIFY", 3)), int(fw.get("FW_CLASSIFY_EVERY_N_PKTS", 20)),
            float(fw.get("FW_FLOW_TIMEOUT_S", 10)))


def replay(session_dir: Path) -> pd.DataFrame:
    min_pkts, every_n, idle_s = _settings(session_dir)
    flows: dict[tuple, dict] = {}
    rows: list[dict] = []
    last_sweep = 0.0

    def close(key: tuple) -> None:
        f = flows.pop(key)
        if len(f["lens"]) < min_pkts:
            return
        feats = cic_features.compute(f["proto"], f["sp"], f["dp"], f["lens"], f["ttls"], f["flags"],
                                     f["ts"], f["hdr"], f["fwd"], f["bwd"])
        broker_side = f["sp"] == 1883 and f["dp"] != 1883
        rows.append({
            "client_ip": f["dst"] if broker_side else f["src"],
            "client_port": f["dp"] if broker_side else f["sp"],
            "proto": f["proto"],
            "first_ts": f["ts"][0],
            **feats,
        })

    with gzip.open(session_dir / "firewall.jsonl.gz", "rt") as fh:
        for line in fh:
            e = json.loads(line)
            if e.get("event") != "packet_parsed":
                continue
            ts = e["ts"]
            if ts - last_sweep >= 1.0:
                for k in [k for k, f in flows.items() if ts - f["ts"][-1] > idle_s]:
                    close(k)
                last_sweep = ts
            fwd = (e["src_ip"], e["dst_ip"], e["sport"], e["dport"], e["proto"])
            bwd = (e["dst_ip"], e["src_ip"], e["dport"], e["sport"], e["proto"])
            key, is_fwd = (fwd, True) if fwd in flows else ((bwd, False) if bwd in flows else (fwd, True))
            if key not in flows:
                flows[key] = {"src": key[0], "dst": key[1], "sp": key[2], "dp": key[3], "proto": key[4],
                              "lens": [], "ttls": [], "flags": [], "ts": [], "hdr": [], "fwd": 0, "bwd": 0}
            f = flows[key]
            f["lens"].append(e["payload_len"] + e["hdr_len"] + cic_features.ETH_HEADER_BYTES)
            f["ttls"].append(e.get("ttl", 64))
            f["flags"].append(e["flags"])
            f["ts"].append(ts)
            f["hdr"].append(e["hdr_len"])
            f["fwd" if is_fwd else "bwd"] += 1
            n = len(f["lens"])
            if e["flags"] & 0x05:
                if n >= min_pkts:
                    close(key)
            elif n >= every_n:
                close(key)
    for k in list(flows):
        close(k)
    return pd.DataFrame(rows)
