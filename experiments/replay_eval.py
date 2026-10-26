"""
replay_eval.py — Offline what-if evaluation of Stage 1 rules on recorded sessions.

Replays packet_parsed events of results/gateway/<session>/firewall.jsonl.gz with
the firewall's segment triggers, labels each segment with the ground truth used
by analyze.py, and classifies it with the deployed model under a feature mode:

  both    features over all packets of the segment (deployed behaviour)
  client  features over client-to-broker packets only

It also applies a blocking rule offline: a connection is blocked after K
consecutive attack verdicts (K=1 is the deployed rule). Replay cannot model how
blocking changes later traffic, so IPS numbers from IDS sessions are estimates.

Usage:  python experiments/replay_eval.py --sessions R1_rep1,R3_rep1 --mode both,client --k 1,2
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np

from analyze import RESULTS, REPO_ROOT, Labeller

sys.path.insert(0, str(REPO_ROOT / "firewall"))
import cic_features  # noqa: E402

BROKER_PORT = 1883
FW_DIR = REPO_ROOT / "firewall"


class Model:
    def __init__(self, class_names: list[str], threshold: float):
        self.booster = lgb.Booster(model_file=str(FW_DIR / "lightgbm_model.txt"))
        self.scaler = joblib.load(FW_DIR / "standard_scaler.pkl")
        self.columns = json.loads((FW_DIR / "feature_columns.json").read_text())
        self.benign_idx = class_names.index("Benign")
        self.threshold = threshold

    def is_attack(self, rows: list[dict]) -> np.ndarray:
        x = np.array([[r[c] for c in self.columns] for r in rows], dtype=np.float32)
        p = self.booster.predict(self.scaler.transform(x))
        return (p.argmax(axis=1) != self.benign_idx) & (p[:, self.benign_idx] < 1.0 - self.threshold)


def segments(session_dir: Path, mode: str, min_pkts: int, every_n: int, idle_s: float) -> list[dict]:
    """Classified segments in arrival order, with features for `mode`."""
    flows: dict[tuple, dict] = {}
    out: list[dict] = []
    last_sweep = 0.0

    def close(key: tuple) -> None:
        f = flows.pop(key)
        if len(f["pkts"]) < min_pkts:
            return
        pk = [p for p in f["pkts"] if p["c2b"]] if mode == "client" else f["pkts"]
        if not pk:
            return
        feats = cic_features.compute(f["proto"], f["sp"], f["dp"], [p["len"] for p in pk],
                                     [p["ttl"] for p in pk], [p["flags"] for p in pk],
                                     [p["ts"] for p in pk], [p["hdr"] for p in pk], len(pk), 0)
        broker_side = f["sp"] == BROKER_PORT and f["dp"] != BROKER_PORT
        out.append({
            "client_ip": f["dst"] if broker_side else f["src"],
            "client_port": f["dp"] if broker_side else f["sp"],
            "proto": f["proto"],
            "first_ts": f["pkts"][0]["ts"],
            "pkts": len(f["pkts"]),
            "client_pkts": sum(p["c2b"] for p in f["pkts"]),
            **feats,
        })

    with gzip.open(session_dir / "firewall.jsonl.gz", "rt") as fh:
        for line in fh:
            e = json.loads(line)
            if e.get("event") != "packet_parsed":
                continue
            ts = e["ts"]
            if ts - last_sweep >= 1.0:
                for k in [k for k, f in flows.items() if ts - f["pkts"][-1]["ts"] > idle_s]:
                    close(k)
                last_sweep = ts
            fwd = (e["src_ip"], e["dst_ip"], e["sport"], e["dport"], e["proto"])
            bwd = (e["dst_ip"], e["src_ip"], e["dport"], e["sport"], e["proto"])
            key = fwd if fwd in flows else (bwd if bwd in flows else fwd)
            if key not in flows:
                flows[key] = {"src": key[0], "dst": key[1], "sp": key[2], "dp": key[3],
                              "proto": key[4], "pkts": []}
            f = flows[key]
            f["pkts"].append({
                "len": e["payload_len"] + e["hdr_len"] + cic_features.ETH_HEADER_BYTES,
                "ttl": e.get("ttl", 64), "flags": e["flags"], "ts": ts, "hdr": e["hdr_len"],
                "c2b": e["dport"] == BROKER_PORT,
            })
            n = len(f["pkts"])
            if e["flags"] & 0x05:
                if n >= min_pkts:
                    close(key)
            elif n >= every_n:
                close(key)
    for k in list(flows):
        close(k)
    return out


def evaluate(session: str, mode: str, ks: list[int]) -> dict:
    gw, cl = RESULTS / "gateway" / session, RESULTS / "client" / session
    gmeta = json.loads((gw / "meta.json").read_text())
    cmeta = json.loads((cl / "meta.json").read_text())
    fw = gmeta["fw_settings"]
    label = Labeller(cmeta, gmeta, cl, float(fw.get("FW_FLOW_TIMEOUT_S", 10)))
    model = Model(fw["FW_CLASS_NAMES"].split(","), float(fw.get("FW_ATTACK_THRESHOLD", 0.5)))
    segs = segments(gw, mode, int(fw.get("FW_MIN_PKTS_CLASSIFY", 3)),
                    int(fw.get("FW_CLASSIFY_EVERY_N_PKTS", 20)), float(fw.get("FW_FLOW_TIMEOUT_S", 10)))
    flags = model.is_attack(segs) if segs else np.array([], dtype=bool)
    attack_names = {w[0] for w in label.windows}

    per_source = defaultdict(lambda: [0, 0])
    per_conn = defaultdict(list)
    for s, a in zip(segs, flags):
        cmeta_offset_ns = int(s["first_ts"] * 1e9)
        src = label(s["client_ip"], s["client_port"], s["proto"], cmeta_offset_ns)
        per_source[src][0] += 1
        per_source[src][1] += int(a)
        per_conn[(s["client_ip"], s["client_port"], s["proto"], src)].append((bool(a), s["pkts"]))

    tp = sum(per_source[s][1] for s in per_source if s in attack_names)
    fn = sum(per_source[s][0] - per_source[s][1] for s in per_source if s in attack_names)
    fp = per_source["benign"][1]
    tn = per_source["benign"][0] - fp
    total = tp + fn + fp + tn
    result = {
        "session": session, "mode": mode,
        "sources": {s: {"verdicts": v, "flagged": f, "flag_rate": f / v if v else None}
                    for s, (v, f) in sorted(per_source.items())},
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "accuracy": (tp + tn) / total if total else None,
        "blocking": {},
    }
    for k in ks:
        blocked = defaultdict(int)
        before = []
        for (ip, port, proto, src), seq in per_conn.items():
            run, pkts = 0, 0
            for a, n in seq:
                pkts += n
                run = run + 1 if a else 0
                if run >= k:
                    kind = "attack" if src in attack_names else src
                    blocked[kind] += 1
                    if kind == "attack":
                        before.append(pkts)
                    break
        result["blocking"][k] = {
            "attack_conns": sum(1 for c in per_conn if c[3] in attack_names),
            "blocked": dict(blocked),
            "attack_pkts_before_block_mean": float(np.mean(before)) if before else None,
        }
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", required=True)
    ap.add_argument("--mode", default="both")
    ap.add_argument("--k", default="1")
    args = ap.parse_args()
    ks = [int(k) for k in args.k.split(",")]
    for session in args.sessions.split(","):
        for mode in args.mode.split(","):
            r = evaluate(session, mode, ks)
            p, rc, acc = r["precision"], r["recall"], r["accuracy"]
            fmt = lambda v: "--" if v is None else f"{v:.3f}"
            print(f"== {session} mode={mode}  precision {fmt(p)}  recall {fmt(rc)}  accuracy {fmt(acc)}")
            for s, v in r["sources"].items():
                print(f"   {s:20s} verdicts {v['verdicts']:5d}  flagged {v['flagged']:5d}  rate {fmt(v['flag_rate'])}")
            for k, b in r["blocking"].items():
                print(f"   block after {k} in a row: attack conns {b['attack_conns']}, blocked {b['blocked']}, "
                      f"attack pkts before block {fmt(b['attack_pkts_before_block_mean'])}")


if __name__ == "__main__":
    main()
