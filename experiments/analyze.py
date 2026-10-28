#!/usr/bin/env python3
"""
analyze.py — Build tab:live-detect and tab:ips-effect from labelled runs.

After both Pis have pushed, pull on any machine and run:

    python experiments/analyze.py

Reads results/gateway/<session>/ and results/client/<session>/ and writes
results/analysis/summary.md and summary.json (per session and mean ± SD per run).

Flow labels (ground truth), from the client Pi's logs:
  infrastructure  client IP is the gateway itself (its own subscriber)
  benign          client Pi IP and a port recorded in benign_conns.csv
  <attack name>   client Pi IP, other port, first packet inside that attack's window
  unlabelled      client Pi IP, outside every window and not a benign port
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

import plan

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS = REPO_ROOT / "results"
WINDOW_GRACE_BEFORE_S = 1.0
IPV4 = re.compile(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$")
SPT = re.compile(r"spt:(\d+)")


def _read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _events(gw_dir: Path):
    path = gw_dir / "firewall.jsonl.gz"
    opener = gzip.open if path.exists() else open
    if not path.exists():
        path = gw_dir / "firewall.jsonl"
    if not path.exists():
        return
    with opener(path, "rt") as f:
        for line in f:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


class Labeller:
    def __init__(self, cmeta: dict, gmeta: dict, client_dir: Path, flow_timeout_s: float):
        self.client_ip = gmeta.get("client_ip") or cmeta["client_ip"]
        self.infra_ips = {"127.0.0.1", cmeta.get("gateway_ip", "")}
        self.offset = cmeta.get("clock_offset_s", 0.0)
        self.benign_ports = {int(r["local_port"]) for r in _read_csv(client_dir / "benign_conns.csv")
                             if r["local_port"] not in ("", "0")}
        self.windows = [(r["attack"], int(r["start_wall_ns"]) / 1e9, int(r["end_wall_ns"]) / 1e9)
                        for r in _read_csv(client_dir / "attack_windows.csv")]
        self.grace_after = flow_timeout_s + 5.0

    def __call__(self, ip: str, port: int, proto: int, first_ns: int) -> str:
        if ip in self.infra_ips:
            return "infrastructure"
        if ip != self.client_ip:
            return "other"
        if proto == 6 and port in self.benign_ports:
            return "benign"
        t = first_ns / 1e9 - self.offset
        for name, start, end in self.windows:
            if start - WINDOW_GRACE_BEFORE_S <= t <= end + self.grace_after:
                return name
        return "unlabelled"


def _iptables_drops(gw_dir: Path) -> list[tuple[str, int, int]]:
    """(source ip, source port, packets) for every project DROP rule."""
    path = gw_dir / "iptables_counters.txt"
    if not path.exists():
        return []
    drops = []
    for line in path.read_text().splitlines():
        tokens = line.split()
        if len(tokens) < 9 or tokens[2] != "DROP" or "pi_sim_ips_block" not in line:
            continue
        ips = [t for t in tokens[3:] if IPV4.match(t)]
        spt = SPT.search(line)
        if ips and spt and tokens[0].isdigit():
            drops.append((ips[0].split("/")[0], int(spt.group(1)), int(tokens[0])))
    return drops


def analyze_session(session: str) -> dict | None:
    gw_dir, cl_dir = RESULTS / "gateway" / session, RESULTS / "client" / session
    if not (gw_dir / "meta.json").exists() or not (cl_dir / "meta.json").exists():
        return None
    gmeta = json.loads((gw_dir / "meta.json").read_text())
    cmeta = json.loads((cl_dir / "meta.json").read_text())
    flow_timeout = float(gmeta.get("fw_settings", {}).get("FW_FLOW_TIMEOUT_S", 10))
    label = Labeller(cmeta, gmeta, cl_dir, flow_timeout)

    verdicts = defaultdict(lambda: {"verdicts": 0, "flagged": 0, "conns": set(), "unclassified": 0})
    conn_label: dict[tuple, str] = {}
    pkts_before_block: dict[tuple, int] = defaultdict(int)
    blocked_conns: dict[tuple, str] = {}
    verdict_conns: set[tuple] = set()
    cb_drops: dict[tuple, int] = defaultdict(int)

    for ev in _events(gw_dir):
        kind = ev.get("event")
        if kind == "verdict":
            conn = (ev["client_ip"], ev["client_port"], ev["flow_proto"])
            src = label(*conn, ev["nfqueue_first_wall_ns"])
            conn_label.setdefault(conn, src)
            verdict_conns.add(conn)
            v = verdicts[src]
            v["verdicts"] += 1
            v["conns"].add(conn)
            if conn not in blocked_conns:
                pkts_before_block[conn] += ev["flow_pkts"]
            if ev["verdict"] == "ATTACK":
                v["flagged"] += 1
        elif kind in ("flow_unclassified", "flow_open_at_shutdown"):
            conn = (ev["client_ip"], ev["client_port"], ev["flow_proto"])
            src = label(*conn, ev["nfqueue_first_wall_ns"])
            conn_label.setdefault(conn, src)
            verdicts[src]["unclassified"] += 1
            verdicts[src]["conns"].add(conn)
        elif kind == "block_applied":
            conn = (ev["ip"], ev["src_port"], ev["proto"])
            blocked_conns[conn] = conn_label.get(conn, "unknown")
        elif kind == "packet_dropped":
            cb_drops[(ev["src_ip"], ev["sport"], ev["proto"])] += 1

    sources = {}
    for src, v in sorted(verdicts.items()):
        sources[src] = {
            "connections": len(v["conns"]),
            "verdicts": v["verdicts"],
            "flagged": v["flagged"],
            "flag_rate": v["flagged"] / v["verdicts"] if v["verdicts"] else None,
            "unclassified_flows": v["unclassified"],
        }

    attack_names = {w[0] for w in label.windows}
    tp = sum(sources[s]["flagged"] for s in sources if s in attack_names)
    fn = sum(sources[s]["verdicts"] - sources[s]["flagged"] for s in sources if s in attack_names)
    fp = sources.get("benign", {}).get("flagged", 0)
    prf = {}
    if tp + fp:
        prf["precision"] = tp / (tp + fp)
    if tp + fn:
        prf["recall"] = tp / (tp + fn)
    if prf.get("precision") and prf.get("recall"):
        prf["f1"] = 2 * prf["precision"] * prf["recall"] / (prf["precision"] + prf["recall"])

    result = {"session": session, "run": cmeta["run"], "rep": cmeta["rep"],
              "client_ip": label.client_ip, "sources": sources, "detection": prf}

    if cmeta["run_config"].get("block"):
        sent = {(r["device_id"], r["seq"]) for r in _read_csv(cl_dir / "benign_sends.csv") if r["rc"] == "0"}
        devices = {d for d, _ in sent}
        recv = {(r["device_id"], r["seq"]) for r in _read_csv(gw_dir / "reencrypt_metrics.csv")
                if r["device_id"] in devices}
        attack_blocked = [c for c, s in blocked_conns.items() if s in attack_names]
        drops = 0
        for ip, port, pkts in _iptables_drops(gw_dir):
            if any(c[0] == ip and c[1] == port and s in attack_names for c, s in blocked_conns.items()):
                drops += pkts
        drops += sum(n for c, n in cb_drops.items() if blocked_conns.get(c) in attack_names)
        attack_conns = [c for c, s in conn_label.items() if s in attack_names]
        never = sum(1 for c in attack_conns if c not in verdict_conns)
        result["ips"] = {
            "benign_sent": len(sent),
            "benign_received_by_stage2": len(sent & recv),
            "benign_delivery_ratio": len(sent & recv) / len(sent) if sent else None,
            "attack_pkts_before_block_mean": (statistics.mean(pkts_before_block[c] for c in attack_blocked)
                                              if attack_blocked else None),
            "attack_pkts_dropped": drops,
            "attack_connections_never_classified": never,
            "attack_connections": len(attack_conns),
            "benign_connections_blocked": sum(1 for s in blocked_conns.values() if s == "benign"),
            "infrastructure_connections_blocked": sum(1 for s in blocked_conns.values() if s == "infrastructure"),
        }
    return result


def _mean_sd(values: list[float]) -> str:
    values = [v for v in values if v is not None]
    if not values:
        return "--"
    m = statistics.mean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    return f"{m:.3f} ± {sd:.3f} (n={len(values)})"


def summarize(results: list[dict]) -> str:
    by_run = defaultdict(list)
    for r in results:
        by_run[r["run"]].append(r)
    lines = ["# Labelled live evaluation", ""]
    for run in sorted(by_run):
        reps = by_run[run]
        lines += [f"## {run} ({len(reps)} repetition(s))", "",
                  "| Source | Connections | Verdicts | Flagged | Flag rate | Unclassified |",
                  "|---|---|---|---|---|---|"]
        for src in sorted({s for r in reps for s in r["sources"]}):
            rows = [r["sources"].get(src, {}) for r in reps]
            lines.append("| " + " | ".join([src] + [_mean_sd([x.get(k) for x in rows]) for k in
                         ("connections", "verdicts", "flagged", "flag_rate", "unclassified_flows")]) + " |")
        det = [r["detection"] for r in reps]
        if any(det):
            lines += ["", "Precision / recall / F1: " + " / ".join(
                _mean_sd([d.get(k) for d in det]) for k in ("precision", "recall", "f1"))]
        if all("ips" in r for r in reps):
            lines += ["", "| IPS metric | Value |", "|---|---|"]
            for k in reps[0]["ips"]:
                lines.append(f"| {k} | {_mean_sd([r['ips'][k] for r in reps])} |")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--all", action="store_true", help="include development trials, not only plan.PAPER_REPS")
    args = parser.parse_args()
    sessions = sorted(p.name for p in (RESULTS / "gateway").glob("R*_rep*")
                      if p.is_dir() and (args.all or plan.is_paper_session(p.name)))
    results = [r for r in (analyze_session(s) for s in sessions) if r]
    if not results:
        print("No complete sessions found (need results/gateway/<s>/ and results/client/<s>/).")
        return 1
    out = RESULTS / "analysis"
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(results, indent=2, default=list))
    md = summarize(results)
    (out / "summary.md").write_text(md)
    print(md)
    print(f"Saved {out}/summary.md and summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
