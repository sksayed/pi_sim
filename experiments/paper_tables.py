"""Numbers for the labelled live-evaluation tables of the journal paper.

Per traffic source and run (mean ± SD over repetitions):
  verdict flag rate   = ATTACK verdicts / verdicts
  connection rate     = connections with >= 1 ATTACK verdict / connections with >= 1 verdict
Benign traffic is split by client (steady, mixed, burst, subscriber).

Usage:  python experiments/paper_tables.py
Writes: results/analysis/paper_tables.json
"""
from __future__ import annotations

import csv
import gzip
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

from analyze import RESULTS, Labeller

OUT = RESULTS / "analysis" / "paper_tables.json"


def session_sources(session: str) -> dict:
    gw, cl = RESULTS / "gateway" / session, RESULTS / "client" / session
    gmeta = json.loads((gw / "meta.json").read_text())
    cmeta = json.loads((cl / "meta.json").read_text())
    label = Labeller(cmeta, gmeta, cl, float(gmeta["fw_settings"].get("FW_FLOW_TIMEOUT_S", 10)))
    with open(cl / "benign_conns.csv") as fh:
        port_client = {int(r["local_port"]): r["client"] for r in csv.DictReader(fh)
                       if r["local_port"] not in ("", "0")}
    verdicts = defaultdict(int)
    flagged = defaultdict(int)
    conns = defaultdict(set)
    flagged_conns = defaultdict(set)
    with gzip.open(gw / "firewall.jsonl.gz", "rt") as fh:
        for line in fh:
            e = json.loads(line)
            if e.get("event") != "verdict":
                continue
            src = label(e["client_ip"], e["client_port"], e["flow_proto"], e["nfqueue_first_wall_ns"])
            if src == "benign":
                src = "benign_" + port_client[e["client_port"]]
            conn = (e["client_ip"], e["client_port"], e["flow_proto"])
            verdicts[src] += 1
            conns[src].add(conn)
            if e["verdict"] == "ATTACK":
                flagged[src] += 1
                flagged_conns[src].add(conn)
    return {s: {"verdicts": verdicts[s], "flag_rate": flagged[s] / verdicts[s],
                "connections": len(conns[s]), "conn_rate": len(flagged_conns[s]) / len(conns[s])}
            for s in verdicts}


def main() -> None:
    per_run: dict[str, list[dict]] = defaultdict(list)
    for gw in sorted((RESULTS / "gateway").iterdir()):
        if not (gw / "meta.json").exists():
            continue
        run = json.loads((gw / "meta.json").read_text())["run"]
        per_run[run].append({"session": gw.name, "sources": session_sources(gw.name)})

    out = {}
    for run, sessions in sorted(per_run.items()):
        names = sorted({s for x in sessions for s in x["sources"]})
        out[run] = {}
        for name in names:
            row = {}
            for k in ("verdicts", "flag_rate", "connections", "conn_rate"):
                vals = [x["sources"][name][k] for x in sessions if name in x["sources"]]
                row[k] = {"mean": float(np.mean(vals)), "sd": float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0,
                          "n": len(vals)}
            out[run][name] = row
    OUT.write_text(json.dumps(out, indent=2))
    for run, rows in out.items():
        print(f"== {run}")
        for name, r in rows.items():
            print(f"  {name:22s} verdicts {r['verdicts']['mean']:7.1f}  "
                  f"flag {r['flag_rate']['mean']:.3f}±{r['flag_rate']['sd']:.3f}  "
                  f"conns {r['connections']['mean']:6.1f}  conn-rate {r['conn_rate']['mean']:.3f}±{r['conn_rate']['sd']:.3f}")
    print(f"Saved {OUT}")


if __name__ == "__main__":
    main()
