"""Stage 1 and Stage 2 timing summary for the labelled live runs.

Usage:  python experiments/timing.py
Writes: results/analysis/timing.md and timing.json
"""
from __future__ import annotations

import csv
import gzip
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

import plan

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
OUT = RESULTS / "analysis"

STAGE1 = {
    "t_inference_ns": "inference",
    "t_classify_ns": "classification",
    "t_inspection_ns": "arrival_to_verdict",
}
STAGE2 = {
    "t_encap_ns": "mlkem768_encap",
    "t_aes_enc_ns": "aes256gcm_encrypt",
    "t_sign_ns": "mldsa65_sign",
    "t_reencrypt_ns": "reencrypt_total",
    "t_recv_to_done_ns": "handler",
}


def _stats(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    a = np.asarray(values)
    return {
        "n": int(a.size),
        "mean": float(a.mean()),
        "median": float(np.median(a)),
        "p95": float(np.percentile(a, 95)),
        "p99": float(np.percentile(a, 99)),
        "max": float(a.max()),
    }


def _sessions() -> list[Path]:
    return sorted(p for p in (RESULTS / "gateway").iterdir()
                  if (p / "meta.json").exists() and plan.is_paper_session(p.name))


def main() -> None:
    stage1: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    stage2: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for sess in _sessions():
        run = json.loads((sess / "meta.json").read_text())["run"]
        with gzip.open(sess / "firewall.jsonl.gz", "rt") as fh:
            for line in fh:
                e = json.loads(line)
                if e.get("event") != "verdict":
                    continue
                for k, name in STAGE1.items():
                    # Reaper-triggered verdicts have no arrival packet and log 0.
                    if e.get(k) is not None and not (k == "t_inspection_ns" and e[k] == 0):
                        stage1[run][name].append(e[k] / 1e6)
                stage1[run]["collection_s"].append(
                    (e["t_verdict_wall_ns"] - e["nfqueue_first_wall_ns"]) / 1e9)
                stage1[run]["flow_pkts"].append(e["flow_pkts"])
        csv_path = sess / "reencrypt_metrics.csv"
        if csv_path.exists():
            with open(csv_path) as fh:
                for r in csv.DictReader(fh):
                    if r.get("pqc_available") != "True":
                        continue
                    for k, name in STAGE2.items():
                        stage2[run][name].append(int(r[k]) / 1e6)

    out = {"stage1": {}, "stage2": {}}
    for group, data in (("stage1", stage1), ("stage2", stage2)):
        all_runs: dict[str, list] = defaultdict(list)
        for run in sorted(data):
            out[group][run] = {m: _stats(v) for m, v in data[run].items()}
            for m, v in data[run].items():
                all_runs[m].extend(v)
        out[group]["all"] = {m: _stats(v) for m, v in all_runs.items()}

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "timing.json").write_text(json.dumps(out, indent=2))
    lines = ["# Timing summary (ms unless noted)", ""]
    for group in ("stage1", "stage2"):
        lines.append(f"## {group}")
        lines.append("")
        lines.append("| Run | Metric | N | Mean | Median | P95 | P99 | Max |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for run, metrics in out[group].items():
            for m, s in metrics.items():
                if s["n"]:
                    lines.append(f"| {run} | {m} | {s['n']} | {s['mean']:.3f} | {s['median']:.3f} "
                                 f"| {s['p95']:.3f} | {s['p99']:.3f} | {s['max']:.3f} |")
        lines.append("")
    (OUT / "timing.md").write_text("\n".join(lines))
    print("\n".join(lines))
    print(f"Saved {OUT / 'timing.md'} and timing.json")


if __name__ == "__main__":
    main()
