#!/usr/bin/env python3
"""
parse_end_to_end_report.py — End-to-end pipeline report.

Combines firewall detection stats + gateway PQC re-encryption metrics
into a single paper-ready report covering the full flow on the gateway host:

    Client → network → NFQUEUE (firewall) → TCP/MQTT stack → Broker →
    gateway.py subscribe → PQC re-encrypt → cloud-ready

WAN delay appears only if CSV rows include t_broker_transit_ns (see
GW_REENCRYPT_LOG_WAN_TRANSIT in benign_pipeline.py). Firewall verdict
timings are flow-level JSONL events, not 1:1 with each MQTT PUBLISH.

Sections:
    1. Traffic Summary
    2. Firewall Performance  (detection rate + timing per attack type)
    3. Gateway PQC Re-encryption Timing
    4. Path Latency (non-overlapping WAN + gateway means; crypto subset note)

Data sources:
    Firewall_logs/mqtt_firewall.jsonl     firewall verdict + timing events
    benchmarks/gateway/reencrypt_metrics.csv  gateway re-encryption metrics

Output:
    benchmarks/end_to_end_report.md   Markdown report
    Console summary
    Optional CSV  --csv <path>
    Optional PDF  --pdf  (requires weasyprint + markdown)

Usage:
    python scripts/parse_end_to_end_report.py
    python scripts/parse_end_to_end_report.py --no-pdf
    python scripts/parse_end_to_end_report.py --since 3600
    python scripts/parse_end_to_end_report.py --csv benchmarks/e2e_stats.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

# ── Paths ──────────────────────────────────────────────────────────────────────
FW_JSONL        = Path(os.getenv("FW_JSONL_FILE",
                    str(_REPO_ROOT / "Firewall_logs" / "mqtt_firewall.jsonl")))
REENCRYPT_CSV   = Path(os.getenv("GW_REENCRYPT_CSV_PATH",
                    str(_REPO_ROOT / "benchmarks" / "gateway" / "reencrypt_metrics.csv")))
REPORT_MD       = _REPO_ROOT / "benchmarks" / "end_to_end_report.md"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_std(vals: list[float]) -> float:
    if len(vals) < 2:
        return 0.0
    mean = sum(vals) / len(vals)
    return math.sqrt(sum((v - mean) ** 2 for v in vals) / (len(vals) - 1))


def _safe_p95(vals: list[float]) -> float:
    """Linear interpolation at the 95th percentile (same idea as parse_gateway_reencrypt)."""
    if not vals:
        return 0.0
    s = sorted(vals)
    pos = (len(s) - 1) * 0.95
    lo = int(pos)
    hi = min(int(pos) + 1, len(s) - 1)
    return s[lo] + (pos - lo) * (s[hi] - s[lo])


def _pct(n: int, total: int) -> str:
    return f"{n/total*100:.1f}%" if total else "n/a"

def _ms(ns: float) -> float:
    return ns / 1e6

def _fmt(v: float, decimals: int = 3) -> str:
    return f"{v:.{decimals}f} ms"


def _path_latency_mean_ms(gw_agg: dict) -> float:
    """Coherent client→handler-done mean: WAN μ + gateway handler μ when WAN is logged, else handler only."""
    if not gw_agg:
        return 0.0
    tr_m, gw_m = gw_agg["transit"]["mean"], gw_agg["total_gw"]["mean"]
    return (tr_m + gw_m) if gw_agg["transit"]["n"] > 0 else gw_m


# ── Firewall data loader ───────────────────────────────────────────────────────

def load_firewall(since_ts: float = 0.0) -> dict:
    """Parse firewall JSONL and return aggregated stats."""
    verdicts: list[dict] = []
    packets  = 0

    if not FW_JSONL.exists():
        return {"verdicts": [], "packets": 0}

    with FW_JSONL.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = ev.get("ts", 0.0)
            if since_ts and ts < since_ts:
                continue
            event = ev.get("event", "")
            if event == "packet_parsed":
                packets += 1
            elif event == "verdict":
                verdicts.append(ev)

    return {"verdicts": verdicts, "packets": packets}


def aggregate_firewall(fw: dict) -> dict:
    verdicts = fw["verdicts"]
    if not verdicts:
        return {
            "total_verdicts": 0,
            "attack_verdicts": 0,
            "benign_verdicts": 0,
            "packets": fw["packets"],
            "by_type": {},
            "ts_min": 0,
            "ts_max": 0,
            "t_inference_all": [],
            "t_classify_all": [],
        }

    attack_v = [v for v in verdicts if v.get("verdict") == "ATTACK"]
    benign_v = [v for v in verdicts if v.get("verdict") != "ATTACK"]

    by_type: dict[str, dict] = defaultdict(lambda: {
        "count": 0,
        "t_inference": [],
        "t_classify": [],
        "t_inspect": [],
        "confidence": [],
    })

    t_inf_all: list[float] = []
    t_cls_all: list[float] = []

    for v in verdicts:
        label = v.get("attack_type", "benign") if v.get("verdict") == "ATTACK" else "benign"
        entry = by_type[label]
        entry["count"] += 1

        t_inf = v.get("t_inference_ns", 0)
        t_cls = v.get("t_classify_ns", 0)
        t_ins = v.get("t_inspection_ns", 0)
        conf  = v.get("attack_prob", 0.0) if v.get("verdict") == "ATTACK" else 0.0

        if t_inf:
            entry["t_inference"].append(_ms(t_inf))
            t_inf_all.append(_ms(t_inf))
        if t_cls:
            entry["t_classify"].append(_ms(t_cls))
            t_cls_all.append(_ms(t_cls))
        if t_ins:
            entry["t_inspect"].append(_ms(t_ins))
        if conf:
            entry["confidence"].append(conf)

    ts_vals = [v["ts"] for v in verdicts if "ts" in v]

    return {
        "total_verdicts":  len(verdicts),
        "attack_verdicts": len(attack_v),
        "benign_verdicts": len(benign_v),
        "packets":         fw["packets"],
        "by_type":         dict(by_type),
        "ts_min":          min(ts_vals) if ts_vals else 0,
        "ts_max":          max(ts_vals) if ts_vals else 0,
        "t_inference_all": t_inf_all,
        "t_classify_all":  t_cls_all,
    }


# ── Gateway re-encryption data loader ─────────────────────────────────────────

def load_reencrypt(since_ts: float = 0.0) -> list[dict]:
    if not REENCRYPT_CSV.exists():
        return []
    rows = []
    with REENCRYPT_CSV.open(newline="") as f:
        for row in csv.DictReader(f):
            ts_ns = int(row.get("ts_unix_ns", 0))
            if since_ts and ts_ns / 1e9 < since_ts:
                continue
            rows.append(row)
    return rows


def aggregate_reencrypt(rows: list[dict]) -> dict:
    if not rows:
        return {}

    def _ns(key: str) -> list[float]:
        return [_ms(int(r[key])) for r in rows if int(r.get(key, 0)) > 0]

    transit    = _ns("t_broker_transit_ns")
    encap      = _ns("t_encap_ns")
    aes        = _ns("t_aes_enc_ns")
    sign       = _ns("t_sign_ns")
    reencrypt  = _ns("t_reencrypt_ns")
    # One row per message — include all handler durations so n == len(rows).
    total_gw   = [_ms(int(r["t_recv_to_done_ns"])) for r in rows]

    ts_vals = [int(r["ts_unix_ns"]) / 1e9 for r in rows]
    kems = list({r["kem"] for r in rows})
    sigs = list({r["sig"] for r in rows})

    def _stat(vals: list[float]) -> dict:
        if not vals:
            return {"n": 0, "mean": 0, "std": 0, "p95": 0, "min": 0, "max": 0}
        s = sorted(vals)
        n = len(s)
        mean = sum(s) / n
        return {
            "n":    n,
            "mean": mean,
            "std":  _safe_std(vals),
            "p95":  _safe_p95(vals),
            "min":  min(s),
            "max":  max(s),
        }

    return {
        "total":     len(rows),
        "kem":       ", ".join(kems),
        "sig":       ", ".join(sigs),
        "pqc_real":  any(r.get("pqc_available", "False") == "True" for r in rows),
        "ts_min":    min(ts_vals) if ts_vals else 0,
        "ts_max":    max(ts_vals) if ts_vals else 0,
        "transit":   _stat(transit),
        "encap":     _stat(encap),
        "aes":       _stat(aes),
        "sign":      _stat(sign),
        "reencrypt": _stat(reencrypt),
        "total_gw":  _stat(total_gw),
    }


# ── Console report ─────────────────────────────────────────────────────────────

def print_console_report(fw_agg: dict, gw_agg: dict) -> None:
    sep = "─" * 72

    print(f"\n{sep}")
    print("  END-TO-END PIPELINE REPORT")
    print(sep)

    # Traffic summary
    total_v   = fw_agg.get("total_verdicts", 0)
    attack_v  = fw_agg.get("attack_verdicts", 0)
    benign_v  = fw_agg.get("benign_verdicts", 0)
    gw_total  = gw_agg.get("total", 0)
    pkts      = fw_agg.get("packets", 0)

    ts_min = min(
        t for t in [fw_agg.get("ts_min", 0), gw_agg.get("ts_min", 0)] if t
    ) if (fw_agg.get("ts_min") or gw_agg.get("ts_min")) else 0
    ts_max = max(
        t for t in [fw_agg.get("ts_max", 0), gw_agg.get("ts_max", 0)] if t
    ) if (fw_agg.get("ts_max") or gw_agg.get("ts_max")) else 0

    def _fmt_ts(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S") if ts else "—"

    print(f"\n  §1 TRAFFIC SUMMARY")
    print(f"  {'Observation window':<35} {_fmt_ts(ts_min)} → {_fmt_ts(ts_max)}")
    print(f"  {'Packets intercepted by firewall':<35} {pkts:,}")
    print(f"  {'Flow verdicts issued':<35} {total_v:,}")
    print(f"  {'  Attack flows detected':<35} {attack_v:,}  ({_pct(attack_v, total_v)})")
    print(f"  {'  Benign flows':<35} {benign_v:,}  ({_pct(benign_v, total_v)})")
    print(f"  {'Benign messages re-encrypted':<35} {gw_total:,}")
    print(f"  {'PQC algorithm (gateway)':<35} {gw_agg.get('kem','—')} + {gw_agg.get('sig','—')}")
    print(f"  {'PQC mode':<35} {'Real liboqs' if gw_agg.get('pqc_real') else 'Simulation'}")

    # Firewall performance
    print(f"\n  §2 FIREWALL PERFORMANCE — PER ATTACK TYPE")
    print(f"  {'Attack Type':<28} {'N':>5}  {'Det.Rate':>9}  {'Infer μ':>9}  {'Classify μ':>11}  {'Inspect μ':>10}")
    print(f"  {'-'*28} {'-'*5}  {'-'*9}  {'-'*9}  {'-'*11}  {'-'*10}")

    by_type = fw_agg.get("by_type", {})
    for label in sorted(by_type.keys(), key=lambda x: (x == "benign", x)):
        entry = by_type[label]
        n     = entry["count"]
        t_inf = entry["t_inference"]
        t_cls = entry["t_classify"]
        t_ins = entry["t_inspect"]
        conf  = entry["confidence"]
        det   = f"{sum(conf)/len(conf)*100:.1f}%" if conf else "—"
        inf_m = f"{sum(t_inf)/len(t_inf):.3f} ms" if t_inf else "—"
        cls_m = f"{sum(t_cls)/len(t_cls):.3f} ms" if t_cls else "—"
        ins_m = f"{sum(t_ins)/len(t_ins):.3f} ms" if t_ins else "—"
        print(f"  {label:<28} {n:>5}  {det:>9}  {inf_m:>9}  {cls_m:>11}  {ins_m:>10}")

    t_inf_all = fw_agg.get("t_inference_all", [])
    t_cls_all = fw_agg.get("t_classify_all", [])
    inf_ov = f"{sum(t_inf_all)/len(t_inf_all):.3f} ms" if t_inf_all else "—"
    cls_ov = f"{sum(t_cls_all)/len(t_cls_all):.3f} ms" if t_cls_all else "—"
    print(f"  {'Overall':<28} {total_v:>5}  {'':>9}  {inf_ov:>9}  {cls_ov:>11}  {'':>10}")

    # Gateway timing
    if gw_agg:
        print(f"\n  §3 GATEWAY PQC RE-ENCRYPTION TIMING")
        rows = [
            ("WAN transit (optional, client clock)", gw_agg["transit"]),
            ("KEM encapsulate",                      gw_agg["encap"]),
            ("AES-256-GCM encrypt",                 gw_agg["aes"]),
            ("Signature sign",                      gw_agg["sign"]),
            ("Total re-encrypt (KEM+AES+Sign)",     gw_agg["reencrypt"]),
            ("On-device gateway (on_message→done)", gw_agg["total_gw"]),
        ]
        print(f"  {'Stage':<35} {'N':>5}  {'Mean':>9}  {'Std':>9}  {'P95':>9}  {'Min':>9}  {'Max':>9}")
        print(f"  {'-'*35} {'-'*5}  {'-'*9}  {'-'*9}  {'-'*9}  {'-'*9}  {'-'*9}")
        for label, s in rows:
            print(
                f"  {label:<35} {s['n']:>5}  "
                f"{_fmt(s['mean']):>9}  {_fmt(s['std']):>9}  "
                f"{_fmt(s['p95']):>9}  {_fmt(s['min']):>9}  {_fmt(s['max']):>9}"
            )

    # §4 — non-overlapping path means + informational crypto subset
    if gw_agg:
        tr_n = gw_agg["transit"]["n"]
        tr   = gw_agg["transit"]["mean"]
        gw   = gw_agg["total_gw"]["mean"]
        re   = gw_agg["reencrypt"]["mean"]
        enc  = gw_agg["encap"]["mean"]
        aes  = gw_agg["aes"]["mean"]
        sgn  = gw_agg["sign"]["mean"]
        ov   = max(gw - re, 0.0)
        inf_fw = sum(t_inf_all) / len(t_inf_all) if t_inf_all else 0.0

        if tr_n:
            path_total = tr + gw
            print(f"\n  §4 PATH LATENCY (non-overlapping means — client stamp → handler done)")
            print(f"  {'Stage':<40} {'Mean (ms)':>10}  {'Share':>7}")
            print(f"  {'-'*40} {'-'*10}  {'-'*7}")
            print(f"  {'WAN transit (client clock → gateway recv)':<40} {tr:>10.3f}  {f'{tr/path_total*100:.1f}%':>7}")
            print(f"  {'Gateway handler (on_message → re-enc done)':<40} {gw:>10.3f}  {f'{gw/path_total*100:.1f}%':>7}")
            print(f"  {'─'*40} {'─'*10}  {'─'*7}")
            print(f"  {'Sum (= approx. client→handler wall budget)':<40} {path_total:>10.3f}  {'100.0%':>7}")
        else:
            path_total = gw
            print(f"\n  §4 PATH LATENCY (on-gateway only — WAN not in CSV)")
            print(f"  {'Stage':<40} {'Mean (ms)':>10}  {'Share':>7}")
            print(f"  {'-'*40} {'-'*10}  {'-'*7}")
            print(f"  {'Gateway handler (on_message → re-enc done)':<40} {gw:>10.3f}  {'100.0%':>7}")
            print(f"  (Set GW_REENCRYPT_LOG_WAN_TRANSIT=1 to log WAN column.)")

        print(f"\n  §4b INSIDE GATEWAY HANDLER (informational — KEM/AES/sign ⊆ re-encrypt ⊆ GW)")
        print(f"  {'Component':<40} {'Mean (ms)':>10}")
        print(f"  {'-'*40} {'-'*10}")
        print(f"  {'KEM encapsulate':<40} {enc:>10.3f}")
        print(f"  {'AES-256-GCM encrypt':<40} {aes:>10.3f}")
        print(f"  {'Signature sign':<40} {sgn:>10.3f}")
        print(f"  {'Timed re-encrypt (sum of above)':<40} {re:>10.3f}")
        print(f"  {'Approx. rest of handler (keys, parse, …)':<40} {ov:>10.3f}")
        print(f"\n  Firewall LightGBM infer μ (flow verdicts, not per MQTT msg): {inf_fw:.3f} ms")
        print(f"  Note: Packets are accepted before classification; slow inference can delay later NFQUEUE work.")

    print(f"\n{sep}\n")


# ── Markdown builder ───────────────────────────────────────────────────────────

def build_markdown(fw_agg: dict, gw_agg: dict) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _fmt_ts(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S") if ts else "—"

    total_v   = fw_agg.get("total_verdicts", 0)
    attack_v  = fw_agg.get("attack_verdicts", 0)
    benign_v  = fw_agg.get("benign_verdicts", 0)
    gw_total  = gw_agg.get("total", 0)
    pkts      = fw_agg.get("packets", 0)

    ts_min = min(t for t in [fw_agg.get("ts_min", 0), gw_agg.get("ts_min", 0)] if t) \
             if (fw_agg.get("ts_min") or gw_agg.get("ts_min")) else 0
    ts_max = max(t for t in [fw_agg.get("ts_max", 0), gw_agg.get("ts_max", 0)] if t) \
             if (fw_agg.get("ts_max") or gw_agg.get("ts_max")) else 0

    kem = gw_agg.get("kem", "—")
    sig = gw_agg.get("sig", "—")
    pqc_mode = "Real liboqs" if gw_agg.get("pqc_real") else "Simulation"

    t_inf_all = fw_agg.get("t_inference_all", [])
    t_cls_all = fw_agg.get("t_classify_all", [])
    inf_ov = f"{sum(t_inf_all)/len(t_inf_all):.3f}" if t_inf_all else "—"
    cls_ov = f"{sum(t_cls_all)/len(t_cls_all):.3f}" if t_cls_all else "—"

    lines: list[str] = []

    lines += [
        "# End-to-End Pipeline Report",
        "",
        f"**Generated:** {now}  ",
        f"**Pipeline:** Client → network → NFQUEUE (firewall) → broker → `gateway.py` (PQC re-encrypt) → cloud-ready  ",
        f"**Source:** `mqtt_firewall.jsonl` + `reencrypt_metrics.csv`  ",
        "",
        "---",
        "",
        "## 1. Traffic Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Observation window | {_fmt_ts(ts_min)} → {_fmt_ts(ts_max)} |",
        f"| Packets intercepted by firewall | {pkts:,} |",
        f"| Flow verdicts issued | {total_v:,} |",
        f"| Attack flows detected | {attack_v:,} ({_pct(attack_v, total_v)}) |",
        f"| Benign flows | {benign_v:,} ({_pct(benign_v, total_v)}) |",
        f"| Benign messages re-encrypted | {gw_total:,} |",
        f"| PQC algorithm (gateway) | `{kem}` + `{sig}` |",
        f"| PQC mode | {pqc_mode} |",
        "",
    ]

    # Firewall performance
    lines += [
        "## 2. Firewall Performance — Per Attack Type",
        "",
        "> **Det. Rate** = mean model confidence on attack-classified flows.  "
        "**Infer** = `model.predict()` only.  "
        "**Classify** = feature extraction + inference + decision.  "
        "**Inspect** = packet arrival → verdict (inline only).",
        "",
        "| Attack Type | N | Det. Rate | Infer μ (ms) | Infer σ (ms) | Classify μ (ms) | Classify σ (ms) | Inspect μ (ms) |",
        "|-------------|---|-----------|--------------|--------------|-----------------|-----------------|----------------|",
    ]

    by_type = fw_agg.get("by_type", {})
    for label in sorted(by_type.keys(), key=lambda x: (x == "benign", x)):
        entry = by_type[label]
        n     = entry["count"]
        t_inf = entry["t_inference"]
        t_cls = entry["t_classify"]
        t_ins = entry["t_inspect"]
        conf  = entry["confidence"]
        det   = f"{sum(conf)/len(conf)*100:.1f}%" if conf else "—"
        inf_m = f"{sum(t_inf)/len(t_inf):.3f}" if t_inf else "—"
        inf_s = f"{_safe_std(t_inf):.3f}" if len(t_inf) > 1 else "—"
        cls_m = f"{sum(t_cls)/len(t_cls):.3f}" if t_cls else "—"
        cls_s = f"{_safe_std(t_cls):.3f}" if len(t_cls) > 1 else "—"
        ins_m = f"{sum(t_ins)/len(t_ins):.3f}" if t_ins else "—"
        lines.append(f"| {label} | {n} | {det} | {inf_m} | {inf_s} | {cls_m} | {cls_s} | {ins_m} |")

    lines += [
        f"| **Overall** | {total_v} | | {inf_ov} | | {cls_ov} | | |",
        "",
    ]

    # Gateway timing
    if gw_agg:
        lines += [
            "## 3. Gateway PQC Re-Encryption Timing",
            "",
            f"> KEM: `{kem}` &nbsp;|&nbsp; Signature: `{sig}` &nbsp;|&nbsp; PQC mode: {pqc_mode}",
            "",
            "| Stage | N | Mean (ms) | Std (ms) | P95 (ms) | Min (ms) | Max (ms) |",
            "|-------|---|-----------|----------|----------|----------|----------|",
        ]
        rows = [
            ("WAN transit (optional, client clock)", gw_agg["transit"]),
            ("KEM encapsulate",                      gw_agg["encap"]),
            ("AES-256-GCM encrypt",                 gw_agg["aes"]),
            ("Signature sign",                      gw_agg["sign"]),
            ("Total re-encrypt (KEM+AES+Sign)",     gw_agg["reencrypt"]),
            ("On-device gateway (on_message→done)", gw_agg["total_gw"]),
        ]
        for label, s in rows:
            lines.append(
                f"| {label} | {s['n']} | {s['mean']:.3f} | {s['std']:.3f} | "
                f"{s['p95']:.3f} | {s['min']:.3f} | {s['max']:.3f} |"
            )
        lines.append("")

    # §4 — path latency (additive) + inside-handler breakdown (informational)
    if gw_agg:
        tr_n = gw_agg["transit"]["n"]
        tr   = gw_agg["transit"]["mean"]
        gw   = gw_agg["total_gw"]["mean"]
        re   = gw_agg["reencrypt"]["mean"]
        enc  = gw_agg["encap"]["mean"]
        aes  = gw_agg["aes"]["mean"]
        sgn  = gw_agg["sign"]["mean"]
        ov   = max(gw - re, 0.0)
        inf_fw = sum(t_inf_all) / len(t_inf_all) if t_inf_all else 0.0
        path_total = _path_latency_mean_ms(gw_agg)

        lines += [
            "## 4. Path Latency (means)",
            "",
            "> **Non-overlapping segment means** along the benign path. "
            "WAN uses the client’s `t_publish_ns` vs gateway `time.time_ns()` (clock skew possible). "
            "Gateway handler = `t_recv_to_done_ns` (includes key setup, JSON routing, and timed KEM/AES/sign). "
            "Firewall verdict timings are **flow-level** (JSONL), not joined per MQTT message.",
            "",
        ]

        if tr_n:
            p_tr = tr + gw
            s_tr = f"{tr/p_tr*100:.1f}%" if p_tr else "—"
            s_gw = f"{gw/p_tr*100:.1f}%" if p_tr else "—"
            lines += [
                "| Segment | Mean (ms) | Share of WAN+handler |",
                "|---------|-----------|----------------------|",
                f"| WAN transit (client clock → gateway recv) | {tr:.3f} | {s_tr} |",
                f"| Gateway handler (on_message → re-enc done) | {gw:.3f} | {s_gw} |",
                f"| **Sum (client → handler complete, approx.)** | **{path_total:.3f}** | **100%** |",
                "",
            ]
        else:
            lines += [
                "| Segment | Mean (ms) | Note |",
                "|---------|-----------|------|",
                f"| Gateway handler (on_message → re-enc done) | {gw:.3f} | WAN column zero — set `GW_REENCRYPT_LOG_WAN_TRANSIT=1` to log WAN |",
                "",
            ]

        lines += [
            "### Inside gateway handler (informational)",
            "",
            "> Sub-stages are **subset** of the handler row above (KEM+AES+sign timings ⊆ re-encrypt ⊆ full handler). "
            "Do **not** add these to WAN to form a second “E2E” — use the **Sum** row in the table above.",
            "",
            "| Component | Mean (ms) |",
            "|-----------|-----------|",
            f"| KEM encapsulate | {enc:.3f} |",
            f"| AES-256-GCM encrypt | {aes:.3f} |",
            f"| Signature sign | {sgn:.3f} |",
            f"| Timed re-encrypt (KEM+AES+Sign) | {re:.3f} |",
            f"| Approx. rest (keys, parse, …) ≈ GW − re-encrypt | {ov:.3f} |",
            "",
            f"**Firewall LightGBM** mean inference (verdict events): **{inf_fw:.3f} ms** — not additive with the path table; "
            "packets are accepted before classification, but slow inference can delay **subsequent** NFQUEUE packets.",
            "",
        ]

    lines += [
        "---",
        "",
        "*Report generated by `scripts/parse_end_to_end_report.py` — MQTT IDS/IPS + PQC Benchmarking Framework.*",
    ]
    return "\n".join(lines)


# ── Optional CSV export ────────────────────────────────────────────────────────

def write_csv(fw_agg: dict, gw_agg: dict, path: str) -> None:
    fieldnames = [
        "attack_type", "fw_verdicts", "fw_det_rate_pct",
        "fw_infer_mean_ms", "fw_infer_std_ms",
        "fw_classify_mean_ms", "fw_classify_std_ms",
        "fw_inspect_mean_ms",
    ]
    gw_fields = [
        "gw_transit_mean_ms", "gw_encap_mean_ms", "gw_aes_mean_ms",
        "gw_sign_mean_ms", "gw_reencrypt_mean_ms", "gw_total_mean_ms",
        "e2e_mean_ms",
    ]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames + gw_fields)
        w.writeheader()
        by_type = fw_agg.get("by_type", {})
        for label, entry in sorted(by_type.items()):
            t_inf = entry["t_inference"]
            t_cls = entry["t_classify"]
            t_ins = entry["t_inspect"]
            conf  = entry["confidence"]
            row = {
                "attack_type":          label,
                "fw_verdicts":          entry["count"],
                "fw_det_rate_pct":      f"{sum(conf)/len(conf)*100:.1f}" if conf else "",
                "fw_infer_mean_ms":     f"{sum(t_inf)/len(t_inf):.3f}" if t_inf else "",
                "fw_infer_std_ms":      f"{_safe_std(t_inf):.3f}" if len(t_inf) > 1 else "",
                "fw_classify_mean_ms":  f"{sum(t_cls)/len(t_cls):.3f}" if t_cls else "",
                "fw_classify_std_ms":   f"{_safe_std(t_cls):.3f}" if len(t_cls) > 1 else "",
                "fw_inspect_mean_ms":   f"{sum(t_ins)/len(t_ins):.3f}" if t_ins else "",
                "gw_transit_mean_ms":   f"{gw_agg['transit']['mean']:.3f}" if gw_agg else "",
                "gw_encap_mean_ms":     f"{gw_agg['encap']['mean']:.3f}" if gw_agg else "",
                "gw_aes_mean_ms":       f"{gw_agg['aes']['mean']:.3f}" if gw_agg else "",
                "gw_sign_mean_ms":      f"{gw_agg['sign']['mean']:.3f}" if gw_agg else "",
                "gw_reencrypt_mean_ms": f"{gw_agg['reencrypt']['mean']:.3f}" if gw_agg else "",
                "gw_total_mean_ms":     f"{gw_agg['total_gw']['mean']:.3f}" if gw_agg else "",
                "e2e_mean_ms":          f"{_path_latency_mean_ms(gw_agg):.3f}" if gw_agg else "",
            }
            w.writerow(row)
    print(f"CSV exported → {path}")


# ── Optional PDF ───────────────────────────────────────────────────────────────

def write_pdf(md_text: str, pdf_path: str) -> None:
    try:
        import markdown as md_lib
        from weasyprint import HTML
    except ImportError:
        print("[WARN] PDF skipped — install: pip install weasyprint markdown", file=sys.stderr)
        return
    html_body = md_lib.markdown(md_text, extensions=["tables"])
    html_full = f"""<!DOCTYPE html><html><head>
    <meta charset="utf-8">
    <style>
      body {{ font-family: sans-serif; font-size: 12px; margin: 2cm; }}
      table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
      th, td {{ border: 1px solid #ccc; padding: 4px 8px; text-align: left; }}
      th {{ background: #f0f0f0; }}
      h1 {{ font-size: 1.6em; }} h2 {{ font-size: 1.2em; }}
      code {{ background: #f8f8f8; padding: 1px 4px; border-radius: 3px; }}
    </style></head><body>{html_body}</body></html>"""
    HTML(string=html_full).write_pdf(pdf_path)
    print(f"PDF exported → {pdf_path}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-end pipeline report generator.")
    parser.add_argument("--since",  type=float, default=0,
                        help="Only include data from last N seconds (0 = all)")
    parser.add_argument("--no-pdf", action="store_true",
                        help="Skip PDF generation")
    parser.add_argument("--csv",    default="",
                        help="Also export a flat CSV to this path")
    args = parser.parse_args()

    since_ts = (time.time() - args.since) if args.since > 0 else 0.0

    print(f"Reading firewall log : {FW_JSONL}")
    print(f"Reading reencrypt CSV: {REENCRYPT_CSV}")

    fw_raw  = load_firewall(since_ts)
    fw_agg  = aggregate_firewall(fw_raw)

    gw_rows = load_reencrypt(since_ts)
    gw_agg  = aggregate_reencrypt(gw_rows)

    print_console_report(fw_agg, gw_agg)

    md_text = build_markdown(fw_agg, gw_agg)
    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    REPORT_MD.write_text(md_text, encoding="utf-8")
    print(f"Markdown report → {REPORT_MD}")

    if args.csv:
        write_csv(fw_agg, gw_agg, args.csv)

    if not args.no_pdf:
        pdf_path = str(REPORT_MD.with_suffix(".pdf"))
        write_pdf(md_text, pdf_path)


if __name__ == "__main__":
    main()
