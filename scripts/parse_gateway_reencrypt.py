#!/usr/bin/env python3
"""
parse_gateway_reencrypt.py — Report generator for the gateway PQC re-encryption pipeline.

Reads:
  benchmarks/gateway/reencrypt_metrics.csv  — per-message re-encryption timing
      (on-gateway: t_recv_to_done_ns, t_reencrypt_ns; t_broker_transit_ns is
      WAN+skew only if logs were produced with GW_REENCRYPT_LOG_WAN_TRANSIT=1)
  Firewall_logs/firewall_misses.jsonl        — attack messages that slipped past firewall

  Firewall IDS/IPS timing is in Firewall_logs/*.jsonl (event=verdict):
      t_inference_ns, t_classify_ns, nfqueue_first_wall_ns, t_verdict_wall_ns —
      flow-level, not joinable row-for-row to MQTT PUBLISH in reencrypt_metrics.csv.

Outputs:
  Console summary
  benchmarks/gateway_reencrypt_report.md    — Markdown report (+ PDF if weasyprint available)
  Optional CSV export via --export

Usage:
    python scripts/parse_gateway_reencrypt.py
    python scripts/parse_gateway_reencrypt.py --no-pdf
    python scripts/parse_gateway_reencrypt.py --export benchmarks/reencrypt_raw.csv
    python scripts/parse_gateway_reencrypt.py --since 02:00:00
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime
from io import StringIO
from pathlib import Path

REPO_ROOT      = Path(__file__).resolve().parents[1]
DEFAULT_CSV    = REPO_ROOT / "benchmarks" / "gateway" / "reencrypt_metrics.csv"
DEFAULT_MISSES = REPO_ROOT / "Firewall_logs" / "firewall_misses.jsonl"
DEFAULT_REPORT = REPO_ROOT / "benchmarks" / "gateway_reencrypt_report.md"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_mean(lst: list) -> float:
    return sum(lst) / len(lst) if lst else 0.0

def _safe_std(lst: list) -> float:
    if len(lst) < 2:
        return 0.0
    mean = sum(lst) / len(lst)
    return math.sqrt(sum((x - mean) ** 2 for x in lst) / len(lst))

def _safe_p95(lst: list) -> float:
    if not lst:
        return 0.0
    s = sorted(lst)
    pos = (len(s) - 1) * 0.95
    lo, hi = int(pos), min(int(pos) + 1, len(s) - 1)
    return s[lo] + (pos - lo) * (s[hi] - s[lo])

def _fmt_ms(ns: float) -> str:
    return f"{ns / 1e6:.3f} ms"

def _pct(n: int, total: int) -> str:
    return f"{100 * n / total:.1f}%" if total else "0.0%"

def _ts_fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "n/a"


# ── Loaders ───────────────────────────────────────────────────────────────────

def load_reencrypt_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                rows.append({
                    "ts_unix_ns":           int(row.get("ts_unix_ns", 0)),
                    "device_id":            row.get("device_id", ""),
                    "seq":                  int(row.get("seq", 0)),
                    "kem":                  row.get("kem", ""),
                    "sig":                  row.get("sig", ""),
                    "payload_bytes":        int(row.get("payload_bytes", 0)),
                    "t_publish_ns":         int(row.get("t_publish_ns", 0)),
                    "t_broker_transit_ns":  int(row.get("t_broker_transit_ns", 0)),
                    "t_recv_to_done_ns":    int(row.get("t_recv_to_done_ns", 0)),
                    "t_encap_ns":           int(row.get("t_encap_ns", 0)),
                    "t_aes_enc_ns":         int(row.get("t_aes_enc_ns", 0)),
                    "t_sign_ns":            int(row.get("t_sign_ns", 0)),
                    "t_reencrypt_ns":       int(row.get("t_reencrypt_ns", 0)),
                    "pqc_available":        row.get("pqc_available", "False") == "True",
                })
            except (ValueError, KeyError):
                continue
    return rows


def load_firewall_misses(path: Path) -> list[dict]:
    if not path.exists():
        return []
    misses = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("event") == "firewall_miss":
                    misses.append(obj)
            except json.JSONDecodeError:
                continue
    return misses


# ── Aggregation ───────────────────────────────────────────────────────────────

def aggregate_reencrypt(rows: list[dict]) -> dict:
    if not rows:
        return {}

    def _stats(vals: list) -> dict:
        return dict(n=len(vals), mean=_safe_mean(vals), std=_safe_std(vals),
                    mn=min(vals) if vals else 0, mx=max(vals) if vals else 0,
                    p95=_safe_p95(vals))

    transit   = [r["t_broker_transit_ns"] for r in rows if r["t_broker_transit_ns"] > 0]
    reencrypt = [r["t_reencrypt_ns"]      for r in rows if r["t_reencrypt_ns"]      > 0]
    encap     = [r["t_encap_ns"]          for r in rows if r["t_encap_ns"]          > 0]
    aes_enc   = [r["t_aes_enc_ns"]        for r in rows if r["t_aes_enc_ns"]        > 0]
    sign      = [r["t_sign_ns"]           for r in rows if r["t_sign_ns"]           > 0]
    # One row per completed re-encrypt — duration should always be > 0; use all rows
    # so n matches len(rows) (and per-device count), not a filtered subset.
    total_gw  = [r["t_recv_to_done_ns"] for r in rows]
    pbytes    = [r["payload_bytes"]       for r in rows if r["payload_bytes"]       > 0]

    # Per-device breakdown
    by_device: dict = defaultdict(lambda: defaultdict(list))
    for r in rows:
        dev = r["device_id"]
        by_device[dev]["transit"].append(r["t_broker_transit_ns"])
        by_device[dev]["reencrypt"].append(r["t_reencrypt_ns"])
        by_device[dev]["total_gw"].append(r["t_recv_to_done_ns"])

    device_stats = {
        dev: {
            "count":    len(d["reencrypt"]),
            "transit":  _stats(d["transit"]),
            "reencrypt":_stats(d["reencrypt"]),
            "total_gw": _stats(d["total_gw"]),
        }
        for dev, d in sorted(by_device.items())
    }

    ts_vals = [r["ts_unix_ns"] / 1e9 for r in rows]

    return dict(
        total          = len(rows),
        first_ts       = _ts_fmt(min(ts_vals)) if ts_vals else "n/a",
        last_ts        = _ts_fmt(max(ts_vals)) if ts_vals else "n/a",
        kem            = rows[0]["kem"] if rows else "n/a",
        sig            = rows[0]["sig"] if rows else "n/a",
        pqc_available  = any(r["pqc_available"] for r in rows),
        transit        = _stats(transit),
        reencrypt      = _stats(reencrypt),
        encap          = _stats(encap),
        aes_enc        = _stats(aes_enc),
        sign_          = _stats(sign),
        total_gw       = _stats(total_gw),
        payload_bytes  = _stats(pbytes),
        device_stats   = device_stats,
    )


def aggregate_misses(misses: list[dict]) -> dict:
    by_label: Counter = Counter(m.get("attack_label", "unknown") for m in misses)
    by_crypto: Counter = Counter(m.get("crypto_type", "unknown") for m in misses)
    return dict(total=len(misses), by_label=by_label, by_crypto=by_crypto)


# ── Console report ────────────────────────────────────────────────────────────

def _hdr(title: str) -> None:
    print(f"\n{'─'*65}\n  {title}\n{'─'*65}")

def _row_ms(label: str, s: dict) -> None:
    if s["n"] == 0:
        print(f"  {label:<28} —")
        return
    print(
        f"  {label:<28} n={s['n']}  "
        f"mean={_fmt_ms(s['mean'])}  std={_fmt_ms(s['std'])}  "
        f"p95={_fmt_ms(s['p95'])}  "
        f"min={_fmt_ms(s['mn'])}  max={_fmt_ms(s['mx'])}"
    )

def print_console_report(agg: dict, miss_agg: dict, tail: int,
                         rows: list[dict], misses: list[dict]) -> None:
    if not agg:
        print("[INFO] No re-encryption data found.")
    else:
        _hdr("GATEWAY PQC RE-ENCRYPTION — OVERALL SUMMARY")
        print(f"  Messages re-encrypted : {agg['total']:,}")
        print(f"  KEM algorithm         : {agg['kem']}")
        print(f"  Signature algorithm   : {agg['sig']}")
        print(f"  PQC available         : {agg['pqc_available']}")
        print(f"  Time range            : {agg['first_ts']} → {agg['last_ts']}")

        _hdr("TIMING BREAKDOWN (per message)")
        _row_ms("WAN transit (opt.)", agg["transit"])
        _row_ms("KEM encapsulate",    agg["encap"])
        _row_ms("AES-256-GCM enc",    agg["aes_enc"])
        _row_ms("Signature sign",     agg["sign_"])
        _row_ms("Total re-encrypt",   agg["reencrypt"])
        _row_ms("On-device gateway",  agg["total_gw"])

        if agg["device_stats"]:
            _hdr("PER-DEVICE BREAKDOWN")
            col = max(len(d) for d in agg["device_stats"]) + 2
            print(f"  {'Device':<{col}} {'N':>5}  {'WAN μ':>11}  {'Reencrypt μ':>12}  {'On-dev GW μ':>11}")
            print(f"  {'─'*col} {'─'*5}  {'─'*11}  {'─'*12}  {'─'*11}")
            for dev, s in agg["device_stats"].items():
                print(
                    f"  {dev:<{col}} {s['count']:>5}  "
                    f"{_fmt_ms(s['transit']['mean']):>11}  "
                    f"{_fmt_ms(s['reencrypt']['mean']):>12}  "
                    f"{_fmt_ms(s['total_gw']['mean']):>11}"
                )

        if tail > 0 and rows:
            _hdr(f"LAST {tail} RE-ENCRYPTED MESSAGES")
            for r in rows[-tail:]:
                print(
                    f"  device={r['device_id']}  seq={r['seq']}  "
                    f"wan={_fmt_ms(r['t_broker_transit_ns'])}  "
                    f"reencrypt={_fmt_ms(r['t_reencrypt_ns'])}  "
                    f"on_dev_gw={_fmt_ms(r['t_recv_to_done_ns'])}"
                )

    _hdr("FIREWALL MISSES (attacks that reached gateway)")
    print(f"  Total misses : {miss_agg['total']:,}")
    if miss_agg["total"] > 0:
        print(f"\n  By attack label:")
        for label, cnt in miss_agg["by_label"].most_common():
            print(f"    {label:<35} {cnt:>5,}")
        print(f"\n  By crypto_type used (spoofing attempt):")
        for ctype, cnt in miss_agg["by_crypto"].most_common():
            print(f"    {ctype:<35} {cnt:>5,}")
        if tail > 0 and misses:
            print(f"\n  Last {min(tail, len(misses))} misses:")
            for m in misses[-tail:]:
                print(
                    f"    [{_ts_fmt(m.get('ts', 0))}] "
                    f"attack={m.get('attack_label','?')}  "
                    f"device={m.get('device_id','?')}  "
                    f"seq={m.get('seq','?')}  "
                    f"preview: {m.get('payload_preview','')[:60]}"
                )
    print()


# ── Markdown report ───────────────────────────────────────────────────────────

def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_No data._\n"
    col_w = [max(len(h), max((len(str(r[i])) for r in rows), default=0))
             for i, h in enumerate(headers)]
    sep  = "| " + " | ".join("-" * w for w in col_w) + " |"
    head = "| " + " | ".join(h.ljust(col_w[i]) for i, h in enumerate(headers)) + " |"
    body = "\n".join(
        "| " + " | ".join(str(r[i]).ljust(col_w[i]) for i in range(len(headers))) + " |"
        for r in rows
    )
    return f"{head}\n{sep}\n{body}\n"


def build_markdown(agg: dict, miss_agg: dict, tail: int,
                   rows: list[dict], misses: list[dict], source: str) -> str:
    buf = StringIO()
    w   = buf.write
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    w("# Gateway PQC Re-Encryption Pipeline Report\n\n")
    w(f"**Generated:** {now}  \n")
    w(f"**Source:** `{source}`  \n\n")
    w("---\n\n")

    # ── 1. Summary ────────────────────────────────────────────────────────────
    w("## 1. Executive Summary\n\n")
    if agg:
        wan_blurb = (
            "WAN transit omitted in CSV (default) — set GW_REENCRYPT_LOG_WAN_TRANSIT=1 to record it."
            if agg["transit"]["n"] == 0
            else f"Optional WAN transit mean: {_fmt_ms(agg['transit']['mean'])}."
        )
        w(f"The re-encrypted **{agg['total']:,} benign messages** used "
          f"`{agg['kem']}` + `{agg['sig']}` (AES-256-GCM). "
          f"Mean **on-device** handler time (MQTT callback → re-encrypt done) was "
          f"**{_fmt_ms(agg['total_gw']['mean'])}**; mean KEM+AES+sign work was "
          f"**{_fmt_ms(agg['reencrypt']['mean'])}**. {wan_blurb}\n\n")
        w("| Metric | Value |\n|--------|-------|\n")
        w(f"| Messages re-encrypted | {agg['total']:,} |\n")
        w(f"| KEM algorithm | `{agg['kem']}` |\n")
        w(f"| Signature algorithm | `{agg['sig']}` |\n")
        w(f"| PQC mode | {'Real liboqs' if agg['pqc_available'] else 'Simulation'} |\n")
        w(f"| Observation window | {agg['first_ts']} → {agg['last_ts']} |\n\n")
    else:
        w("_No re-encryption data available._\n\n")

    # ── 2. Timing breakdown ───────────────────────────────────────────────────
    w("## 2. Timing Breakdown\n\n")
    w("> All values in milliseconds (ms). "
      "**WAN transit** (optional) is only non-zero in the CSV if "
      "`GW_REENCRYPT_LOG_WAN_TRANSIT=1` when the gateway was run — otherwise that column "
      "is zero by design. "
      "**On-device gateway** = handler wall time from `on_message` entry (perf_counter) "
      "through end of re-encrypt; excludes WAN. "
      "NFQUEUE / LightGBM times are not in this CSV (see Firewall `verdict` JSONL).\n\n")
    if agg:
        timing_rows = []
        for label, key in [
            ("WAN transit (optional, client clock)", "transit"),
            ("KEM encapsulate",                      "encap"),
            ("AES-256-GCM encrypt",                  "aes_enc"),
            ("Signature sign",                       "sign_"),
            ("Total re-encrypt (KEM+AES+Sign)",      "reencrypt"),
            ("On-device gateway (on_message→done)",  "total_gw"),
        ]:
            s = agg[key]
            timing_rows.append([
                label,
                str(s["n"]),
                f"{_fmt_ms(s['mean'])}",
                f"{_fmt_ms(s['std'])}",
                f"{_fmt_ms(s['p95'])}",
                f"{_fmt_ms(s['mn'])}",
                f"{_fmt_ms(s['mx'])}",
            ])
        w(_md_table(
            ["Stage", "N", "Mean", "Std", "P95", "Min", "Max"],
            timing_rows,
        ))
        w("\n")
    else:
        w("_No timing data available._\n\n")

    # ── 3. Per-device breakdown ───────────────────────────────────────────────
    w("## 3. Per-Device Timing\n\n")
    if agg and agg.get("device_stats"):
        dev_rows = []
        for dev, s in agg["device_stats"].items():
            dev_rows.append([
                dev,
                str(s["count"]),
                f"{_fmt_ms(s['transit']['mean'])}",
                f"{_fmt_ms(s['transit']['std'])}",
                f"{_fmt_ms(s['reencrypt']['mean'])}",
                f"{_fmt_ms(s['reencrypt']['std'])}",
                f"{_fmt_ms(s['total_gw']['mean'])}",
            ])
        w(_md_table(
            ["Device ID", "N", "WAN Mean", "WAN Std",
             "Reencrypt Mean", "Reencrypt Std", "On-dev GW Mean"],
            dev_rows,
        ))
        w("\n")
    else:
        w("_No per-device data available._\n\n")

    # ── 4. Firewall misses ────────────────────────────────────────────────────
    w("## 4. Firewall Misses — Attacks That Reached the Gateway\n\n")
    w(f"**Total missed attacks:** {miss_agg['total']:,}\n\n")
    if miss_agg["total"] > 0:
        w("> These messages had `is_attack=True` in the payload, meaning the "
          "attack client injected the label. The LightGBM firewall failed to "
          "classify or block the corresponding network flow before it reached "
          "the gateway. Use these records to identify model weaknesses.\n\n")

        w("### By Attack Label\n\n")
        w(_md_table(
            ["Attack Label", "Count", "Share"],
            [[l, str(c), _pct(c, miss_agg["total"])]
             for l, c in miss_agg["by_label"].most_common()],
        ))
        w("\n")

        w("### By crypto_type Used (Spoofing Pattern)\n\n")
        w(_md_table(
            ["crypto_type", "Count"],
            [[ct, str(c)] for ct, c in miss_agg["by_crypto"].most_common()],
        ))
        w("\n")

        if tail > 0 and misses:
            w(f"### Last {min(tail, len(misses))} Miss Events\n\n")
            miss_rows = [
                [
                    _ts_fmt(m.get("ts", 0)),
                    m.get("attack_label", "?"),
                    m.get("device_id",    "?"),
                    str(m.get("seq",      "?")),
                    m.get("crypto_type",  "?"),
                    m.get("payload_preview", "")[:60],
                ]
                for m in misses[-tail:]
            ]
            w(_md_table(
                ["Time", "Attack Label", "Device", "Seq", "crypto_type", "Payload Preview"],
                miss_rows,
            ))
            w("\n")
    else:
        w("_No firewall misses recorded — all attack traffic was blocked._\n\n")

    # ── 5. Recent re-encryptions ──────────────────────────────────────────────
    if tail > 0 and rows and agg:
        w(f"## 5. Last {min(tail, len(rows))} Re-Encrypted Messages\n\n")
        recent_rows = [
            [
                r["device_id"],
                str(r["seq"]),
                _fmt_ms(r["t_broker_transit_ns"]),
                _fmt_ms(r["t_reencrypt_ns"]),
                _fmt_ms(r["t_recv_to_done_ns"]),
            ]
            for r in rows[-tail:]
        ]
        w(_md_table(
            ["Device", "Seq", "WAN Transit", "Re-Encrypt", "On-device GW"],
            recent_rows,
        ))
        w("\n")

    w("---\n\n")
    w("*Report generated by `scripts/parse_gateway_reencrypt.py` — "
      "MQTT IDS/IPS + PQC Benchmarking Framework.*\n")

    return buf.getvalue()


# ── PDF ───────────────────────────────────────────────────────────────────────

def write_pdf(md_text: str, pdf_path: Path) -> None:
    try:
        import markdown as md_lib
        from weasyprint import HTML, CSS
    except ImportError:
        print("[WARN] weasyprint/markdown not installed — skipping PDF.", file=sys.stderr)
        return
    _CSS = ("body{font-family:Arial,sans-serif;font-size:11pt;color:#1a1a1a}"
            "h1{font-size:17pt;color:#1a3a6b}h2{font-size:13pt;color:#1a3a6b}"
            "table{border-collapse:collapse;width:100%;font-size:9pt}"
            "thead th{background:#1a3a6b;color:#fff;padding:5px 8px}"
            "tbody td{padding:4px 8px;border-bottom:1px solid #ddd}"
            "tbody tr:nth-child(even){background:#f0f4fa}")
    html = f"<html><body>{md_lib.markdown(md_text, extensions=['tables'])}</body></html>"
    try:
        HTML(string=html).write_pdf(str(pdf_path), stylesheets=[CSS(string=_CSS)])
        print(f"[pdf]    → {pdf_path}")
    except Exception as exc:
        print(f"[ERROR] PDF failed: {exc}", file=sys.stderr)


# ── CSV export ────────────────────────────────────────────────────────────────

def export_csv(rows: list[dict], path: Path) -> None:
    if not rows:
        print("[INFO] No rows to export.")
        return
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"[export] → {path}  ({len(rows):,} rows)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Parse gateway PQC re-encryption CSV + firewall miss JSONL → report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--csv",    default=str(DEFAULT_CSV),    help="Path to reencrypt_metrics.csv")
    p.add_argument("--misses", default=str(DEFAULT_MISSES), help="Path to firewall_misses.jsonl")
    p.add_argument("--report", default=str(DEFAULT_REPORT), help="Output Markdown report path")
    p.set_defaults(pdf=True)
    p.add_argument("--no-pdf", dest="pdf", action="store_false")
    p.add_argument("--export", default="", help="Export raw rows to this CSV path")
    p.add_argument("--tail",   type=int, default=10, help="Recent records to show (default 10)")
    p.add_argument("--since",  default="", help="Filter records after HH:MM:SS (today)")
    return p.parse_args()


def main() -> int:
    args   = parse_args()
    csv_p  = Path(args.csv)
    miss_p = Path(args.misses)

    rows   = load_reencrypt_csv(csv_p)
    misses = load_firewall_misses(miss_p)

    print(f"[source] reencrypt CSV : {csv_p}  ({len(rows):,} rows)")
    print(f"[source] misses JSONL  : {miss_p}  ({len(misses):,} events)")

    if args.since and rows:
        try:
            cutoff_s = datetime.strptime(args.since, "%H:%M:%S").replace(
                year=datetime.now().year,
                month=datetime.now().month,
                day=datetime.now().day,
            ).timestamp()
            cutoff_ns = int(cutoff_s * 1e9)
            before = len(rows)
            rows = [r for r in rows if r["ts_unix_ns"] >= cutoff_ns]
            print(f"[filter] --since {args.since}: {before} → {len(rows)} rows")
        except ValueError:
            print("[WARN] --since expects HH:MM:SS", file=sys.stderr)

    agg      = aggregate_reencrypt(rows)
    miss_agg = aggregate_misses(misses)

    print_console_report(agg, miss_agg, args.tail, rows, misses)

    source   = f"{csv_p.name} + {miss_p.name}"
    md_text  = build_markdown(agg, miss_agg, args.tail, rows, misses, source)
    md_path  = Path(args.report)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(md_text, encoding="utf-8")
    print(f"[report] → {md_path}")

    if args.pdf:
        write_pdf(md_text, md_path.with_suffix(".pdf"))

    if args.export:
        export_csv(rows, Path(args.export))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
