#!/usr/bin/env python3
"""
parse_firewall_logs.py — Firewall log analyser.

Reads mqtt_firewall.jsonl (machine-readable) and/or mqtt_firewall.log
(human-readable fallback) and prints a console summary, and optionally
writes a Markdown report and/or exports a PDF.

Usage:
    python scripts/parse_firewall_logs.py                          # console only
    python scripts/parse_firewall_logs.py --report report.md       # + Markdown file
    python scripts/parse_firewall_logs.py --report report.md --pdf # + PDF from MD
    python scripts/parse_firewall_logs.py --export verdicts.csv    # raw CSV export
    python scripts/parse_firewall_logs.py --tail 20                # last N verdicts
    python scripts/parse_firewall_logs.py --since "02:00:00"       # filter by time
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from datetime import datetime
from io import StringIO
from pathlib import Path

REPO_ROOT     = Path(__file__).resolve().parents[1]
DEFAULT_LOG   = REPO_ROOT / "Firewall_logs" / "mqtt_firewall.log"
DEFAULT_JSONL = REPO_ROOT / "Firewall_logs" / "mqtt_firewall.jsonl"
DEFAULT_REPORT = REPO_ROOT / "benchmarks" / "firewall_report.md"


# ── Parsers ──────────────────────────────────────────────────────────────────

def _parse_jsonl(path: Path) -> list[dict]:
    verdicts = []
    with path.open("r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("event") == "verdict":
                verdicts.append(obj)
    return verdicts


_LOG_VERDICT_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) \[INFO\] \[VERDICT\] "
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+) -> (?P<dst_ip>[\d.]+):(?P<dst_port>\d+) \| "
    r"verdict=(?P<verdict>\S+)\s+type=(?P<attack_type>\S+)\s+confidence=(?P<confidence>[\d.]+)\s+"
    r"pkts=(?P<pkts>\d+)\s+bytes=(?P<bytes>\d+)\s+dur=(?P<dur>[\d.]+)s"
)

def _parse_log(path: Path) -> list[dict]:
    verdicts = []
    with path.open("r", errors="replace") as fh:
        for line in fh:
            m = _LOG_VERDICT_RE.search(line)
            if not m:
                continue
            ts_str = m.group("ts")
            try:
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f")
                ts = dt.timestamp()
            except ValueError:
                ts = 0.0
            verdicts.append({
                "ts":              ts,
                "verdict":         m.group("verdict"),
                "attack_type":     m.group("attack_type"),
                "attack_prob":     float(m.group("confidence")),
                "flow_src_ip":     m.group("src_ip"),
                "flow_src_port":   int(m.group("src_port")),
                "flow_dst_ip":     m.group("dst_ip"),
                "flow_dst_port":   int(m.group("dst_port")),
                "flow_pkts":       int(m.group("pkts")),
                "flow_bytes":      int(m.group("bytes")),
                "flow_duration_s": float(m.group("dur")),
            })
    return verdicts


def _count_packets(log_path: Path) -> tuple[int, int]:
    total_pkts = total_lines = 0
    if not log_path.exists():
        return 0, 0
    with log_path.open("r", errors="replace") as fh:
        for line in fh:
            total_lines += 1
            if "[PKT]" in line:
                total_pkts += 1
    return total_pkts, total_lines


# ── Helpers ──────────────────────────────────────────────────────────────────

def _pct(n: int, total: int) -> str:
    return f"{100*n/total:.1f}%" if total else "0.0%"

def _bar(n: int, total: int, width: int = 20) -> str:
    filled = int(width * n / total) if total else 0
    return "█" * filled + "░" * (width - filled)

def _ts_fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "n/a"

def _safe_mean(lst: list) -> float:
    return sum(lst) / len(lst) if lst else 0.0


# ── Data aggregation ─────────────────────────────────────────────────────────

def _aggregate(verdicts: list[dict], log_path: Path) -> dict:
    total_pkts, total_lines = _count_packets(log_path)
    attacks = [v for v in verdicts if v.get("verdict") == "ATTACK"]
    benigns = [v for v in verdicts if v.get("verdict") != "ATTACK"]

    type_counts: Counter = Counter(v.get("attack_type", "unknown") for v in verdicts)
    attack_flows: Counter = Counter(
        (v.get("flow_src_ip"), v.get("flow_src_port"), v.get("attack_type"))
        for v in attacks
    )
    confs  = [v.get("attack_prob", 0.0) for v in attacks]
    pkts_l = [v.get("flow_pkts",       0)   for v in verdicts]
    byt_l  = [v.get("flow_bytes",      0)   for v in verdicts]
    dur_l  = [v.get("flow_duration_s", 0.0) for v in verdicts]

    return dict(
        total_lines=total_lines,
        total_pkts=total_pkts,
        total_verdicts=len(verdicts),
        n_attack=len(attacks),
        n_benign=len(benigns),
        first_ts=_ts_fmt(verdicts[0].get("ts", 0))  if verdicts else "n/a",
        last_ts =_ts_fmt(verdicts[-1].get("ts", 0)) if verdicts else "n/a",
        type_counts=type_counts,
        attack_flows=attack_flows,
        conf_min =min(confs)          if confs else 0.0,
        conf_max =max(confs)          if confs else 0.0,
        conf_mean=_safe_mean(confs),
        conf_high=sum(1 for c in confs if c >= 0.9),
        pkts_min =min(pkts_l)         if pkts_l else 0,
        pkts_max =max(pkts_l)         if pkts_l else 0,
        pkts_avg =_safe_mean(pkts_l),
        byt_min  =min(byt_l)          if byt_l  else 0,
        byt_max  =max(byt_l)          if byt_l  else 0,
        byt_avg  =_safe_mean(byt_l),
        dur_min  =min(dur_l)          if dur_l  else 0.0,
        dur_max  =max(dur_l)          if dur_l  else 0.0,
        dur_avg  =_safe_mean(dur_l),
    )


# ── Console report ────────────────────────────────────────────────────────────

def _print_header(title: str) -> None:
    print(f"\n{'─'*60}\n  {title}\n{'─'*60}")

def print_console_report(verdicts: list[dict], agg: dict, tail: int) -> None:
    _print_header("FIREWALL REPORT — OVERALL SUMMARY")
    print(f"  Log lines total    : {agg['total_lines']:>8,}")
    print(f"  Packets seen       : {agg['total_pkts']:>8,}")
    print(f"  Verdict events     : {agg['total_verdicts']:>8,}")
    print(f"  ├─ ATTACK verdicts : {agg['n_attack']:>8,}  ({_pct(agg['n_attack'], agg['total_verdicts'])})")
    print(f"  └─ benign verdicts : {agg['n_benign']:>8,}  ({_pct(agg['n_benign'], agg['total_verdicts'])})")
    print(f"  Time range         : {agg['first_ts']} → {agg['last_ts']}")

    _print_header("ATTACK TYPE BREAKDOWN")
    col_w = max(len(k) for k in agg["type_counts"]) + 2 if agg["type_counts"] else 20
    print(f"  {'Type':<{col_w}} {'Count':>7}  {'Share':>7}  Chart")
    print(f"  {'─'*col_w} {'─'*7}  {'─'*7}  {'─'*20}")
    for label, count in agg["type_counts"].most_common():
        bar = _bar(count, agg["total_verdicts"])
        print(f"  {label:<{col_w}} {count:>7,}  {_pct(count, agg['total_verdicts']):>7}  {bar}")

    _print_header("CONFIDENCE STATISTICS (attack_prob)")
    print(f"  Attack flows (n={agg['n_attack']:,})")
    print(f"  Min  : {agg['conf_min']:.4f}")
    print(f"  Max  : {agg['conf_max']:.4f}")
    print(f"  Mean : {agg['conf_mean']:.4f}")
    print(f"  ≥0.90: {agg['conf_high']:,}  ({_pct(agg['conf_high'], agg['n_attack'])})")

    _print_header("FLOW STATISTICS")
    print(f"  Packets/flow : min={agg['pkts_min']}  max={agg['pkts_max']}  avg={agg['pkts_avg']:.1f}")
    print(f"  Bytes/flow   : min={agg['byt_min']:,}  max={agg['byt_max']:,}  avg={agg['byt_avg']:,.0f}")
    print(f"  Duration (s) : min={agg['dur_min']:.4f}  max={agg['dur_max']:.4f}  avg={agg['dur_avg']:.4f}")

    _print_header("TOP ATTACKER FLOWS (src:port, type)")
    print(f"  {'Source':>22}  {'Attack type':<30}  Count")
    print(f"  {'─'*22}  {'─'*30}  {'─'*7}")
    for (ip, port, atype), cnt in agg["attack_flows"].most_common(15):
        print(f"  {ip}:{port:>5}  {atype:<30}  {cnt:>7,}")
    extra = len(agg["attack_flows"]) - 15
    if extra > 0:
        print(f"  ... and {extra} more flows")

    if tail > 0:
        _print_header(f"LAST {tail} VERDICTS")
        for v in verdicts[-tail:]:
            tag   = "ATTACK" if v.get("verdict") == "ATTACK" else "benign"
            atype = v.get("attack_type", "?")
            prob  = v.get("attack_prob", 0.0)
            sp    = v.get("flow_src_port", 0)
            dp    = v.get("flow_dst_port", 0)
            pkts  = v.get("flow_pkts", 0)
            ts    = _ts_fmt(v.get("ts", 0))
            print(f"  [{ts}] {tag:<6}  {atype:<30}  conf={prob:.2f}  :{sp}→:{dp}  pkts={pkts}")

    print()


# ── Markdown report ───────────────────────────────────────────────────────────

def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    col_w = [max(len(h), max((len(str(r[i])) for r in rows), default=0))
             for i, h in enumerate(headers)]
    sep  = "| " + " | ".join("-" * w for w in col_w) + " |"
    head = "| " + " | ".join(h.ljust(col_w[i]) for i, h in enumerate(headers)) + " |"
    body = "\n".join(
        "| " + " | ".join(str(r[i]).ljust(col_w[i]) for i in range(len(headers))) + " |"
        for r in rows
    )
    return f"{head}\n{sep}\n{body}"


def build_markdown(verdicts: list[dict], agg: dict, tail: int, source: str) -> str:
    buf = StringIO()
    w   = buf.write

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_v  = agg["total_verdicts"]
    n_attack = agg["n_attack"]
    n_benign = agg["n_benign"]

    # ── Title & meta ──────────────────────────────────────────────────────────
    w("# MQTT Firewall Intrusion Detection Report\n\n")
    w(f"**Generated:** {generated_at}  \n")
    w(f"**Source file:** `{source}`  \n")
    w(f"**Time range:** {agg['first_ts']} → {agg['last_ts']}  \n\n")
    w("---\n\n")

    # ── 1. Executive summary ──────────────────────────────────────────────────
    w("## 1. Executive Summary\n\n")
    detection_rate = _pct(n_attack, total_v) if total_v else "0.0%"
    w(f"The LightGBM-based MQTT firewall processed **{agg['total_pkts']:,} packets** "
      f"({agg['total_lines']:,} log lines) and issued **{total_v:,} flow-level verdicts**. "
      f"Of these, **{n_attack:,} ({detection_rate}) were classified as attacks** and "
      f"**{n_benign:,} ({_pct(n_benign, total_v)}) as benign**. "
      f"Mean model confidence on attack flows was **{agg['conf_mean']:.4f}**.\n\n")

    w("| Metric | Value |\n")
    w("|--------|-------|\n")
    w(f"| Total log lines | {agg['total_lines']:,} |\n")
    w(f"| Total packets intercepted | {agg['total_pkts']:,} |\n")
    w(f"| Total flow verdicts | {total_v:,} |\n")
    w(f"| Attack verdicts | {n_attack:,} ({detection_rate}) |\n")
    w(f"| Benign verdicts | {n_benign:,} ({_pct(n_benign, total_v)}) |\n")
    w(f"| Observation window | {agg['first_ts']} → {agg['last_ts']} |\n\n")

    # ── 2. Attack type breakdown ──────────────────────────────────────────────
    w("## 2. Attack Type Breakdown\n\n")
    rows = [
        [label, f"{count:,}", _pct(count, total_v)]
        for label, count in agg["type_counts"].most_common()
    ]
    w(_md_table(["Attack Type", "Verdict Count", "Share (%)"], rows))
    w("\n\n")

    # ── 3. Model confidence ───────────────────────────────────────────────────
    w("## 3. Model Confidence Statistics\n\n")
    w("Statistics computed over **attack-classified flows only**.\n\n")
    w("| Statistic | Value |\n")
    w("|-----------|-------|\n")
    w(f"| Sample size | {n_attack:,} flows |\n")
    w(f"| Minimum confidence | {agg['conf_min']:.4f} |\n")
    w(f"| Maximum confidence | {agg['conf_max']:.4f} |\n")
    w(f"| Mean confidence | {agg['conf_mean']:.4f} |\n")
    w(f"| Flows with confidence ≥ 0.90 | {agg['conf_high']:,} ({_pct(agg['conf_high'], n_attack)}) |\n\n")

    # ── 4. Flow statistics ────────────────────────────────────────────────────
    w("## 4. Flow Statistics\n\n")
    w("| Metric | Min | Max | Mean |\n")
    w("|--------|-----|-----|------|\n")
    w(f"| Packets per flow | {agg['pkts_min']} | {agg['pkts_max']} | {agg['pkts_avg']:.1f} |\n")
    w(f"| Bytes per flow | {agg['byt_min']:,} | {agg['byt_max']:,} | {agg['byt_avg']:,.0f} |\n")
    w(f"| Flow duration (s) | {agg['dur_min']:.4f} | {agg['dur_max']:.4f} | {agg['dur_avg']:.4f} |\n\n")

    # ── 5. Top attacker flows ─────────────────────────────────────────────────
    w("## 5. Top Attacker Flows\n\n")
    w(f"**{len(agg['attack_flows']):,}** distinct `(src_ip:src_port, attack_type)` flows detected.\n\n")
    top_flows = agg["attack_flows"].most_common(20)
    rows = [
        [f"{ip}:{port}", atype, f"{cnt:,}"]
        for (ip, port, atype), cnt in top_flows
    ]
    w(_md_table(["Source (ip:port)", "Classified Attack Type", "Verdict Count"], rows))
    if len(agg["attack_flows"]) > 20:
        w(f"\n\n*...and {len(agg['attack_flows'])-20} additional flows not shown.*")
    w("\n\n")

    # ── 6. Recent verdicts ────────────────────────────────────────────────────
    if tail > 0 and verdicts:
        w(f"## 6. Last {tail} Verdicts\n\n")
        recent = verdicts[-tail:]
        rows = [
            [
                _ts_fmt(v.get("ts", 0)),
                v.get("verdict", "?"),
                v.get("attack_type", "?"),
                f"{v.get('attack_prob', 0.0):.4f}",
                f"{v.get('flow_src_ip')}:{v.get('flow_src_port')}",
                f"{v.get('flow_dst_ip')}:{v.get('flow_dst_port')}",
                str(v.get("flow_pkts", 0)),
                f"{v.get('flow_bytes', 0):,}",
            ]
            for v in recent
        ]
        w(_md_table(
            ["Time", "Verdict", "Attack Type", "Confidence",
             "Source", "Destination", "Pkts", "Bytes"],
            rows,
        ))
        w("\n\n")

    # ── Footer ────────────────────────────────────────────────────────────────
    w("---\n\n")
    w("*Report generated by `scripts/parse_firewall_logs.py` — "
      "MQTT IDS/IPS Benchmarking Framework.*\n")

    return buf.getvalue()


# ── PDF generation ────────────────────────────────────────────────────────────

_PDF_CSS = """
@page {
    size: A4;
    margin: 2cm 2.2cm 2cm 2.2cm;
    @bottom-right { content: "Page " counter(page) " of " counter(pages); font-size: 9pt; color: #888; }
}
body          { font-family: "Segoe UI", Arial, sans-serif; font-size: 11pt; color: #1a1a1a; line-height: 1.55; }
h1            { font-size: 18pt; color: #1a3a6b; border-bottom: 2px solid #1a3a6b; padding-bottom: 6px; margin-top: 0; }
h2            { font-size: 14pt; color: #1a3a6b; border-left: 4px solid #1a3a6b; padding-left: 8px; margin-top: 28px; }
p             { margin: 6px 0 10px; }
table         { border-collapse: collapse; width: 100%; margin: 10px 0 18px; font-size: 9.5pt; }
thead th      { background-color: #1a3a6b; color: #fff; padding: 6px 10px; text-align: left; }
tbody tr:nth-child(even) { background-color: #f0f4fa; }
tbody td      { padding: 5px 10px; border-bottom: 1px solid #dce4f0; }
code          { background: #f0f4fa; padding: 1px 4px; border-radius: 3px; font-size: 9.5pt; font-family: "Courier New", monospace; }
hr            { border: none; border-top: 1px solid #ccc; margin: 18px 0; }
strong        { color: #1a3a6b; }
em            { color: #555; }
"""

def write_pdf(md_text: str, pdf_path: Path) -> None:
    try:
        import markdown as md_lib
        from weasyprint import HTML, CSS
    except ImportError:
        print("[WARN] weasyprint / markdown not installed — skipping PDF.\n"
              "       Install with:  pip install markdown weasyprint", file=sys.stderr)
        return

    html_body = md_lib.markdown(md_text, extensions=["tables", "nl2br"])
    full_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Firewall Report</title></head>
<body>{html_body}</body></html>"""

    try:
        HTML(string=full_html).write_pdf(
            str(pdf_path),
            stylesheets=[CSS(string=_PDF_CSS)],
        )
        print(f"[pdf]    → {pdf_path}")
    except Exception as exc:
        print(f"[ERROR] PDF generation failed: {exc}", file=sys.stderr)


# ── CSV export ────────────────────────────────────────────────────────────────

def write_csv(verdicts: list[dict], csv_path: Path) -> None:
    fields = [
        "ts", "verdict", "attack_type", "attack_prob",
        "flow_src_ip", "flow_src_port", "flow_dst_ip", "flow_dst_port",
        "flow_pkts", "flow_bytes", "flow_duration_s", "threshold",
    ]
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for v in verdicts:
            w.writerow({k: v.get(k, "") for k in fields})
    print(f"[csv]    → {csv_path}  ({len(verdicts):,} rows)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Firewall log parser — Markdown + PDF report from mqtt_firewall.jsonl/.log",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--jsonl",   default=str(DEFAULT_JSONL))
    p.add_argument("--log",     default=str(DEFAULT_LOG))
    p.add_argument("--from-md", default="", dest="from_md",
                   help="Convert an existing .md file directly to PDF, skipping log parsing "
                        "(e.g. --from-md benchmarks/firewall_report.md)")
    p.add_argument("--report",  default=str(DEFAULT_REPORT),
                   help=f"Write Markdown report to this path (default: {DEFAULT_REPORT})")
    p.add_argument("--pdf",     action="store_true",
                   help="Also convert the Markdown report to PDF (requires --report)")
    p.add_argument("--export",  default="",
                   help="Export raw verdict rows to this CSV path")
    p.add_argument("--tail",    type=int, default=10,
                   help="Number of recent verdicts to include in report (default: 10)")
    p.add_argument("--since",   default="",
                   help="Only process verdicts after HH:MM:SS (today)")
    return p.parse_args()


def main() -> int:
    args   = parse_args()
    jsonl  = Path(args.jsonl)
    log    = Path(args.log)

    # ── Short-circuit: convert an existing .md to PDF and exit ────────────────
    if args.from_md:
        md_path = Path(args.from_md)
        if not md_path.exists():
            print(f"[ERROR] File not found: {md_path}", file=sys.stderr)
            return 1
        md_text  = md_path.read_text(encoding="utf-8")
        pdf_path = md_path.with_suffix(".pdf")
        print(f"[from-md] Reading  : {md_path}")
        write_pdf(md_text, pdf_path)
        return 0

    # ── Load verdicts (merge JSONL + .log, deduplicate) ──────────────────────
    sources: list[str] = []
    all_verdicts: list[dict] = []

    if not jsonl.exists() and not log.exists():
        print(f"[ERROR] No log files found at:\n  {jsonl}\n  {log}", file=sys.stderr)
        return 1

    if jsonl.exists():
        jv = _parse_jsonl(jsonl)
        all_verdicts.extend(jv)
        sources.append(f"JSONL ({len(jv):,} verdicts)")
        print(f"[source] JSONL : {jsonl}  ({len(jv):,} verdict events)")

    if log.exists():
        lv = _parse_log(log)
        sources.append(f".log ({len(lv):,} verdicts)")
        print(f"[source] .log  : {log}  ({len(lv):,} verdict events)")
        if all_verdicts:
            # Deduplicate: key = (ts rounded to 1 decimal, src_ip, src_port, dst_ip, dst_port)
            seen: set[tuple] = set()
            for v in all_verdicts:
                seen.add((
                    round(v.get("ts", 0.0), 1),
                    v.get("flow_src_ip"), v.get("flow_src_port"),
                    v.get("flow_dst_ip"), v.get("flow_dst_port"),
                ))
            added = 0
            for v in lv:
                key = (
                    round(v.get("ts", 0.0), 1),
                    v.get("flow_src_ip"), v.get("flow_src_port"),
                    v.get("flow_dst_ip"), v.get("flow_dst_port"),
                )
                if key not in seen:
                    all_verdicts.append(v)
                    seen.add(key)
                    added += 1
            if added:
                print(f"[merge] +{added:,} unique verdicts from .log not in JSONL")
            else:
                print(f"[merge] .log contains no new verdicts beyond JSONL (both in sync)")
        else:
            all_verdicts.extend(lv)

    verdicts = sorted(all_verdicts, key=lambda v: v.get("ts", 0.0))
    source   = " + ".join(sources)
    print(f"[total] {len(verdicts):,} verdicts after merge")

    if not verdicts:
        print("[INFO] No verdict events found.")
        return 0

    # ── Optional time filter ──────────────────────────────────────────────────
    if args.since:
        try:
            cutoff = datetime.strptime(args.since, "%H:%M:%S").replace(
                year=datetime.now().year,
                month=datetime.now().month,
                day=datetime.now().day,
            ).timestamp()
            before = len(verdicts)
            verdicts = [v for v in verdicts if v.get("ts", 0) >= cutoff]
            print(f"[filter] --since {args.since}: {before:,} → {len(verdicts):,} verdicts")
        except ValueError:
            print("[WARN] --since expects HH:MM:SS format.", file=sys.stderr)

    if not verdicts:
        print("[INFO] No verdicts after applying time filter.")
        return 0

    # ── Aggregate stats ───────────────────────────────────────────────────────
    agg = _aggregate(verdicts, log)

    # ── Console report ────────────────────────────────────────────────────────
    print_console_report(verdicts, agg, args.tail)

    # ── Markdown report ───────────────────────────────────────────────────────
    md_path = Path(args.report)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_text = build_markdown(verdicts, agg, args.tail, source)
    md_path.write_text(md_text, encoding="utf-8")
    print(f"[report] → {md_path}")

    if args.pdf:
        pdf_path = md_path.with_suffix(".pdf")
        write_pdf(md_text, pdf_path)

    # ── CSV export ────────────────────────────────────────────────────────────
    if args.export:
        write_csv(verdicts, Path(args.export))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
