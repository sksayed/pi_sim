#!/usr/bin/env python3
"""
analyze_firewall_logs.py — Parse mqtt_firewall.jsonl and print a human-readable report.

Usage:
    python scripts/analyze_firewall_logs.py
    python scripts/analyze_firewall_logs.py --jsonl Firewall_logs/mqtt_firewall.jsonl
    python scripts/analyze_firewall_logs.py --event verdict          # filter by event type
    python scripts/analyze_firewall_logs.py --ip 192.168.1.42        # filter by IP
    python scripts/analyze_firewall_logs.py --since "2024-01-01 12:00:00"
    python scripts/analyze_firewall_logs.py --tail 50                # last N events
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# ── Default paths ──────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JSONL = REPO_ROOT / "Firewall_logs" / "mqtt_firewall.jsonl"


# ── Helpers ────────────────────────────────────────────────────────────────────
def load_events(path: Path, since: float | None, event_filter: str | None,
                ip_filter: str | None) -> list[dict]:
    events = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                print(f"  [WARN] line {lineno}: invalid JSON, skipped", file=sys.stderr)
                continue
            if since and ev.get("ts", 0) < since:
                continue
            if event_filter and ev.get("event") != event_filter:
                continue
            if ip_filter:
                ips = {ev.get("src_ip"), ev.get("flow_src_ip"), ev.get("ip")}
                if ip_filter not in ips:
                    continue
            events.append(ev)
    return events


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def fmt_bytes(b: int) -> str:
    if b >= 1_048_576:
        return f"{b/1_048_576:.1f} MB"
    if b >= 1_024:
        return f"{b/1_024:.1f} KB"
    return f"{b} B"


def divider(title: str = "") -> None:
    width = 72
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * (width - pad - len(title) - 2)}")
    else:
        print("─" * width)


# ── Report sections ────────────────────────────────────────────────────────────
def section_summary(events: list[dict]) -> None:
    divider("SUMMARY")
    by_event = Counter(e["event"] for e in events)
    verdicts = [e for e in events if e["event"] == "verdict"]
    attacks  = [e for e in verdicts if e.get("verdict") == "ATTACK"]
    blocks   = [e for e in events if e["event"] == "block_applied"]
    unblocks = [e for e in events if e["event"] == "block_removed"]
    packets  = [e for e in events if e["event"] == "packet_parsed"]

    if events:
        first, last = events[0]["ts"], events[-1]["ts"]
        print(f"  Time range : {fmt_ts(first)}  →  {fmt_ts(last)}")
        duration = last - first
        print(f"  Duration   : {duration:.0f}s ({duration/60:.1f} min)")

    print(f"  Total events     : {len(events)}")
    print(f"  Packets seen     : {len(packets)}")
    print(f"  Flows classified : {len(verdicts)}")
    if verdicts:
        pct = len(attacks) / len(verdicts) * 100
        print(f"  Attack flows     : {len(attacks)}  ({pct:.1f}%)")
        print(f"  Benign flows     : {len(verdicts) - len(attacks)}")
    print(f"  IPs blocked      : {len(blocks)}")
    print(f"  IPs unblocked    : {len(unblocks)}")


def section_verdicts(events: list[dict], top_n: int = 20) -> None:
    verdicts = [e for e in events if e["event"] == "verdict"]
    if not verdicts:
        return
    divider("FLOW VERDICTS")
    print(f"  {'TIME':<20} {'SRC':>21} {'DST':>21} {'VERDICT':<8} {'PROB':>6}  {'PKTS':>5}  {'BYTES':>9}  {'DUR':>7}")
    divider()
    for e in verdicts[-top_n:]:
        src = f"{e.get('flow_src_ip','?')}:{e.get('flow_src_port','?')}"
        dst = f"{e.get('flow_dst_ip','?')}:{e.get('flow_dst_port','?')}"
        label = e.get("verdict", "?")
        marker = "  <-- ATTACK" if label == "ATTACK" else ""
        print(
            f"  {fmt_ts(e['ts']):<20}  {src:>21}  {dst:>21}  {label:<8}"
            f"  {e.get('attack_prob', 0):.4f}  {e.get('flow_pkts', 0):>5}"
            f"  {fmt_bytes(e.get('flow_bytes', 0)):>9}  {e.get('flow_duration_s', 0):>6.2f}s"
            f"{marker}"
        )
    if len(verdicts) > top_n:
        print(f"  ... ({len(verdicts) - top_n} earlier verdicts hidden; use --tail to see more)")


def section_blocked_ips(events: list[dict]) -> None:
    blocks   = {e["ip"]: e for e in events if e["event"] == "block_applied"}
    unblocks = {e["ip"]: e for e in events if e["event"] == "block_removed"}
    expireds = {e["ip"] for e in events if e["event"] == "block_ttl_expired"}
    if not blocks:
        return
    divider("BLOCKED IPs")
    print(f"  {'IP':<18} {'BLOCKED AT':<22} {'STATUS'}")
    divider()
    for ip, ev in sorted(blocks.items()):
        if ip in unblocks:
            status = f"unblocked at {fmt_ts(unblocks[ip]['ts'])}"
        elif ip in expireds:
            status = "auto-unblocked (TTL)"
        else:
            status = "still blocked"
        print(f"  {ip:<18}  {fmt_ts(ev['ts']):<22}  {status}")


def section_top_talkers(events: list[dict], top_n: int = 10) -> None:
    packets = [e for e in events if e["event"] == "packet_parsed"]
    if not packets:
        return
    divider("TOP SOURCE IPs  (by packet count)")
    counts = Counter(e.get("src_ip", "?") for e in packets)
    bytes_by_ip: dict[str, int] = defaultdict(int)
    for e in packets:
        bytes_by_ip[e.get("src_ip", "?")] += e.get("payload_len", 0)

    print(f"  {'IP':<18}  {'PACKETS':>8}  {'PAYLOAD':>10}")
    divider()
    for ip, cnt in counts.most_common(top_n):
        print(f"  {ip:<18}  {cnt:>8}  {fmt_bytes(bytes_by_ip[ip]):>10}")


def section_attack_probs(events: list[dict]) -> None:
    verdicts = [e for e in events if e["event"] == "verdict"]
    if len(verdicts) < 2:
        return
    probs = [e.get("attack_prob", 0) for e in verdicts]
    divider("ATTACK PROBABILITY DISTRIBUTION")
    buckets = [0] * 10
    for p in probs:
        idx = min(int(p * 10), 9)
        buckets[idx] += 1
    bar_width = 30
    max_count = max(buckets) or 1
    for i, cnt in enumerate(buckets):
        lo, hi = i / 10, (i + 1) / 10
        bar = "#" * int(cnt / max_count * bar_width)
        print(f"  {lo:.1f}–{hi:.1f}  {bar:<{bar_width}}  {cnt}")


def section_firewall_config(events: list[dict]) -> None:
    startup = next((e for e in events if e["event"] == "firewall_startup"), None)
    if not startup:
        return
    divider("FIREWALL CONFIGURATION  (from startup event)")
    skip = {"event", "ts"}
    for k, v in sorted(startup.items()):
        if k not in skip:
            print(f"  {k:<25} {v}")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Analyze mqtt_firewall.jsonl logs")
    parser.add_argument(
        "--jsonl", default=str(DEFAULT_JSONL),
        help=f"Path to .jsonl log file (default: {DEFAULT_JSONL})"
    )
    parser.add_argument("--event",  help="Show only events of this type (e.g. verdict, block_applied)")
    parser.add_argument("--ip",     help="Filter events involving this IP address")
    parser.add_argument("--since",  help="Show events after this datetime (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--tail",   type=int, default=20, help="Max verdict rows to display (default: 20)")
    args = parser.parse_args()

    path = Path(args.jsonl)
    if not path.exists():
        print(f"Error: log file not found: {path}", file=sys.stderr)
        print("Make sure FW_JSON_EVENT_LOGS=true and the firewall has been run.", file=sys.stderr)
        sys.exit(1)

    since_ts = None
    if args.since:
        since_ts = datetime.strptime(args.since, "%Y-%m-%d %H:%M:%S").timestamp()

    events = load_events(path, since_ts, args.event, args.ip)
    if not events:
        print("No matching events found.")
        return

    print(f"\nLog file : {path}")
    print(f"Events   : {len(events)} loaded")

    if args.event:
        # Raw dump mode when filtering by event type
        divider(f"EVENT: {args.event}")
        for e in events[-args.tail:]:
            print(f"  {fmt_ts(e['ts'])}  {json.dumps({k: v for k, v in e.items() if k not in ('event','ts','features')}, separators=(',', ':'))}")
        return

    section_firewall_config(events)
    section_summary(events)
    section_blocked_ips(events)
    section_verdicts(events, top_n=args.tail)
    section_top_talkers(events)
    section_attack_probs(events)
    print()


if __name__ == "__main__":
    main()
