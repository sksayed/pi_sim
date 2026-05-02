#!/usr/bin/env python3
"""
attack_manager.py — Orchestrate attack + benign traffic against the MQTT gateway.

Three scenarios
───────────────
  sequential   Each attack runs alone for --duration seconds, then stops.
               Original evaluation mode.

  mixed        All attacks launch concurrently with --stagger gap between
               each start, all run for --duration seconds total.

  full_eval    The main research evaluation mode:
               • All four benign clients run throughout the entire session.
               • Each attack runs for --duration seconds (default 30s),
                 sequentially, with a --stagger gap between them.
               • After every attack window the firewall JSONL log is parsed
                 for verdict events that occurred during that window.
               • A detection summary table is printed at the end showing:
                   – Estimated messages sent (rate × duration)
                   – Packets seen by the firewall
                   – Flow verdicts issued (ATTACK / benign)
                   – Top detected attack type
               Rates are capped at 1 msg/s by default — safe for a Pi.

Usage
─────
    # Full evaluation (recommended — starts benign + all attacks, prints summary)
    python attack_clients/attack_manager.py --scenario full_eval

    # Override duration per attack and stagger gap
    python attack_clients/attack_manager.py --scenario full_eval --duration 30 --stagger 3

    # Original sequential / mixed modes
    python attack_clients/attack_manager.py --scenario sequential --duration 20
    python attack_clients/attack_manager.py --scenario mixed --duration 60

    # Show the attack + benign plan without running
    python attack_clients/attack_manager.py --list

Notes
─────
  • Root-required attacks (icmp_flood, syn_flood) are skipped
    automatically when not running as root; re-run with sudo to include them.
  • The replay attack is skipped if attack_clients/captured.jsonl does not exist.
    Capture first:  python attack_clients/run_attack.py replay --mode capture
  • Firewall stats require the firewall to be running and logging to its default
    JSONL path (firewall/Firewall_logs/mqtt_firewall.jsonl).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shlex
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON    = str(REPO_ROOT / ".venv" / "bin" / "python")

FIREWALL_JSONL = REPO_ROOT / "firewall" / "Firewall_logs" / "mqtt_firewall.jsonl"

# ── Attack definitions (Pi-friendly: rate = 1 msg/s) ─────────────────────────
# Each entry: (name, command, description, estimated_rate_per_s)
ATTACKS: list[tuple[str, str, str, float]] = [
    (
        "flood",
        f"{PYTHON} attack_clients/run_attack.py flood --rate 1",
        "MQTT publish flood             [MQTT-DoS/DDoS-Publish_Flood]",
        1.0,
    ),
    (
        "malformed",
        f"{PYTHON} attack_clients/run_attack.py malformed --rate 1",
        "Malformed payload mutations    [MQTT-Malformed_Data]",
        1.0,
    ),
    (
        "replay",
        f"{PYTHON} attack_clients/run_attack.py replay --mode replay --rate 1",
        "Replay captured messages        [replay pattern]",
        1.0,
    ),
    (
        "slowloris",
        f"{PYTHON} attack_clients/run_attack.py slowloris --mode hold --connections 5",
        "Slow-connection exhaustion      [TCP_IP-DoS-TCP]",
        0.2,   # ~1 new connection / 5s
    ),
    (
        "connect_flood",
        f"{PYTHON} attack_clients/run_attack.py connect_flood --mode serial --rate 1",
        "MQTT CONNECT/DISCONNECT flood   [MQTT-DoS-Connect_Flood]",
        1.0,
    ),
    (
        "connect_flood_ddos",
        f"{PYTHON} attack_clients/run_attack.py connect_flood --mode parallel --threads 5 --rate 1",
        "Concurrent MQTT connect flood   [MQTT-DDoS-Connect_Flood]",
        5.0,
    ),
    (
        "port_scan",
        f"{PYTHON} attack_clients/run_attack.py port_scan --mode port_scan --rate 1",
        "TCP port reconnaissance         [Recon-Port_Scan]",
        1.0,
    ),
    (
        "vul_scan",
        f"{PYTHON} attack_clients/run_attack.py port_scan --mode vul_scan --rate 1",
        "Vulnerability / banner scan     [Recon-VulScan]",
        1.0,
    ),
    (
        "udp_flood",
        f"{PYTHON} attack_clients/run_attack.py udp_flood --mode dos --rate 1",
        "UDP datagram flood              [TCP_IP-DoS-UDP]",
        1.0,
    ),
    (
        "udp_flood_ddos",
        f"{PYTHON} attack_clients/run_attack.py udp_flood --mode ddos --threads 5 --rate 1",
        "Concurrent UDP flood            [TCP_IP-DDoS-UDP]",
        5.0,
    ),
    # ── Root-required ─────────────────────────────────────────────────────────
    (
        "icmp_flood",
        f"{PYTHON} attack_clients/run_attack.py icmp_flood --mode dos --rate 1",
        "ICMP echo flood [root]          [TCP_IP-DoS-ICMP]",
        1.0,
    ),
    (
        "syn_flood",
        f"{PYTHON} attack_clients/run_attack.py syn_flood --mode dos --rate 1",
        "TCP SYN flood [root]            [TCP_IP-DoS-SYN]",
        1.0,
    ),
]

ROOT_ATTACKS = {"icmp_flood", "syn_flood"}

# ── Benign client definitions ─────────────────────────────────────────────────
# Run throughout the full_eval session in the background.
BENIGN_CLIENTS: list[tuple[str, str, str]] = [
    (
        "benign-steady",
        f"{PYTHON} benign_clients/run_benign.py steady --interval 2",
        "Steady steady client publish @ 0.5 msg/s  (client_a pattern)",
    ),
    (
        "benign-subscriber",
        f"{PYTHON} benign_clients/run_benign.py subscriber --qos 1",
        "Subscribe to nodes/+/data           (dashboard / monitor pattern)",
    ),
    (
        "benign-mixed",
        f"{PYTHON} benign_clients/run_benign.py mixed --min-interval 1 --max-interval 3 --idle-prob 0.05",
        "Publish + subscribe @ 0.3–1 msg/s   (real sensor node pattern)",
    ),
    (
        "benign-burst",
        f"{PYTHON} benign_clients/run_benign.py burst --burst-min 3 --burst-max 8 --rate 5 --idle-min 5 --idle-max 15",
        "Event-driven burst then idle         (motion / threshold sensor)",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Per-attack argument randomiser (used only in full_eval)
# ─────────────────────────────────────────────────────────────────────────────

_UDP_PORTS  = [1883, 8883, 5683, 1884, 49152]   # MQTT, MQTT-TLS, CoAP, alt-MQTT, ephemeral
_MQTT_PORTS = [1883, 8883, 1884]                 # TCP MQTT variants (all go through NFQUEUE)


def _build_random_cmd(name: str) -> tuple[str, str, float, dict]:
    """
    Return (cmd, sampled_args_summary, estimated_rate_per_s, extra_env) for `name`.

    Arguments and target/source ports are randomly sampled from Pi-safe ranges
    each time full_eval runs, so the firewall sees diverse traffic patterns
    within each attack class across repeated runs.
    extra_env is merged into the subprocess environment at launch time.
    """
    if name == "flood":
        rate = random.choice([1, 2, 5])
        port = random.choice(_MQTT_PORTS)
        return (
            f"{PYTHON} attack_clients/run_attack.py flood --rate {rate}",
            f"rate={rate} msg/s  port={port}",
            float(rate),
            {"GATEWAY_PORT": str(port)},
        )

    if name == "malformed":
        rate     = random.choice([1, 2])
        strategy = random.choice(["", "0", "1", "2", "3", "4", "5", "6", "7"])
        port     = random.choice(_MQTT_PORTS)
        s_arg    = f"--strategy {strategy}" if strategy else ""
        s_label  = f"strategy={'cycle-all' if not strategy else strategy}"
        return (
            f"{PYTHON} attack_clients/run_attack.py malformed --rate {rate} {s_arg}".strip(),
            f"rate={rate} msg/s  {s_label}  port={port}",
            float(rate),
            {"GATEWAY_PORT": str(port)},
        )

    if name == "replay":
        rate = random.choice([1, 2])
        port = random.choice(_MQTT_PORTS)
        return (
            f"{PYTHON} attack_clients/run_attack.py replay --mode replay --rate {rate}",
            f"rate={rate} msg/s  port={port}",
            float(rate),
            {"GATEWAY_PORT": str(port)},
        )

    if name == "slowloris":
        mode  = random.choice(["hold", "exhaust"])
        conns = random.randint(3, 10)
        port  = random.choice(_MQTT_PORTS)
        return (
            f"{PYTHON} attack_clients/run_attack.py slowloris --mode {mode} --connections {conns}",
            f"mode={mode}  connections={conns}  port={port}",
            0.2,
            {"GATEWAY_PORT": str(port)},
        )

    if name == "connect_flood":
        rate = random.choice([1, 2, 5])
        port = random.choice(_MQTT_PORTS)
        return (
            f"{PYTHON} attack_clients/run_attack.py connect_flood --mode serial --rate {rate}",
            f"mode=serial  rate={rate} conn/s  port={port}",
            float(rate),
            {"GATEWAY_PORT": str(port)},
        )

    if name == "connect_flood_ddos":
        threads = random.randint(3, 10)
        rate    = random.choice([1, 2])
        port    = random.choice(_MQTT_PORTS)
        return (
            f"{PYTHON} attack_clients/run_attack.py connect_flood --mode parallel"
            f" --threads {threads} --rate {rate}",
            f"mode=parallel  threads={threads}  rate={rate} conn/s/thread  port={port}",
            float(rate * threads),
            {"GATEWAY_PORT": str(port)},
        )

    if name == "port_scan":
        start = random.choice([1, 20, 80])
        end   = start + random.choice([100, 500, 1024])
        return (
            f"{PYTHON} attack_clients/run_attack.py port_scan --mode port_scan"
            f" --rate 1 --start {start} --end {end}",
            f"mode=port_scan  range={start}-{end}",
            1.0,
            {},
        )

    if name == "vul_scan":
        rate = random.choice([1, 2])
        return (
            f"{PYTHON} attack_clients/run_attack.py port_scan --mode vul_scan --rate {rate}",
            f"mode=vul_scan  rate={rate} probes/s",
            float(rate),
            {},
        )

    if name == "udp_flood":
        payload = random.choice([64, 128, 512, 1024])
        rate    = random.choice([1, 2, 5])
        port    = random.choice(_UDP_PORTS)
        return (
            f"{PYTHON} attack_clients/run_attack.py udp_flood --mode dos"
            f" --rate {rate} --payload {payload}",
            f"mode=dos  rate={rate} pkt/s  payload={payload}B  port={port}",
            float(rate),
            {"UDP_FLOOD_TARGET_PORT": str(port)},
        )

    if name == "udp_flood_ddos":
        threads = random.randint(3, 8)
        payload = random.choice([64, 512, 1024])
        rate    = random.choice([1, 2])
        port    = random.choice(_UDP_PORTS)
        return (
            f"{PYTHON} attack_clients/run_attack.py udp_flood --mode ddos"
            f" --threads {threads} --rate {rate} --payload {payload}",
            f"mode=ddos  threads={threads}  rate={rate} pkt/s/thread  payload={payload}B  port={port}",
            float(rate * threads),
            {"UDP_FLOOD_TARGET_PORT": str(port)},
        )

    if name == "icmp_flood":
        payload = random.choice([56, 128, 512, 1024])
        mode    = random.choice(["dos", "ddos"])
        threads = random.randint(2, 6) if mode == "ddos" else 1
        t_arg   = f"--threads {threads}" if mode == "ddos" else ""
        return (
            f"{PYTHON} attack_clients/run_attack.py icmp_flood --mode {mode}"
            f" --rate 1 --payload {payload} {t_arg}".strip(),
            f"mode={mode}  payload={payload}B  threads={threads}",
            float(threads),
            {},   # ICMP has no port concept
        )

    if name == "syn_flood":
        mode    = random.choice(["dos", "ddos"])
        threads = random.randint(2, 6) if mode == "ddos" else 1
        port    = random.choice(_MQTT_PORTS)
        spoof   = random.choice(["0", "1"])   # randomise source port each packet when 1
        t_arg   = f"--threads {threads}" if mode == "ddos" else ""
        return (
            f"{PYTHON} attack_clients/run_attack.py syn_flood --mode {mode}"
            f" --rate 1 {t_arg}".strip(),
            f"mode={mode}  threads={threads}  dst_port={port}  src_spoof={spoof}",
            float(threads),
            {"SYN_FLOOD_TARGET_PORT": str(port), "SYN_FLOOD_SPOOF": spoof},
        )

    # Fallback — should never be reached
    raise ValueError(f"No randomiser defined for attack: {name}")


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _launch(cmd: str, name: str, capture: bool = False,
            extra_env: dict | None = None) -> subprocess.Popen:
    print(f"[{_ts()}] ▶  START  {name}")
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(
        shlex.split(cmd),
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
        text=True,
        env=env,
    )


def _stop(proc: subprocess.Popen, name: str) -> None:
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    print(f"[{_ts()}] ■  STOP   {name}")


def _filter_active(attacks: list, is_root: bool,
                   replay_exists: bool) -> list:
    out = []
    for entry in attacks:
        name = entry[0]
        if name == "replay" and not replay_exists:
            print(f"[WARN] Skipping 'replay' — no captured.jsonl found.\n"
                  f"       Run first: python attack_clients/run_attack.py replay --mode capture\n")
            continue
        if name in ROOT_ATTACKS and not is_root:
            continue
        out.append(entry)
    if not is_root:
        skipped = [e[0] for e in attacks if e[0] in ROOT_ATTACKS]
        if skipped:
            print(f"[WARN] Not root — skipping {skipped}. Re-run with sudo to include them.\n")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Firewall JSONL stats parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_firewall_stats(
    windows: list[tuple[str, float, float]]
) -> dict[str, dict]:
    """
    Parse firewall/Firewall_logs/mqtt_firewall.jsonl and bucket verdict and
    packet-parsed events into the time window of each attack.

    Returns a dict keyed by attack name:
        {
          "packets_seen": int,      # packet_parsed events in window
          "verdicts":     int,      # verdict events in window
          "attack_v":     int,      # ATTACK verdicts
          "benign_v":     int,      # benign verdicts
          "top_type":     str,      # most common attack_type label
          "by_type":      dict,     # label -> count
        }
    """
    stats: dict[str, dict] = {
        name: {
            "packets_seen": 0,
            "verdicts":     0,
            "attack_v":     0,
            "benign_v":     0,
            "top_type":     "—",
            "by_type":      defaultdict(int),
        }
        for name, _, _ in windows
    }

    if not FIREWALL_JSONL.exists():
        print(f"[WARN] Firewall JSONL not found at {FIREWALL_JSONL} — no detection stats.")
        return stats

    # Build sorted list of (start_ts, end_ts, name) for O(n) scan
    sorted_windows = sorted(windows, key=lambda x: x[1])

    with open(FIREWALL_JSONL) as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                continue

            ts    = ev.get("ts", 0.0)
            event = ev.get("event", "")

            for name, t0, t1 in sorted_windows:
                if t0 <= ts <= t1:
                    s = stats[name]
                    if event == "packet_parsed":
                        s["packets_seen"] += 1
                    elif event == "verdict":
                        s["verdicts"] += 1
                        if ev.get("verdict") == "ATTACK":
                            s["attack_v"] += 1
                            atype = ev.get("attack_type", "unknown")
                            s["by_type"][atype] += 1
                        else:
                            s["benign_v"] += 1
                    break   # each event belongs to exactly one window

    # Resolve top_type
    for name, s in stats.items():
        if s["by_type"]:
            s["top_type"] = max(s["by_type"], key=lambda k: s["by_type"][k])

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# Detection summary printer
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(
    windows:    list[tuple[str, float, float]],
    rate_map:   dict[str, float],
    duration_s: float,
    stats:      dict[str, dict],
) -> None:
    sep = "─" * 110
    print(f"\n{sep}")
    print("  ATTACK MANAGER — DETECTION SUMMARY")
    print(sep)
    header = (
        f"  {'Attack':<22} {'Est.Sent':>9} {'Pkts Seen':>10} "
        f"{'Verdicts':>9} {'ATTACK':>7} {'Benign':>7}  Top Detected Type"
    )
    print(header)
    print(sep)

    total_sent    = 0
    total_pkts    = 0
    total_verd    = 0
    total_attack  = 0
    total_benign  = 0

    for name, t0, t1 in windows:
        s    = stats.get(name, {})
        rate = rate_map.get(name, 1.0)
        est  = int(rate * duration_s)
        pkts = s.get("packets_seen", 0)
        verd = s.get("verdicts",     0)
        atk  = s.get("attack_v",     0)
        ben  = s.get("benign_v",     0)
        top  = s.get("top_type",     "—")

        total_sent   += est
        total_pkts   += pkts
        total_verd   += verd
        total_attack += atk
        total_benign += ben

        det_rate = f"{atk/verd*100:.0f}%" if verd else "n/a"
        print(
            f"  {name:<22} {est:>9,} {pkts:>10,} "
            f"{verd:>9,} {atk:>7,} {ben:>7,}  {top}  ({det_rate})"
        )

    print(sep)
    overall_det = f"{total_attack/total_verd*100:.0f}%" if total_verd else "n/a"
    print(
        f"  {'TOTAL':<22} {total_sent:>9,} {total_pkts:>10,} "
        f"{total_verd:>9,} {total_attack:>7,} {total_benign:>7,}  overall detection: {overall_det}"
    )
    print(f"{sep}\n")
    print("  Legend:")
    print("    Est.Sent  — estimated messages sent (rate_hz × duration_s)")
    print("    Pkts Seen — raw TCP packets observed by the firewall in this window")
    print("    Verdicts  — flow-level classification decisions issued")
    print("    ATTACK    — flows classified as attack (any class ≠ Benign)")
    print("    Benign    — flows classified as benign")
    print(f"{sep}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Scenario runners
# ─────────────────────────────────────────────────────────────────────────────

def run_sequential(attacks: list, duration: float, stagger: float) -> None:
    print(f"\n[MANAGER] Scenario: sequential | each attack {duration}s | stagger {stagger}s\n")
    for name, cmd, desc, _ in attacks:
        print(f"[{_ts()}] ── {name}: {desc}")
        proc = _launch(cmd, name)
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            _stop(proc, name)
            raise
        _stop(proc, name)
        if stagger > 0:
            print(f"[{_ts()}]    (gap {stagger}s)")
            time.sleep(stagger)
    print(f"\n[{_ts()}] Sequential run complete.")


def run_mixed(attacks: list, duration: float, stagger: float) -> None:
    print(f"\n[MANAGER] Scenario: mixed | stagger {stagger}s | total ~{duration}s\n")
    procs: list[tuple[str, subprocess.Popen]] = []
    try:
        for name, cmd, desc, _ in attacks:
            print(f"[{_ts()}] ── {name}: {desc}")
            procs.append((name, _launch(cmd, name)))
            time.sleep(stagger)

        print(f"[{_ts()}] All attacks running. Waiting {duration}s...")
        time.sleep(duration)

    except KeyboardInterrupt:
        print(f"\n[{_ts()}] Interrupted.")
    finally:
        for name, proc in procs:
            _stop(proc, name)
        print(f"[{_ts()}] Mixed run complete.")


def run_full_eval(attacks: list, duration: float, stagger: float) -> None:
    """
    Full evaluation scenario:
      1. Start all benign clients in the background.
      2. Run each attack sequentially for `duration` seconds.
      3. Stop all benign clients.
      4. Parse the firewall JSONL and print a detection summary.
    """
    print(f"\n[MANAGER] Scenario: full_eval")
    print(f"[MANAGER] Attacks: {len(attacks)}  |  Duration per attack: {duration}s  |  Stagger: {stagger}s")
    print(f"[MANAGER] Estimated total time: ~{len(attacks) * (duration + stagger):.0f}s "
          f"({len(attacks) * (duration + stagger) / 60:.1f} min)")
    print(f"[MANAGER] Benign clients: {len(BENIGN_CLIENTS)} (running throughout)\n")

    # ── 1. Start benign clients ───────────────────────────────────────────────
    benign_procs: list[tuple[str, subprocess.Popen]] = []
    for name, cmd, desc in BENIGN_CLIENTS:
        print(f"[{_ts()}] 🟢 BENIGN  {name}: {desc}")
        benign_procs.append((name, _launch(cmd, name)))
        time.sleep(0.3)

    print(f"\n[{_ts()}] Benign clients running. Starting attacks in 2s...\n")
    time.sleep(2)

    # ── 2. Run attacks sequentially with randomised args, record time windows ──
    windows:  list[tuple[str, float, float]] = []
    rate_map: dict[str, float] = {}

    print(f"[{_ts()}] Sampling randomised arguments for each attack ...\n")
    sampled: list[tuple[str, str, str, float]] = []   # (name, cmd, args_summary, rate)
    for name, _base_cmd, desc, _base_rate in attacks:
        try:
            cmd, args_summary, rate = _build_random_cmd(name)
        except ValueError:
            # No randomiser defined — fall back to base command
            cmd, args_summary, rate = _base_cmd, "(fixed args)", _base_rate
        sampled.append((name, cmd, args_summary, rate))
        print(f"  {name:<22}  {args_summary}")

    print()

    try:
        for name, cmd, args_summary, rate_hz in sampled:
            print(f"[{_ts()}] ── ATTACK  {name}  [{args_summary}]")
            print(f"           cmd: {cmd}")
            t0   = time.time()
            proc = _launch(cmd, name)

            try:
                time.sleep(duration)
            except KeyboardInterrupt:
                _stop(proc, name)
                raise

            _stop(proc, name)
            t1 = time.time()
            windows.append((name, t0, t1))
            rate_map[name] = rate_hz

            if stagger > 0:
                print(f"[{_ts()}]    (stagger {stagger}s)")
                time.sleep(stagger)

    except KeyboardInterrupt:
        print(f"\n[{_ts()}] Interrupted during attacks.")

    finally:
        # ── 3. Stop benign clients ────────────────────────────────────────────
        print(f"\n[{_ts()}] Stopping benign clients ...")
        for name, proc in benign_procs:
            _stop(proc, name)

    # ── 4. Parse firewall JSONL and print summary ─────────────────────────────
    if windows:
        print(f"\n[{_ts()}] Parsing firewall log: {FIREWALL_JSONL}")
        stats = _parse_firewall_stats(windows)
        _print_summary(windows, rate_map, duration, stats)
    else:
        print(f"[{_ts()}] No attack windows recorded — no summary to show.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _list_plan() -> None:
    print("\n── Attack clients ──────────────────────────────────────────────────────────")
    for i, (name, cmd, desc, rate) in enumerate(ATTACKS, 1):
        root_tag = " [root]" if name in ROOT_ATTACKS else ""
        print(f"  {i:2d}. {name:<22}{root_tag}  {desc}")
        print(f"        rate: {rate} msg/s   cmd: {cmd}")
    print()
    print("── Benign clients (full_eval only) ─────────────────────────────────────────")
    for i, (name, cmd, desc) in enumerate(BENIGN_CLIENTS, 1):
        print(f"  {i:2d}. {name:<22}  {desc}")
        print(f"        cmd: {cmd}")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Attack manager — orchestrate attack + benign traffic for IDS/IPS evaluation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario",
        choices=["sequential", "mixed", "full_eval"],
        default="full_eval",
        help="sequential: one attack at a time | mixed: all concurrent | "
             "full_eval: benign throughout + sequential attacks + detection summary (default)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Seconds each attack runs. Default: 30",
    )
    parser.add_argument(
        "--stagger",
        type=float,
        default=2.0,
        help="Seconds between attack launches. Default: 2",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print the full attack + benign plan without running.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.list:
        _list_plan()
        return 0

    is_root      = os.geteuid() == 0
    replay_ok    = (REPO_ROOT / "attack_clients" / "captured.jsonl").exists()
    active       = _filter_active(ATTACKS, is_root, replay_ok)

    if not active:
        print("[ERROR] No attacks to run.")
        return 1

    try:
        if args.scenario == "sequential":
            run_sequential(active, args.duration, args.stagger)
        elif args.scenario == "mixed":
            run_mixed(active, args.duration, args.stagger)
        else:
            run_full_eval(active, args.duration, args.stagger)
    except KeyboardInterrupt:
        print(f"\n[{_ts()}] Stopped by user.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
