"""
plan.py — Labelled live-evaluation plan (paper Section "Labelled Live Detection").

Shared by experiments/gateway_agent.py (gateway Pi) and
experiments/client_runner.py (client Pi). Edit here, commit, pull on both Pis.

Runs (two-Pi paper baseline)
  R1  benign only                     IDS
  R2  each attack alone (sequential)  IDS
  R3  benign + attacks                IDS
  R4  benign + attacks                IPS, gateway-local clients allow-listed
  R5  benign + attacks                IPS, no allow-list

Phase 4 (three-Pi + cloud). Use --first-rep 20+ for a clean campaign. Never reuse reps 6–9.
  Pi B is never idle: benign load on E1, attacks on E2–E5.
  E1  Pi A benign; Pi B benign;                         IPS + allow-list + cloud
  E2  Pi A benign; Pi B attacks-all;                    IDS + cloud
  E3  Pi A benign; Pi B attacks-all;                    IPS + allow-list + cloud
  E4  Pi A benign+attacks-slice-a; Pi B attacks-slice-b; IDS + cloud
  E5  Pi A benign+attacks-slice-a; Pi B attacks-slice-b; IPS + allow-list + cloud

E4/E5 partition ATTACKS so the combined schedule matches one full pass (E2/E3 volume).
"""

from __future__ import annotations

CONTROL_PORT = 9100
BEACON_PORT = 9101
BEACON_MAGIC = "pi_sim_gateway_agent"
MQTT_PORT = 1883

# Applied by the gateway agent in every session, overriding .env.
FIXED_FW_SETTINGS = {
    "FW_MIN_PKTS_CLASSIFY": "3",
    "FW_CLASSIFY_EVERY_N_PKTS": "20",
    "FW_FLOW_TIMEOUT_S": "10",
    "FW_ATTACK_THRESHOLD": "0.5",
    "FW_BLOCK_TTL_S": "0",
    "FW_VERBOSE_PACKET_LOGS": "false",
    "FW_JSON_EVENT_LOGS": "true",
    "FW_MIN_CLIENT_SHARE": "0.3",
    "FW_CLIENT_SHARE_BY": "bytes",
    "FW_BLOCK_AFTER_N": "2",
}

# The gateway's own subscriber connects over loopback.
INFRA_ALLOW_IPS = ["127.0.0.1"]

BENIGN_CLIENTS = [
    ("steady",     ["steady", "--interval", "2"]),
    ("subscriber", ["subscriber", "--qos", "1"]),
    ("mixed",      ["mixed", "--min-interval", "1", "--max-interval", "3", "--idle-prob", "0.05"]),
    ("burst",      ["burst", "--burst-min", "3", "--burst-max", "8", "--rate", "5",
                    "--idle-min", "5", "--idle-max", "15"]),
]

# (name, run_attack.py args, needs_root). All target the broker port 1883.
# Replay is excluded (no benign capture file); ICMP never reaches Stage 1.
# Publish flood ~80 pkt/s (CIC median 74-90). UDP floods use CIC's 50-byte frames
# (8-byte payload) at 500 pkt/s total, below CIC's ~20k pkt/s, which the Python
# NFQUEUE path on the gateway Pi cannot absorb.
ATTACKS = [
    ("flood",              ["flood", "--rate", "40"], False),
    ("malformed",          ["malformed", "--rate", "1"], False),
    ("slowloris",          ["slowloris", "--mode", "hold", "--connections", "5"], False),
    ("connect_flood",      ["connect_flood", "--mode", "serial", "--rate", "1"], False),
    ("connect_flood_ddos", ["connect_flood", "--mode", "parallel", "--threads", "5", "--rate", "1"], False),
    ("port_scan",          ["port_scan", "--mode", "port_scan", "--rate", "1",
                            "--start", "1870", "--end", "1900"], False),
    ("vul_scan",           ["port_scan", "--mode", "vul_scan", "--rate", "1"], False),
    ("udp_flood",          ["udp_flood", "--mode", "dos", "--rate", "500", "--payload", "8"], False),
    ("udp_flood_ddos",     ["udp_flood", "--mode", "ddos", "--threads", "5", "--rate", "100",
                            "--payload", "8"], False),
    ("syn_flood",          ["syn_flood", "--mode", "dos", "--rate", "1"], True),
]

RUNS = {
    "R1": {"benign": True,  "attacks": False, "block": False, "allow_list": False},
    "R2": {"benign": False, "attacks": True,  "block": False, "allow_list": False},
    "R3": {"benign": True,  "attacks": True,  "block": False, "allow_list": False},
    "R4": {"benign": True,  "attacks": True,  "block": True,  "allow_list": True},
    "R5": {"benign": True,  "attacks": True,  "block": True,  "allow_list": False},
    # Phase 4 — Pi B role is enforced by extra_client flags, not by the agent.
    # pi_b: benign | attacks_all | attacks_b  (never "off" in this matrix)
    "E1": {"benign": True,  "attacks": False, "block": True,  "allow_list": True,
           "attack_slice": "none", "pi_b": "benign"},
    "E2": {"benign": True,  "attacks": False, "block": False, "allow_list": False,
           "attack_slice": "none", "pi_b": "attacks_all"},
    "E3": {"benign": True,  "attacks": False, "block": True,  "allow_list": True,
           "attack_slice": "none", "pi_b": "attacks_all"},
    "E4": {"benign": True,  "attacks": True,  "block": False, "allow_list": False,
           "attack_slice": "a", "pi_b": "attacks_b"},
    "E5": {"benign": True,  "attacks": True,  "block": True,  "allow_list": True,
           "attack_slice": "a", "pi_b": "attacks_b"},
}

# Timing (seconds). Gap must exceed FW_FLOW_TIMEOUT_S so attack windows do not overlap.
BENIGN_ONLY_S = 600
ATTACK_S = 60
GAP_S = 20
WARMUP_S = 20
DRAIN_S = 15


def session_name(run_id: str, rep: int) -> str:
    return f"{run_id}_rep{rep}"


# Repetitions reported in the paper. Reps 1-5 were development trials
# (rules and attack rates were chosen on them); rep 10 was interrupted.
PAPER_REPS = (6, 7, 8, 9)

# Phase 4 three-Pi + cloud matrix (separate from PAPER_REPS).
PHASE4_REPS = (12, 13, 14)
PHASE4_RUNS = ("E1", "E2", "E3", "E4", "E5")


def is_paper_session(name: str) -> bool:
    run, _, rep = name.partition("_rep")
    return run in ("R1", "R2", "R3", "R4", "R5") and rep.isdigit() and int(rep) in PAPER_REPS


def is_phase4_session(name: str) -> bool:
    run, _, rep = name.partition("_rep")
    return run in PHASE4_RUNS and rep.isdigit() and int(rep) in PHASE4_REPS


def attack_slice(which: str) -> list:
    """Return a subset of ATTACKS.

    all  — full list (Pi B on E2/E3)
    a/b  — disjoint partition; a∪b = all, a∩b = ∅ (E4/E5 multi-source, same total volume)
    none — empty
    """
    which = (which or "all").lower()
    if which in ("none", "off", "-"):
        return []
    if which == "all":
        return list(ATTACKS)
    if which == "a":
        return [ATTACKS[i] for i in range(len(ATTACKS)) if i % 2 == 0]
    if which == "b":
        return [ATTACKS[i] for i in range(len(ATTACKS)) if i % 2 == 1]
    raise ValueError(f"Unknown attack slice {which!r}; use all|a|b|none")


def attacks_for_run(run_id: str, available: list | None = None) -> list:
    """Pi A attack list for this run, filtered by root availability if given."""
    cfg = RUNS[run_id]
    if not cfg.get("attacks"):
        return []
    wanted = attack_slice(cfg.get("attack_slice", "all"))
    if available is None:
        return wanted
    names = {a[0] for a in wanted}
    return [a for a in available if a[0] in names]


def pi_b_extra_args(run_id: str) -> list[str]:
    """CLI args for experiments/extra_client.py for this Phase 4 run (after --tag)."""
    role = RUNS[run_id].get("pi_b", "benign")
    if role in ("off", "idle"):
        return []
    if role == "benign":
        # Default extra_client: benign publishers only (no --attacks*).
        return []
    if role == "attacks_all":
        return ["--attacks-only", "--attack-slice", "all"]
    if role == "attacks_b":
        return ["--attacks-only", "--attack-slice", "b"]
    raise ValueError(f"Unknown pi_b role {role!r} for {run_id}")
