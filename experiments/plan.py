"""
plan.py — Labelled live-evaluation plan (paper Section "Labelled Live Detection").

Shared by experiments/gateway_agent.py (gateway Pi) and
experiments/client_runner.py (client Pi). Edit here, commit, pull on both Pis.

Runs
  R1  benign only                     IDS
  R2  each attack alone (sequential)  IDS
  R3  benign + attacks                IDS
  R4  benign + attacks                IPS, gateway-local clients allow-listed
  R5  benign + attacks                IPS, no allow-list
"""

from __future__ import annotations

CONTROL_PORT = 9100
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
ATTACKS = [
    ("flood",              ["flood", "--rate", "1"], False),
    ("malformed",          ["malformed", "--rate", "1"], False),
    ("slowloris",          ["slowloris", "--mode", "hold", "--connections", "5"], False),
    ("connect_flood",      ["connect_flood", "--mode", "serial", "--rate", "1"], False),
    ("connect_flood_ddos", ["connect_flood", "--mode", "parallel", "--threads", "5", "--rate", "1"], False),
    ("port_scan",          ["port_scan", "--mode", "port_scan", "--rate", "1",
                            "--start", "1870", "--end", "1900"], False),
    ("vul_scan",           ["port_scan", "--mode", "vul_scan", "--rate", "1"], False),
    ("udp_flood",          ["udp_flood", "--mode", "dos", "--rate", "1"], False),
    ("udp_flood_ddos",     ["udp_flood", "--mode", "ddos", "--threads", "5", "--rate", "1"], False),
    ("syn_flood",          ["syn_flood", "--mode", "dos", "--rate", "1"], True),
]

RUNS = {
    "R1": {"benign": True,  "attacks": False, "block": False, "allow_list": False},
    "R2": {"benign": False, "attacks": True,  "block": False, "allow_list": False},
    "R3": {"benign": True,  "attacks": True,  "block": False, "allow_list": False},
    "R4": {"benign": True,  "attacks": True,  "block": True,  "allow_list": True},
    "R5": {"benign": True,  "attacks": True,  "block": True,  "allow_list": False},
}

# Timing (seconds). Gap must exceed FW_FLOW_TIMEOUT_S so attack windows do not overlap.
BENIGN_ONLY_S = 600
ATTACK_S = 60
GAP_S = 20
WARMUP_S = 20
DRAIN_S = 15


def session_name(run_id: str, rep: int) -> str:
    return f"{run_id}_rep{rep}"
