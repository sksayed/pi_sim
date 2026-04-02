#!/usr/bin/env python3
"""
Sequential benchmark driver for the client Pi: run each configured profile with
several payload sizes, one scenario at a time (connect → N publishes → disconnect).

Default: all 7 PQC research profiles + 3 classical profiles, 3 payload sizes
(~5 KB / ~10 KB / ~100 KB). **Each** scenario sends **600** MQTT publishes (profile × size),
then disconnects before the next scenario (30 × 600 = 18_000 total with defaults).

Requires broker + gateway running; same .env as manual runs (GATEWAY_IP, MASTER_SECRET).

Usage (repo root):
  python scripts/run_client_benchmark_matrix.py
  python scripts/run_client_benchmark_matrix.py --per-scenario 400 --interval 0.3
  python scripts/run_client_benchmark_matrix.py --profiles pqc --dry-run
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from dotenv import load_dotenv

load_dotenv(_REPO / ".env")

from client.classic_research_client import (  # noqa: E402
    ProfileClassicAes,
    ProfileClassicChaCha,
    ProfileClassicEcdhEcdsa,
)
from client.profile_1_baseline import Profile1_BaselineFloor  # noqa: E402
from client.profile_2_sig_min import Profile2_SignatureMinimization  # noqa: E402
from client.profile_3_kem_div import Profile3_KemDiversity  # noqa: E402
from client.profile_4_standard import Profile4_StandardizedCompliance  # noqa: E402
from client.profile_5_kem_cons import Profile5_KemConservative  # noqa: E402
from client.profile_6_sig_rob import Profile6_SignatureRobustness  # noqa: E402
from client.profile_7_optional_extreme import Profile7_ExtremeFallback  # noqa: E402

# (label for logs, client class)
PQC_PROFILES: list[tuple[str, type]] = [
    ("PQC profile-1", Profile1_BaselineFloor),
    ("PQC profile-2", Profile2_SignatureMinimization),
    ("PQC profile-3", Profile3_KemDiversity),
    ("PQC profile-4", Profile4_StandardizedCompliance),
    ("PQC profile-5", Profile5_KemConservative),
    ("PQC profile-6", Profile6_SignatureRobustness),
    ("PQC profile-7", Profile7_ExtremeFallback),
]

CLASSICAL_PROFILES: list[tuple[str, type]] = [
    ("CLASSICAL AES-GCM", ProfileClassicAes),
    ("CLASSICAL ChaCha20", ProfileClassicChaCha),
    ("CLASSICAL ECDH+ECDSA", ProfileClassicEcdhEcdsa),
]

DEFAULT_PAYLOAD_BYTES = [5120, 10240, 102400]


def _parse_sizes(s: str) -> list[int]:
    parts = [p.strip() for p in s.split(",") if p.strip()]
    out: list[int] = []
    for p in parts:
        out.append(int(p, 10))
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Run benchmark matrix on client Pi (sequential profiles × payload sizes).")
    p.add_argument(
        "--profiles",
        choices=("all", "pqc", "classical"),
        default="all",
        help="Which profile family to run (default: all 10).",
    )
    p.add_argument(
        "--payload-sizes",
        type=str,
        default=",".join(str(x) for x in DEFAULT_PAYLOAD_BYTES),
        help="Comma-separated plaintext target bytes (default: 5120,10240,102400).",
    )
    p.add_argument(
        "--per-scenario",
        type=int,
        default=600,
        help="MQTT publishes per (profile × payload size) scenario (default: 600).",
    )
    p.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Seconds between publishes (sets PUBLISH_INTERVAL for this script only).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print plan only; do not connect or publish.",
    )
    args = p.parse_args()

    if args.profiles == "pqc":
        rows = list(PQC_PROFILES)
    elif args.profiles == "classical":
        rows = list(CLASSICAL_PROFILES)
    else:
        rows = PQC_PROFILES + CLASSICAL_PROFILES

    sizes = _parse_sizes(args.payload_sizes)
    n_scenarios = len(rows) * len(sizes)
    if n_scenarios == 0:
        print("No scenarios.", file=sys.stderr)
        return 1

    per = max(1, int(args.per_scenario))
    grand_total = per * n_scenarios

    saved_interval = os.environ.get("PUBLISH_INTERVAL")
    saved_target = os.environ.get("PAYLOAD_TARGET_BYTES")

    print(
        f"Scenarios: {n_scenarios}  |  publishes per scenario: {per}  "
        f"|  matrix total: {grand_total}  |  payload sizes: {sizes}"
    )
    for label, cls in rows:
        for sz in sizes:
            print(f"  - {label} @ {sz} B")

    if args.dry_run:
        return 0

    try:
        if args.interval is not None:
            os.environ["PUBLISH_INTERVAL"] = str(args.interval)
        for label, cls in rows:
            for sz in sizes:
                os.environ["PAYLOAD_TARGET_BYTES"] = str(sz)
                print("\n" + "=" * 72)
                print(f"{label}  |  PAYLOAD_TARGET_BYTES={sz}  |  count={per}")
                print("=" * 72 + "\n")
                client = cls()
                client.run(max_messages=per)
    except KeyboardInterrupt:
        print("\nMatrix: stopped by user.", file=sys.stderr)
        return 130
    finally:
        if saved_interval is None:
            os.environ.pop("PUBLISH_INTERVAL", None)
        else:
            os.environ["PUBLISH_INTERVAL"] = saved_interval
        if saved_target is None:
            os.environ.pop("PAYLOAD_TARGET_BYTES", None)
        else:
            os.environ["PAYLOAD_TARGET_BYTES"] = saved_target

    print("\nDone. Client CSV:", os.getenv("BENCH_CSV_PATH", "benchmarks/client/pqc_metrics.csv"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
