#!/usr/bin/env python3
"""
Second client Pi: generate traffic only. Do not start this on the Pi that
runs client_runner.py. It does not talk to the gateway agent, so it will not
start or stop a session.

    sudo .venv/bin/python experiments/extra_client.py --gateway <GATEWAY_IP> --tag pi2
    sudo .venv/bin/python experiments/extra_client.py --gateway <IP> --tag pi2 --attacks

--attacks runs the plan.py attack list once (60 s each) while benign clients
keep publishing. syn_flood is included only when this process is root.
Ctrl+C stops everything.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from experiments import plan  # noqa: E402

PYTHON = str(REPO_ROOT / ".venv" / "bin" / "python")
IS_ROOT = os.geteuid() == 0


def _launch(args: list[str], env: dict) -> subprocess.Popen:
    return subprocess.Popen(args, cwd=REPO_ROOT, env=env, preexec_fn=os.setsid)


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=8)
    except (subprocess.TimeoutExpired, ProcessLookupError):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--tag", default="pi2", help="Prefix for benign device ids")
    parser.add_argument("--attacks", action="store_true")
    args = parser.parse_args()

    env = {
        **os.environ,
        "GATEWAY_IP": args.gateway,
        "GATEWAY_PORT": str(plan.MQTT_PORT),
        "PYTHONUNBUFFERED": "1",
        "BENIGN_STEADY_DEVICE_ID": f"{args.tag}-steady",
        "BENIGN_MIXED_DEVICE_ID": f"{args.tag}-mixed",
        "BENIGN_BURST_DEVICE_ID": f"{args.tag}-burst",
    }
    procs = []
    for name, cmd in plan.BENIGN_CLIENTS:
        procs.append(_launch([PYTHON, "benign_clients/run_benign.py", *cmd], env))
        time.sleep(0.4)
    print(f"[EXTRA] Benign clients for tag={args.tag} → {args.gateway}. Ctrl+C to stop.")

    try:
        if args.attacks:
            attacks = [a for a in plan.ATTACKS if IS_ROOT or not a[2]]
            skipped = [a[0] for a in plan.ATTACKS if a not in attacks]
            if skipped:
                print(f"[EXTRA] Not root, skipping {skipped}")
            for i, (name, cmd, _) in enumerate(attacks, 1):
                print(f"[EXTRA] attack {i}/{len(attacks)}: {name} for {plan.ATTACK_S}s")
                proc = _launch([PYTHON, "attack_clients/run_attack.py", *cmd], env)
                time.sleep(plan.ATTACK_S)
                _kill(proc)
                time.sleep(plan.GAP_S)
            print("[EXTRA] Attack pass done. Benign clients still running.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[EXTRA] Stopping.")
    finally:
        for proc in procs:
            _kill(proc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
