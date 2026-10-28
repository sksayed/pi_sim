#!/usr/bin/env python3
"""
Second client Pi: join a labelled session as traffic + ground-truth peer.

Start experiments/gateway_agent.py on the gateway and experiments/client_runner.py
on Client Pi A first. This Pi does not start or stop sessions.

    sudo .venv/bin/python experiments/extra_client.py --tag pi2
    sudo .venv/bin/python experiments/extra_client.py --tag pi2 --attacks
    sudo .venv/bin/python experiments/extra_client.py --gateway 192.168.x.x --tag pi2

Without --gateway it uses the same UDP beacon / subnet scan as client_runner.
It waits until Pi A has started a session, registers as a peer, writes CSVs under
results/client/<session>/peers/<tag>/, and stops when that session ends.

Root is needed only for syn_flood; without it that attack is skipped.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from experiments import plan  # noqa: E402
from experiments.client_runner import (  # noqa: E402
    _call,
    _clock_offset,
    _local_ip_towards,
    find_gateway,
)

PYTHON = str(REPO_ROOT / ".venv" / "bin" / "python")
IS_ROOT = os.geteuid() == 0
RESULTS_DIR = REPO_ROOT / "results" / "client"


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


def _wait_for_session(gateway: str, want: str | None, timeout_s: float) -> str:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            st = _call(gateway, {"cmd": "status"}, timeout=5)
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"[EXTRA] status failed: {exc}")
            time.sleep(2)
            continue
        session = st.get("session")
        if session and (want is None or session == want):
            return session
        print(f"[EXTRA] Waiting for Pi A to start a session"
              f"{f' ({want})' if want else ''} ...")
        time.sleep(2)
    raise SystemExit("Timed out waiting for an active session on the gateway agent")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway", help="Gateway Pi IP (default: find automatically)")
    parser.add_argument("--tag", default="pi2", help="Peer tag and device-id prefix")
    parser.add_argument("--session", help="Only join this session name (default: any active)")
    parser.add_argument("--attacks", action="store_true",
                        help="Run the plan attack list once while benign clients publish")
    parser.add_argument("--wait-s", type=float, default=3600,
                        help="How long to wait for Pi A to start a session")
    args = parser.parse_args()

    gateway = args.gateway or find_gateway()
    if not gateway:
        print("Could not find the gateway agent. Start it first, or pass --gateway.")
        return 1
    print(f"[EXTRA] Gateway agent at {gateway}")

    session = _wait_for_session(gateway, args.session, args.wait_s)
    client_ip = _local_ip_towards(gateway)
    offset = _clock_offset(gateway)
    _call(gateway, {
        "cmd": "register_peer",
        "session": session,
        "tag": args.tag,
        "host": socket.gethostname(),
    }, timeout=10)

    out = RESULTS_DIR / session / "peers" / args.tag
    out.mkdir(parents=True, exist_ok=True)
    for name, header in (
        ("benign_conns.csv", "ts_unix_ns,client,device_id,local_ip,local_port"),
        ("benign_sends.csv", "ts_unix_ns,client,device_id,seq,qos,rc"),
        ("attack_windows.csv", "attack,start_wall_ns,end_wall_ns"),
    ):
        (out / name).write_text(header + "\n")

    env = {
        **os.environ,
        "GATEWAY_IP": gateway,
        "GATEWAY_PORT": str(plan.MQTT_PORT),
        "PYTHONUNBUFFERED": "1",
        "BENIGN_LOG_DIR": str(out),
        "BENIGN_STEADY_DEVICE_ID": f"{args.tag}-steady",
        "BENIGN_MIXED_DEVICE_ID": f"{args.tag}-mixed",
        "BENIGN_BURST_DEVICE_ID": f"{args.tag}-burst",
    }

    meta = {
        "session": session,
        "role": "extra_client",
        "tag": args.tag,
        "gateway_ip": gateway,
        "client_ip": client_ip,
        "client_host": socket.gethostname(),
        "clock_offset_s": offset,
        "attacks": [],
        "start_wall_ns": time.time_ns(),
    }

    procs = []
    for name, cmd in plan.BENIGN_CLIENTS:
        procs.append(_launch([PYTHON, "benign_clients/run_benign.py", *cmd], env))
        time.sleep(0.4)
    print(f"[EXTRA] Joined {session} as tag={args.tag} ip={client_ip}. "
          f"Logs → {out}")

    try:
        if args.attacks:
            attacks = [a for a in plan.ATTACKS if IS_ROOT or not a[2]]
            skipped = [a[0] for a in plan.ATTACKS if a not in attacks]
            if skipped:
                print(f"[EXTRA] Not root, skipping {skipped}")
            meta["attacks"] = [a[0] for a in attacks]
            for i, (name, cmd, _) in enumerate(attacks, 1):
                st = _call(gateway, {"cmd": "status"}, timeout=5)
                if st.get("session") != session:
                    print("[EXTRA] Session ended during attacks; stopping.")
                    break
                print(f"[EXTRA] attack {i}/{len(attacks)}: {name} for {plan.ATTACK_S}s")
                t_start = time.time_ns()
                proc = _launch([PYTHON, "attack_clients/run_attack.py", *cmd], env)
                time.sleep(plan.ATTACK_S)
                _kill(proc)
                with open(out / "attack_windows.csv", "a") as fh:
                    fh.write(f"{name},{t_start},{time.time_ns()}\n")
                time.sleep(plan.GAP_S)
            print("[EXTRA] Attack pass done. Waiting for the session to end.")

        while True:
            try:
                st = _call(gateway, {"cmd": "status"}, timeout=5)
            except (OSError, ValueError, RuntimeError) as exc:
                print(f"[EXTRA] Lost agent ({exc}); stopping.")
                break
            if st.get("session") != session:
                print(f"[EXTRA] Session {session} ended on the agent.")
                break
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[EXTRA] Interrupted.")
    finally:
        for proc in procs:
            _kill(proc)
        meta["stop_wall_ns"] = time.time_ns()
        (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        print(f"[EXTRA] Saved {out / 'meta.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
