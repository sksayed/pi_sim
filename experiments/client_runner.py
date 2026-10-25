#!/usr/bin/env python3
"""
client_runner.py — Client-Pi side of the labelled live evaluation.

Start experiments/gateway_agent.py on the gateway Pi first, then:

    sudo .venv/bin/python experiments/client_runner.py --gateway <GATEWAY_PI_IP>
    sudo .venv/bin/python experiments/client_runner.py --gateway <IP> --runs R1 --reps 1

Root is needed only for syn_flood; without it, syn_flood is skipped.

For each session it asks the gateway to start, runs the benign clients and/or
the attack schedule from plan.py, waits for the firewall to drain, and asks
the gateway to stop. Ground truth goes to results/client/<session>/:

  benign_conns.csv   every benign MQTT connection with its local port
  benign_sends.csv   every benign publish (device_id, seq)
  attack_windows.csv start/end wall time of each attack
  meta.json          plan, clock offset to the gateway, client IP
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

VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
PYTHON = str(VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable))
RESULTS_DIR = REPO_ROOT / "results" / "client"
IS_ROOT = os.geteuid() == 0


def _call(gateway: str, req: dict, timeout: float = 120.0) -> dict:
    with socket.create_connection((gateway, plan.CONTROL_PORT), timeout=timeout) as s:
        s.sendall((json.dumps(req) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    resp = json.loads(data.decode())
    if not resp.get("ok"):
        raise RuntimeError(f"gateway refused {req.get('cmd')}: {resp.get('error')}")
    return resp


def _clock_offset(gateway: str) -> float:
    """Gateway clock minus client clock, in seconds (median of 5 pings)."""
    samples = []
    for _ in range(5):
        t0 = time.time()
        resp = _call(gateway, {"cmd": "ping"}, timeout=10)
        t1 = time.time()
        samples.append(resp["gw_time"] - (t0 + t1) / 2)
    return sorted(samples)[len(samples) // 2]


def _local_ip_towards(gateway: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((gateway, plan.MQTT_PORT))
        return s.getsockname()[0]


def _launch(args: list[str], log_path: Path, env: dict) -> subprocess.Popen:
    return subprocess.Popen(
        args, cwd=REPO_ROOT, env=env,
        stdout=open(log_path, "w"), stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_session(gateway: str, run_id: str, rep: int, attacks: list) -> None:
    run = plan.RUNS[run_id]
    session = plan.session_name(run_id, rep)
    out = RESULTS_DIR / session
    out.mkdir(parents=True, exist_ok=True)
    for name, header in (
        ("benign_conns.csv", "ts_unix_ns,client,device_id,local_ip,local_port"),
        ("benign_sends.csv", "ts_unix_ns,client,device_id,seq,qos,rc"),
        ("attack_windows.csv", "attack,start_wall_ns,end_wall_ns"),
    ):
        (out / name).write_text(header + "\n")

    env = {**os.environ, "GATEWAY_IP": gateway, "GATEWAY_PORT": str(plan.MQTT_PORT),
           "BENIGN_LOG_DIR": str(out), "PYTHONUNBUFFERED": "1"}

    print(f"\n[CLIENT] ===== {session}  benign={run['benign']}  attacks={run['attacks']}  "
          f"IPS={run['block']}  allow_list={run['allow_list']} =====")
    offset = _clock_offset(gateway)
    _call(gateway, {"cmd": "start", "session": session, "run": run_id, "rep": rep,
                    "gateway_ip": gateway})
    meta = {
        "session": session, "run": run_id, "rep": rep, "run_config": run,
        "gateway_ip": gateway, "client_ip": _local_ip_towards(gateway),
        "client_host": socket.gethostname(), "clock_offset_s": offset,
        "attacks": [a[0] for a in attacks] if run["attacks"] else [],
        "timing": {"benign_only_s": plan.BENIGN_ONLY_S, "attack_s": plan.ATTACK_S,
                   "gap_s": plan.GAP_S, "warmup_s": plan.WARMUP_S, "drain_s": plan.DRAIN_S},
        "start_wall_ns": time.time_ns(),
    }

    benign_procs = []
    try:
        if run["benign"]:
            for name, args in plan.BENIGN_CLIENTS:
                benign_procs.append(_launch(
                    [PYTHON, "benign_clients/run_benign.py", *args], out / f"benign_{name}.log", env))
                time.sleep(0.5)
            print(f"[CLIENT] benign clients running; warm-up {plan.WARMUP_S}s")
            time.sleep(plan.WARMUP_S)

        if run["attacks"]:
            for i, (name, args, _) in enumerate(attacks, 1):
                print(f"[CLIENT] attack {i}/{len(attacks)}: {name} for {plan.ATTACK_S}s")
                t_start = time.time_ns()
                proc = _launch([PYTHON, "attack_clients/run_attack.py", *args],
                               out / f"attack_{name}.log", env)
                time.sleep(plan.ATTACK_S)
                _kill(proc)
                with open(out / "attack_windows.csv", "a") as f:
                    f.write(f"{name},{t_start},{time.time_ns()}\n")
                time.sleep(plan.GAP_S)
        else:
            print(f"[CLIENT] benign only for {plan.BENIGN_ONLY_S}s")
            time.sleep(plan.BENIGN_ONLY_S)
    finally:
        for proc in benign_procs:
            _kill(proc)
        print(f"[CLIENT] draining {plan.DRAIN_S}s")
        time.sleep(plan.DRAIN_S)
        meta["stop_wall_ns"] = time.time_ns()
        (out / "meta.json").write_text(json.dumps(meta, indent=2))
        _call(gateway, {"cmd": "stop", "session": session})
        print(f"[CLIENT] ===== {session} saved to {out} =====")


def _estimate_minutes(runs: list[str], n_attacks: int, reps: int) -> float:
    per = 0.0
    for r in runs:
        cfg = plan.RUNS[r]
        t = plan.WARMUP_S if cfg["benign"] else 0
        t += n_attacks * (plan.ATTACK_S + plan.GAP_S) if cfg["attacks"] else plan.BENIGN_ONLY_S
        per += t + plan.DRAIN_S + 25
    return per * reps / 60


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway", required=True, help="Gateway Pi IP address")
    parser.add_argument("--runs", default="R1,R2,R3,R4,R5")
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--first-rep", type=int, default=1)
    args = parser.parse_args()

    runs = [r.strip().upper() for r in args.runs.split(",") if r.strip()]
    unknown = [r for r in runs if r not in plan.RUNS]
    if unknown:
        print(f"Unknown runs: {unknown}. Choose from {list(plan.RUNS)}")
        return 1

    attacks = [a for a in plan.ATTACKS if IS_ROOT or not a[2]]
    skipped = [a[0] for a in plan.ATTACKS if a not in attacks]
    if skipped:
        print(f"[CLIENT] Not root: skipping {skipped}. Use sudo to include them.")

    try:
        resp = _call(args.gateway, {"cmd": "ping"}, timeout=10)
    except OSError as exc:
        print(f"[CLIENT] Cannot reach the gateway agent at {args.gateway}:{plan.CONTROL_PORT} ({exc}).")
        print("         Is gateway_agent.py running, and are both Pis on the same hotspot?")
        return 1
    print(f"[CLIENT] Gateway agent on {resp['host']} reachable.")
    print(f"[CLIENT] Plan: runs={runs} reps={args.reps} — about "
          f"{_estimate_minutes(runs, len(attacks), args.reps):.0f} min")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        for rep in range(args.first_rep, args.first_rep + args.reps):
            for run_id in runs:
                run_session(args.gateway, run_id, rep, attacks)
    except KeyboardInterrupt:
        print("\n[CLIENT] Interrupted.")
    finally:
        user = os.getenv("SUDO_USER")
        if user:
            subprocess.run(["chown", "-R", f"{user}:{user}", str(RESULTS_DIR.parent)], check=False)

    _call(args.gateway, {"cmd": "finish"}, timeout=10)
    print("[CLIENT] All done. Results in results/client/ — now run: git add results && git commit && git push")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
