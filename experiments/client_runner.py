#!/usr/bin/env python3
"""
client_runner.py — Client-Pi side of the labelled live evaluation.

Start experiments/gateway_agent.py on the gateway Pi first, then:

    sudo .venv/bin/python experiments/client_runner.py
    sudo .venv/bin/python experiments/client_runner.py --runs R1 --reps 1

The gateway is found automatically (UDP broadcast, then a scan of the local
/24 network); pass --gateway <IP> to skip that.

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
from experiments.results_fs import chown_results_to_invoker, ensure_results_dir  # noqa: E402

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


def _listen_for_beacon(timeout_s: float) -> str | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", plan.BEACON_PORT))
        s.settimeout(1.0)
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                data, (ip, _) = s.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                if json.loads(data.decode()).get("magic") == plan.BEACON_MAGIC:
                    return ip
            except (ValueError, UnicodeDecodeError):
                continue
    return None


def _scan_subnet() -> str | None:
    from concurrent.futures import ThreadPoolExecutor

    try:
        own = _local_ip_towards("8.8.8.8")
    except OSError:
        own = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()[0]
    prefix = own.rsplit(".", 1)[0]

    def probe(host: str) -> str | None:
        try:
            if _call(host, {"cmd": "ping"}, timeout=0.7):
                return host
        except (OSError, ValueError, RuntimeError):
            return None
        return None

    hosts = [f"{prefix}.{i}" for i in range(1, 255) if f"{prefix}.{i}" != own]
    with ThreadPoolExecutor(max_workers=64) as pool:
        for found in pool.map(probe, hosts):
            if found:
                return found
    return None


def find_gateway() -> str | None:
    print(f"[CLIENT] Looking for the gateway agent (broadcast on UDP {plan.BEACON_PORT}) ...")
    ip = _listen_for_beacon(30)
    if ip:
        return ip
    print("[CLIENT] No broadcast heard; scanning the local network ...")
    return _scan_subnet()


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


def run_session(gateway: str, run_id: str, rep: int, available_attacks: list) -> None:
    run = plan.RUNS[run_id]
    session = plan.session_name(run_id, rep)
    out = RESULTS_DIR / session
    if (out / "meta.json").exists():
        raise RuntimeError(
            f"{session} already has meta.json — refusing to overwrite. "
            "Choose a free --first-rep (Phase 4 uses 12+; never 6–9)."
        )
    attacks = plan.attacks_for_run(run_id, available_attacks)
    ensure_results_dir(out)
    for name, header in (
        ("benign_conns.csv", "ts_unix_ns,client,device_id,local_ip,local_port"),
        ("benign_sends.csv", "ts_unix_ns,client,device_id,seq,qos,rc"),
        ("attack_windows.csv", "attack,start_wall_ns,end_wall_ns"),
    ):
        (out / name).write_text(header + "\n")

    env = {**os.environ, "GATEWAY_IP": gateway, "GATEWAY_PORT": str(plan.MQTT_PORT),
           "BENIGN_LOG_DIR": str(out), "PYTHONUNBUFFERED": "1"}

    pi_b = run.get("pi_b", "benign")
    print(f"\n[CLIENT] ===== {session}  benign={run['benign']}  attacks={run['attacks']}  "
          f"slice={run.get('attack_slice', 'all')}  IPS={run['block']}  "
          f"allow_list={run['allow_list']}  pi_b={pi_b} =====")
    if pi_b not in ("off", "idle", None, ""):
        extra = " ".join(plan.pi_b_extra_args(run_id))
        cmd = (f"sudo .venv/bin/python experiments/extra_client.py --tag pi2 "
               f"--session {session}" + (f" {extra}" if extra else ""))
        print(f"[CLIENT] Pi B (manual one-shot):  {cmd}")
        print("[CLIENT] Pi B (auto matrix):      sudo .venv/bin/python "
              "experiments/extra_client.py --tag pi2 --auto")
    else:
        print("[CLIENT] Pi B: leave idle for this session.")
    offset = _clock_offset(gateway)
    _call(gateway, {"cmd": "start", "session": session, "run": run_id, "rep": rep,
                    "gateway_ip": gateway})
    meta = {
        "session": session, "run": run_id, "rep": rep, "run_config": run,
        "gateway_ip": gateway, "client_ip": _local_ip_towards(gateway),
        "client_host": socket.gethostname(), "clock_offset_s": offset,
        "attacks": [a[0] for a in attacks],
        "attack_slice": run.get("attack_slice", "all"),
        "pi_b": pi_b,
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
    parser.add_argument("--gateway", help="Gateway Pi IP address (default: find it automatically)")
    parser.add_argument("--runs", default="R1,R2,R3,R4,R5")
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--first-rep", type=int, default=1)
    args = parser.parse_args()

    runs = [r.strip().upper() for r in args.runs.split(",") if r.strip()]
    unknown = [r for r in runs if r not in plan.RUNS]
    if unknown:
        print(f"Unknown runs: {unknown}. Choose from {list(plan.RUNS)}")
        return 1

    phase4 = [r for r in runs if r in plan.PHASE4_RUNS]
    if phase4:
        bad = [rep for rep in range(args.first_rep, args.first_rep + args.reps)
               if rep in plan.PAPER_REPS]
        if bad:
            print(f"[CLIENT] Refusing Phase 4 with paper reps {bad}. Use --first-rep 12 (or higher).")
            return 1

    available = [a for a in plan.ATTACKS if IS_ROOT or not a[2]]
    skipped = [a[0] for a in plan.ATTACKS if a not in available]
    if skipped:
        print(f"[CLIENT] Not root: skipping {skipped}. Use sudo to include them.")

    if not args.gateway:
        args.gateway = find_gateway()
        if not args.gateway:
            print("[CLIENT] Could not find the gateway agent. Is gateway_agent.py running, "
                  "and are both Pis on the same hotspot?")
            return 1
        print(f"[CLIENT] Found gateway at {args.gateway}")

    try:
        resp = _call(args.gateway, {"cmd": "ping"}, timeout=10)
    except OSError as exc:
        print(f"[CLIENT] Cannot reach the gateway agent at {args.gateway}:{plan.CONTROL_PORT} ({exc}).")
        print("         Is gateway_agent.py running, and are both Pis on the same hotspot?")
        return 1
    print(f"[CLIENT] Gateway agent on {resp['host']} reachable.")
    # Estimate using the longest attack list among selected runs.
    n_att = max((len(plan.attacks_for_run(r, available)) for r in runs), default=0)
    print(f"[CLIENT] Plan: runs={runs} reps={args.reps} — about "
          f"{_estimate_minutes(runs, n_att, args.reps):.0f} min")
    print(f"[CLIENT] plan.py PLAN_ID={getattr(plan, 'PLAN_ID', '?')}  "
          f"file={Path(plan.__file__).resolve()}")
    for r in phase4:
        pb = plan.RUNS[r].get("pi_b", "benign")
        extra = plan.pi_b_extra_args(r)
        hint = " ".join(extra) if extra else "(benign only — no --attacks flags)"
        print(f"[CLIENT] {r}: pi_b={pb}  {hint}")
        if r == "E1" and pb == "off":
            print("[CLIENT] ERROR: E1 still has pi_b=off — this checkout is stale.")
            print("         On Pi A run:  git fetch origin && git checkout origin/main -- "
                  "experiments/plan.py experiments/client_runner.py")
            return 1

    ensure_results_dir(RESULTS_DIR)
    try:
        for rep in range(args.first_rep, args.first_rep + args.reps):
            for run_id in runs:
                run_session(args.gateway, run_id, rep, available)
    except KeyboardInterrupt:
        print("\n[CLIENT] Interrupted.")
    finally:
        chown_results_to_invoker(RESULTS_DIR.parent)

    _call(args.gateway, {"cmd": "finish"}, timeout=10)
    print("[CLIENT] All done. Results in results/client/ — now run: git add results && git commit && git push")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
