#!/usr/bin/env python3
"""
Second client Pi: join a labelled session as traffic + ground-truth peer.

Start experiments/gateway_agent.py on the gateway first. This Pi does not start
or stop sessions.

Manual (one session / one role):
    sudo .venv/bin/python experiments/extra_client.py --tag pi2
    sudo .venv/bin/python experiments/extra_client.py --tag pi2 --attacks-only --attack-slice all

Automated Phase 4 (recommended): start once, then run the full matrix on Pi A.
Pi B reads each session's run id from the agent and applies plan.pi_b_traffic_mode
(E1 benign, E2/E3 attacks-all, E4/E5 attacks-b) without restarting:

    sudo .venv/bin/python experiments/extra_client.py --tag pi2 --auto

Without --gateway it uses the same UDP beacon / subnet scan as client_runner.
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
from experiments.results_fs import (  # noqa: E402
    chown_results_to_invoker,
    ensure_results_dir,
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


def _wait_for_session(
    gateway: str,
    want: str | None,
    timeout_s: float,
    *,
    after_session: str | None = None,
) -> dict:
    """Block until the agent reports an active session. Returns status dict."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            st = _call(gateway, {"cmd": "status"}, timeout=5)
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"[EXTRA] status failed: {exc}")
            time.sleep(2)
            continue
        session = st.get("session")
        if session and (want is None or session == want) and session != after_session:
            return st
        hint = f" ({want})" if want else ""
        if after_session:
            hint += f" after {after_session}"
        print(f"[EXTRA] Waiting for Pi A to start a session{hint} ...")
        time.sleep(2)
    raise SystemExit("Timed out waiting for an active session on the gateway agent")


def _resolve_mode(args: argparse.Namespace, run_id: str | None) -> dict:
    """Decide benign/attacks from --auto+run_id, else from CLI flags."""
    if args.auto:
        if not run_id:
            raise SystemExit("[EXTRA] --auto needs status.run from the agent (pull latest gateway code)")
        mode = plan.pi_b_traffic_mode(run_id)
        print(f"[EXTRA] --auto: run={run_id} role={mode['role']} "
              f"benign={mode['do_benign']} attacks={mode['do_attacks']} "
              f"slice={mode['attack_slice']}")
        return mode

    do_attacks = bool(args.attacks or args.attacks_only)
    do_benign = not args.attacks_only
    return {
        "role": "cli",
        "do_benign": do_benign,
        "do_attacks": do_attacks,
        "attack_slice": args.attack_slice,
    }


def _run_one_session(
    gateway: str,
    tag: str,
    session: str,
    run_id: str | None,
    mode: dict,
) -> None:
    client_ip = _local_ip_towards(gateway)
    offset = _clock_offset(gateway)
    _call(gateway, {
        "cmd": "register_peer",
        "session": session,
        "tag": tag,
        "host": socket.gethostname(),
    }, timeout=10)

    out = ensure_results_dir(RESULTS_DIR / session / "peers" / tag)
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
        "BENIGN_STEADY_DEVICE_ID": f"{tag}-steady",
        "BENIGN_MIXED_DEVICE_ID": f"{tag}-mixed",
        "BENIGN_BURST_DEVICE_ID": f"{tag}-burst",
    }

    do_benign = bool(mode["do_benign"])
    do_attacks = bool(mode["do_attacks"])
    attack_slice = mode.get("attack_slice") or "all"

    meta = {
        "session": session,
        "run": run_id,
        "role": "extra_client",
        "tag": tag,
        "gateway_ip": gateway,
        "client_ip": client_ip,
        "client_host": socket.gethostname(),
        "clock_offset_s": offset,
        "pi_b_role": mode.get("role"),
        "attacks": [],
        "attack_slice": attack_slice,
        "attacks_only": bool(do_attacks and not do_benign),
        "auto": mode.get("role") != "cli",
        "start_wall_ns": time.time_ns(),
    }

    procs: list[subprocess.Popen] = []
    if do_benign:
        for _name, cmd in plan.BENIGN_CLIENTS:
            procs.append(_launch([PYTHON, "benign_clients/run_benign.py", *cmd], env))
            time.sleep(0.4)
        print(f"[EXTRA] Joined {session} as tag={tag} ip={client_ip} (benign on). "
              f"Logs → {out}")
    else:
        print(f"[EXTRA] Joined {session} as tag={tag} ip={client_ip} "
              f"(attacks-only, slice={attack_slice}). Logs → {out}")

    try:
        if do_attacks:
            wanted = plan.attack_slice(attack_slice)
            attacks = [a for a in wanted if IS_ROOT or not a[2]]
            skipped = [a[0] for a in wanted if a not in attacks]
            if skipped:
                print(f"[EXTRA] Not root, skipping {skipped}")
            meta["attacks"] = [a[0] for a in attacks]
            for i, (name, cmd, _) in enumerate(attacks, 1):
                try:
                    st = _call(gateway, {"cmd": "status"}, timeout=5)
                except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
                    # TimeoutError is OSError on 3.x; name it explicitly for clarity.
                    print(f"[EXTRA] Lost agent during attacks ({exc}); stopping.")
                    break
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

        if not do_benign and not do_attacks:
            print("[EXTRA] Nothing to run (idle role). Waiting for session end.")

        while True:
            try:
                st = _call(gateway, {"cmd": "status"}, timeout=5)
            except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
                print(f"[EXTRA] Lost agent ({exc}); stopping session.")
                break
            if st.get("session") != session:
                print(f"[EXTRA] Session {session} ended on the agent.")
                break
            time.sleep(2)
    except KeyboardInterrupt:
        raise
    finally:
        for proc in procs:
            _kill(proc)
        meta["stop_wall_ns"] = time.time_ns()
        (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        chown_results_to_invoker(RESULTS_DIR / session)
        print(f"[EXTRA] Saved {out / 'meta.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway", help="Gateway Pi IP (default: find automatically)")
    parser.add_argument("--tag", default="pi2", help="Peer tag and device-id prefix")
    parser.add_argument("--session", help="Only join this session name (default: any active)")
    parser.add_argument("--auto", action="store_true",
                        help="Loop: for each Pi A session, pick role from plan (E1–E5)")
    parser.add_argument("--attacks", action="store_true",
                        help="Run attacks once while benign clients also publish")
    parser.add_argument("--attacks-only", action="store_true",
                        help="Phase 4: run attacks only (no benign publishers)")
    parser.add_argument("--attack-slice", choices=("all", "a", "b"), default="all",
                        help="Which partition of plan.ATTACKS to run (default all)")
    parser.add_argument("--wait-s", type=float, default=3600,
                        help="How long to wait for each new Pi A session")
    args = parser.parse_args()

    if args.auto and (args.attacks or args.attacks_only):
        print("[EXTRA] NOTE: --auto ignores --attacks / --attacks-only; role comes from plan.")

    gateway = args.gateway or find_gateway()
    if not gateway:
        print("Could not find the gateway agent. Start it first, or pass --gateway.")
        return 1
    print(f"[EXTRA] Gateway agent at {gateway}"
          + ("  (--auto: will follow E1–E5 roles)" if args.auto else ""))

    last_session: str | None = None
    try:
        while True:
            st = _wait_for_session(
                gateway, args.session, args.wait_s, after_session=last_session,
            )
            session = st["session"]
            run_id = st.get("run")
            mode = _resolve_mode(args, run_id)
            _run_one_session(gateway, args.tag, session, run_id, mode)
            last_session = session
            if not args.auto:
                break
            print("[EXTRA] --auto: ready for the next Pi A session (Ctrl+C to stop).")
    except KeyboardInterrupt:
        print("\n[EXTRA] Interrupted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
