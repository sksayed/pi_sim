#!/usr/bin/env python3
"""
gateway_agent.py — Gateway-Pi side of the labelled live evaluation.

Run once on the gateway Pi, then start experiments/client_runner.py on the
client Pi. The client tells this agent when each session starts and stops.

    sudo .venv/bin/python experiments/gateway_agent.py

Per session it:
  start  clean IPS rules, restart Mosquitto, ensure NFQUEUE rules, start the
         firewall (IDS or IPS, fixed settings from plan.py) and gateway.py,
         writing logs into results/gateway/<session>/
  stop   save iptables counters, stop gateway.py and the firewall, remove
         IPS DROP rules, gzip the firewall JSONL

Control channel: TCP port plan.CONTROL_PORT (not inspected by the firewall).
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from dotenv import dotenv_values  # noqa: E402

from experiments import plan  # noqa: E402
from scripts.start_stack import (  # noqa: E402
    _clean_nfqueue_rules,
    _clear_ips_blocks,
    _ensure_nfqueue_rules,
    _wait_for_port,
)

VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
PYTHON = str(VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable))
RESULTS_DIR = REPO_ROOT / "results" / "gateway"
MOSQUITTO_CONF = Path("/etc/mosquitto/conf.d/pi_sim.conf")


def _sh(args: list[str], check: bool = False, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=REPO_ROOT, text=True, capture_output=capture, check=check)


def _git_commit() -> str:
    return _sh(["git", "rev-parse", "HEAD"]).stdout.strip()


def _broker_listens_on_lan() -> bool:
    out = _sh(["ss", "-ltnH"]).stdout
    return any(
        line.split()[3] in (f"0.0.0.0:{plan.MQTT_PORT}", f"*:{plan.MQTT_PORT}", f"[::]:{plan.MQTT_PORT}")
        for line in out.splitlines() if len(line.split()) >= 4
    )


def _restart_mosquitto() -> None:
    _sh(["systemctl", "restart", "mosquitto"], check=True)
    if not _wait_for_port("127.0.0.1", plan.MQTT_PORT, 20):
        raise RuntimeError("Mosquitto did not start on 127.0.0.1:1883")
    if _broker_listens_on_lan():
        return
    if MOSQUITTO_CONF.exists():
        raise RuntimeError(
            f"Mosquitto is not listening on all interfaces even with {MOSQUITTO_CONF}. "
            "Check /etc/mosquitto/mosquitto.conf."
        )
    print(f"[AGENT] Mosquitto is local-only; writing {MOSQUITTO_CONF}")
    MOSQUITTO_CONF.write_text(f"listener {plan.MQTT_PORT} 0.0.0.0\nallow_anonymous true\n")
    _sh(["systemctl", "restart", "mosquitto"], check=True)
    if not (_wait_for_port("127.0.0.1", plan.MQTT_PORT, 20) and _broker_listens_on_lan()):
        raise RuntimeError("Mosquitto still not listening on 0.0.0.0:1883 after config change")


def _stop_procs(procs: dict[str, subprocess.Popen]) -> None:
    for name in ("gateway", "firewall"):
        proc = procs.get(name)
        if proc is None or proc.poll() is not None:
            continue
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait()


class Agent:
    def __init__(self) -> None:
        self.procs: dict[str, subprocess.Popen] = {}
        self.session: str | None = None
        self.session_dir: Path | None = None
        self.meta: dict = {}

    # ── start ──────────────────────────────────────────────────────────────────
    def start(self, req: dict, peer_ip: str) -> dict:
        if self.session:
            self.stop({"session": self.session})
        session = req["session"]
        run = plan.RUNS[req["run"]]
        out = RESULTS_DIR / session
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)

        print(f"\n[AGENT] ===== start {session}  block={run['block']}  allow_list={run['allow_list']} =====")
        _sh(["systemctl", "stop", "mqtt_firewall"])
        _sh(["pkill", "-f", "firewall/mqtt_firewall\\.py"])
        _sh(["pkill", "-f", "gateway/gateway\\.py"])
        _clear_ips_blocks(plan.MQTT_PORT, False)
        _restart_mosquitto()
        _clean_nfqueue_rules(plan.MQTT_PORT, 0, False)
        _ensure_nfqueue_rules(plan.MQTT_PORT, 0, False)

        env = {**os.environ, **{k: v for k, v in dotenv_values(REPO_ROOT / ".env").items() if v is not None}}
        env.update(plan.FIXED_FW_SETTINGS)
        env.update({
            "FW_QUEUE_NUM": "0",
            "FW_MODEL_PATH": str(REPO_ROOT / "firewall" / "lightgbm_model.txt"),
            "FW_SCALER_PATH": str(REPO_ROOT / "firewall" / "standard_scaler.pkl"),
            "FW_BLOCK_VERDICT": "true" if run["block"] else "false",
            "FW_ALLOW_IPS": ",".join(plan.INFRA_ALLOW_IPS) if run["allow_list"] else "",
            "FW_LOG_FILE": str(out / "firewall.log"),
            "FW_JSONL_FILE": str(out / "firewall.jsonl"),
            "GATEWAY_IP": "127.0.0.1",
            "GATEWAY_PORT": str(plan.MQTT_PORT),
            "GW_REENCRYPT_CSV_PATH": str(out / "reencrypt_metrics.csv"),
            "PYTHONUNBUFFERED": "1",
        })

        fw_out = open(out / "firewall_console.log", "w")
        self.procs["firewall"] = subprocess.Popen(
            [PYTHON, str(REPO_ROOT / "firewall" / "mqtt_firewall.py")],
            cwd=REPO_ROOT / "firewall", env=env, stdout=fw_out, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        time.sleep(8)
        if self.procs["firewall"].poll() is not None:
            raise RuntimeError(f"firewall exited early, see {out / 'firewall_console.log'}")

        gw_out = open(out / "gateway_console.log", "w")
        self.procs["gateway"] = subprocess.Popen(
            [PYTHON, str(REPO_ROOT / "gateway" / "gateway.py")],
            cwd=REPO_ROOT, env=env, stdout=gw_out, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        time.sleep(5)
        if self.procs["gateway"].poll() is not None:
            raise RuntimeError(f"gateway.py exited early, see {out / 'gateway_console.log'}")

        self.session, self.session_dir = session, out
        self.meta = {
            "session": session,
            "run": req["run"],
            "rep": req.get("rep"),
            "run_config": run,
            "fw_settings": {k: env[k] for k in sorted(env) if k.startswith("FW_") and "PATH" not in k},
            "gateway_host": socket.gethostname(),
            "gateway_lan_ip": req.get("gateway_ip", ""),
            "client_ip": peer_ip,
            "git_commit": _git_commit(),
            "start_wall_ns": time.time_ns(),
        }
        print(f"[AGENT] {session} running (client {peer_ip})")
        return {"ok": True, "gw_time": time.time()}

    # ── stop ───────────────────────────────────────────────────────────────────
    def stop(self, req: dict) -> dict:
        if not self.session or req.get("session") != self.session:
            return {"ok": False, "error": f"no active session {req.get('session')}"}
        out = self.session_dir
        (out / "iptables_counters.txt").write_text(_sh(["iptables", "-L", "INPUT", "-v", "-x", "-n"]).stdout)
        (out / "iptables_rules.txt").write_text(_sh(["iptables", "-S"]).stdout)
        _stop_procs(self.procs)
        self.procs.clear()
        _clear_ips_blocks(plan.MQTT_PORT, False)

        jsonl = out / "firewall.jsonl"
        if jsonl.exists():
            with open(jsonl, "rb") as src, gzip.open(str(jsonl) + ".gz", "wb") as dst:
                shutil.copyfileobj(src, dst)
            jsonl.unlink()

        self.meta["stop_wall_ns"] = time.time_ns()
        (out / "meta.json").write_text(json.dumps(self.meta, indent=2))
        _chown_to_user(out.parent)
        print(f"[AGENT] ===== stop {self.session} — saved to {out} =====")
        self.session, self.session_dir = None, None
        return {"ok": True}


def _beacon(stop: threading.Event) -> None:
    """Broadcast this agent's presence so the client Pi can find it without an IP."""
    msg = json.dumps({"magic": plan.BEACON_MAGIC, "port": plan.CONTROL_PORT,
                      "host": socket.gethostname()}).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while not stop.is_set():
            try:
                s.sendto(msg, ("255.255.255.255", plan.BEACON_PORT))
            except OSError:
                pass
            stop.wait(2.0)


def _chown_to_user(path: Path) -> None:
    user = os.getenv("SUDO_USER")
    if user:
        _sh(["chown", "-R", f"{user}:{user}", str(path)])


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        agent: Agent = self.server.agent  # type: ignore[attr-defined]
        try:
            req = json.loads(self.rfile.readline().decode())
            cmd = req.get("cmd")
            if cmd == "ping":
                resp = {"ok": True, "gw_time": time.time(), "host": socket.gethostname()}
            elif cmd == "start":
                resp = agent.start(req, self.client_address[0])
            elif cmd == "stop":
                resp = agent.stop(req)
            elif cmd == "finish":
                resp = {"ok": True}
                self.server.finished = True  # type: ignore[attr-defined]
            else:
                resp = {"ok": False, "error": f"unknown cmd {cmd}"}
        except Exception as exc:
            print(f"[AGENT] ERROR: {exc}", file=sys.stderr)
            resp = {"ok": False, "error": str(exc)}
        self.wfile.write((json.dumps(resp) + "\n").encode())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=plan.CONTROL_PORT)
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("Run as root:  sudo .venv/bin/python experiments/gateway_agent.py")
        return 1

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    agent = Agent()
    stop_beacon = threading.Event()
    threading.Thread(target=_beacon, args=(stop_beacon,), daemon=True).start()
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", args.port), Handler) as server:
        server.agent = agent  # type: ignore[attr-defined]
        server.finished = False  # type: ignore[attr-defined]
        server.timeout = 1.0
        print(f"[AGENT] Waiting for the client Pi on port {args.port} (Ctrl+C to quit)")
        try:
            while not server.finished:  # type: ignore[attr-defined]
                server.handle_request()
        except KeyboardInterrupt:
            print("\n[AGENT] Interrupted.")
        finally:
            stop_beacon.set()
            if agent.session:
                agent.stop({"session": agent.session})
    print("[AGENT] All sessions done. Results in results/gateway/ — now run: git add results && git commit && git push")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
