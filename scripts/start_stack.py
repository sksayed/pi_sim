#!/usr/bin/env python3
"""
Gateway-side stack starter.

This is the clean starting point for a gateway experiment. It does not launch
clients. It:

1) Updates GATEWAY_IP in .env via scripts/set_gateway_ip_env.py
2) Stops any existing gateway.py process
3) Stops the firewall while generated logs are cleaned
4) Deletes firewall logs plus benchmarks/gateway/reencrypt_metrics.csv for a fresh run
5) Removes stale IPS DROP rules created by this project
6) Restarts Mosquitto
7) Ensures NFQUEUE rules exist for the MQTT port
8) Restarts mqtt_firewall
9) Starts gateway/gateway.py in the foreground and monitors it

If sudo is needed, either run interactively or set SUDO_PASSWORD/STACK_SUDO_PASSWORD
in the environment or .env.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv


REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = REPO_ROOT / ".env"
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
PYTHON = str(VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable))
IPTABLES_COMMENT = "pi_sim_ips_block"

DEFAULT_CLEAN_PATTERNS = [
    "Firewall_logs/*.log",
    "Firewall_logs/*.jsonl",
    "benchmarks/gateway/reencrypt_metrics.csv",
]


def _load_env() -> None:
    load_dotenv(ENV_PATH, override=True)


def _sudo_password() -> str | None:
    return os.getenv("STACK_SUDO_PASSWORD") or os.getenv("SUDO_PASSWORD")


def _run(
    args: list[str],
    label: str,
    *,
    dry_run: bool = False,
    sudo: bool = False,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess:
    cmd = args[:]
    input_text = None
    if sudo and os.geteuid() != 0:
        cmd = ["sudo", "-S", *cmd]
        password = _sudo_password()
        if password:
            input_text = f"{password}\n"

    print(f"[{label}] {shlex.join(cmd)}")
    if dry_run:
        return subprocess.CompletedProcess(cmd, 0, "", "")

    result = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        input=input_text,
        text=True,
        capture_output=capture,
        check=False,
    )
    if check and result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else ""
        stdout = result.stdout.strip() if result.stdout else ""
        detail = stderr or stdout
        raise RuntimeError(f"{label} failed with exit code {result.returncode}: {detail}")
    return result


def _systemctl(action: str, service: str, label: str, dry_run: bool) -> None:
    _run(["systemctl", action, service], label, dry_run=dry_run, sudo=True)


def _wait_for_port(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.5)
    return False


def _set_gateway_ip(args: argparse.Namespace) -> None:
    cmd = [PYTHON, "scripts/set_gateway_ip_env.py", "--env-file", str(ENV_PATH)]
    if args.gateway_ip:
        cmd.extend(["--ip", args.gateway_ip])
    if args.dry_run:
        cmd.append("--dry-run")
    _run(cmd, "1/8 Set GATEWAY_IP", dry_run=False)
    _load_env()


def _stop_gateway(dry_run: bool) -> None:
    _run(
        ["pkill", "-f", "/gateway/gateway\\.py"],
        "2/8 Stop existing gateway.py",
        dry_run=dry_run,
        check=False,
    )


def _clean_generated(patterns: list[str], dry_run: bool) -> None:
    print("[4/8 Clean generated outputs]")
    for pattern in patterns:
        matches = sorted(REPO_ROOT.glob(pattern))
        if not matches:
            print(f"  {pattern}: no matches")
            continue
        for path in matches:
            if not path.is_file():
                continue
            rel = path.relative_to(REPO_ROOT)
            print(f"  remove {rel}")
            if not dry_run:
                path.unlink(missing_ok=True)


def _iptables_lines(dry_run: bool) -> list[str]:
    result = _run(
        ["iptables", "-S", "INPUT"],
        "iptables list INPUT",
        dry_run=dry_run,
        sudo=True,
        check=False,
        capture=True,
    )
    return result.stdout.splitlines() if result.stdout else []


def _delete_iptables_rule(rule: str, dry_run: bool) -> None:
    parts = shlex.split(rule)
    if len(parts) < 3 or parts[:2] != ["-A", "INPUT"]:
        return
    delete_args = ["iptables", "-D", "INPUT", *parts[2:]]
    _run(delete_args, "Remove stale IPS DROP", dry_run=dry_run, sudo=True, check=False)


def _is_project_drop_rule(rule: str, mqtt_port: int) -> bool:
    if "-j DROP" not in rule:
        return False
    if IPTABLES_COMMENT in rule:
        return True
    # Backward-compatible cleanup for older un-commented test rules generated
    # before rules were tagged. Only target specific MQTT port-scoped DROP rules.
    return (
        " --sport " in rule
        and " --dport " in rule
        and (f" --dport {mqtt_port}" in rule or f" --sport {mqtt_port}" in rule)
    )


def _clear_ips_blocks(mqtt_port: int, dry_run: bool) -> None:
    print("[5/8 Clear stale project IPS DROP rules]")
    rules = _iptables_lines(dry_run)
    removed = 0
    for rule in rules:
        if _is_project_drop_rule(rule, mqtt_port):
            _delete_iptables_rule(rule, dry_run)
            removed += 1
    if removed == 0:
        print("  no project DROP rules found")


def _iptables_check(rule_args: list[str], dry_run: bool) -> bool:
    result = _run(
        ["iptables", "-C", *rule_args],
        "Check NFQUEUE rule",
        dry_run=dry_run,
        sudo=True,
        check=False,
        capture=True,
    )
    return result.returncode == 0


def _iptables_insert(rule_args: list[str], dry_run: bool) -> None:
    _run(["iptables", "-I", *rule_args], "Add NFQUEUE rule", dry_run=dry_run, sudo=True)


def _iptables_lines_chain(chain: str, dry_run: bool) -> list[str]:
    result = _run(
        ["iptables", "-S", chain],
        f"iptables list {chain}",
        dry_run=dry_run,
        sudo=True,
        check=False,
        capture=True,
    )
    return result.stdout.splitlines() if result.stdout else []


def _is_project_nfqueue_rule(rule: str, mqtt_port: int, queue_num: int) -> bool:
    """Match any NFQUEUE rule targeting the MQTT port and our queue number."""
    return (
        "-j NFQUEUE" in rule
        and f"--queue-num {queue_num}" in rule
        and (f"--dport {mqtt_port}" in rule or f"--sport {mqtt_port}" in rule)
    )


def _delete_iptables_rule_chain(chain: str, rule: str, dry_run: bool) -> None:
    parts = shlex.split(rule)
    if len(parts) < 3 or parts[1] != chain:
        return
    delete_args = ["iptables", "-D", chain, *parts[2:]]
    _run(delete_args, f"Remove stale NFQUEUE rule from {chain}", dry_run=dry_run, sudo=True, check=False)


def _clean_nfqueue_rules(mqtt_port: int, queue_num: int, dry_run: bool) -> None:
    """Remove all existing project NFQUEUE rules so they can be re-inserted cleanly."""
    print("[6a/8 Clean stale NFQUEUE rules]")
    removed = 0
    for chain in ("INPUT", "OUTPUT"):
        for rule in _iptables_lines_chain(chain, dry_run):
            if _is_project_nfqueue_rule(rule, mqtt_port, queue_num):
                _delete_iptables_rule_chain(chain, rule, dry_run)
                removed += 1
    if removed == 0:
        print("  no stale NFQUEUE rules found")


def _ensure_nfqueue_rules(mqtt_port: int, queue_num: int, dry_run: bool) -> None:
    print("[6b/8 Ensure NFQUEUE rules (with --queue-bypass)]")
    # --queue-bypass: if no process is bound to the queue, packets are ACCEPTED
    # instead of dropped. Prevents silent packet loss during firewall restart gaps.
    rules = [
        ["INPUT",  "-p", "tcp", "--dport", str(mqtt_port), "-j", "NFQUEUE", "--queue-num", str(queue_num), "--queue-bypass"],
        ["OUTPUT", "-p", "tcp", "--sport", str(mqtt_port), "-j", "NFQUEUE", "--queue-num", str(queue_num), "--queue-bypass"],
        ["INPUT",  "-p", "udp", "--dport", str(mqtt_port), "-j", "NFQUEUE", "--queue-num", str(queue_num), "--queue-bypass"],
        ["OUTPUT", "-p", "udp", "--sport", str(mqtt_port), "-j", "NFQUEUE", "--queue-num", str(queue_num), "--queue-bypass"],
    ]
    for rule in rules:
        if _iptables_check(rule, dry_run):
            print(f"  exists: iptables -A {shlex.join(rule)}")
        else:
            _iptables_insert(rule, dry_run)


def _start_gateway(gateway_cmd: str, dry_run: bool) -> subprocess.Popen | None:
    print(f"[8/8 Gateway] {gateway_cmd}")
    if dry_run:
        return None
    return subprocess.Popen(
        shlex.split(gateway_cmd),
        cwd=REPO_ROOT,
        preexec_fn=os.setsid,
    )


def _terminate_gateway(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return


def _parse_clean_patterns(extra: list[str], no_default: bool) -> list[str]:
    patterns = [] if no_default else DEFAULT_CLEAN_PATTERNS[:]
    patterns.extend(extra)
    # Keep only relative glob patterns; this script intentionally cleans inside repo.
    safe: list[str] = []
    for pattern in patterns:
        if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ValueError(f"Unsafe clean pattern outside repo: {pattern}")
        safe.append(pattern)
    return safe


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fresh-start the gateway-side stack (Mosquitto + firewall + gateway only)."
    )
    parser.add_argument("--gateway-ip", help="Set this GATEWAY_IP instead of auto-detecting")
    parser.add_argument(
        "--broker-host",
        default="",
        help=(
            "Host used for broker readiness check. Default: current GATEWAY_IP "
            "after .env update. Use 127.0.0.1 only if GATEWAY_IP is also loopback "
            "or Mosquitto listens on the detected LAN IP."
        ),
    )
    parser.add_argument(
        "--broker-port",
        type=int,
        default=None,
        help="MQTT broker port (default: GATEWAY_PORT from .env or 1883)",
    )
    parser.add_argument("--broker-timeout", type=float, default=20.0)
    parser.add_argument(
        "--gateway-cmd",
        default=f"{shlex.quote(PYTHON)} gateway/gateway.py",
        help="Gateway command to run in foreground",
    )
    parser.add_argument("--skip-ip-update", action="store_true")
    parser.add_argument("--skip-clean", action="store_true")
    parser.add_argument("--skip-nfqueue", action="store_true")
    parser.add_argument("--clean-pattern", action="append", default=[])
    parser.add_argument("--no-default-clean-patterns", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    _load_env()
    broker_port = args.broker_port or int(os.getenv("GATEWAY_PORT", "1883"))
    queue_num = int(os.getenv("FW_QUEUE_NUM", "0"))
    gateway_proc: subprocess.Popen | None = None

    try:
        if args.skip_ip_update:
            print("[1/8 Set GATEWAY_IP] skipped")
        else:
            _set_gateway_ip(args)
        gateway_ip = os.getenv("GATEWAY_IP", "127.0.0.1")
        broker_host = args.broker_host or gateway_ip

        _stop_gateway(args.dry_run)
        _systemctl("stop", "mqtt_firewall", "3/8 Stop firewall for clean start", args.dry_run)

        if args.skip_clean:
            print("[4/8 Clean generated outputs] skipped")
        else:
            patterns = _parse_clean_patterns(
                args.clean_pattern,
                args.no_default_clean_patterns,
            )
            _clean_generated(patterns, args.dry_run)

        _clear_ips_blocks(broker_port, args.dry_run)

        _systemctl("restart", "mosquitto", "Restart Mosquitto", args.dry_run)

        if args.skip_nfqueue:
            print("[6a/8 Clean stale NFQUEUE rules] skipped")
            print("[6b/8 Ensure NFQUEUE rules] skipped")
        else:
            _clean_nfqueue_rules(broker_port, queue_num, args.dry_run)
            _ensure_nfqueue_rules(broker_port, queue_num, args.dry_run)

        _systemctl("restart", "mqtt_firewall", "7/8 Restart firewall", args.dry_run)

        if not args.dry_run:
            print(f"[CHECK] Waiting for broker readiness at {broker_host}:{broker_port}...")
            if not _wait_for_port(broker_host, broker_port, args.broker_timeout):
                raise RuntimeError(
                    f"Broker not reachable at {broker_host}:{broker_port} within "
                    f"{args.broker_timeout:.1f}s. gateway.py will use GATEWAY_IP={gateway_ip}; "
                    "either configure Mosquitto to listen on that address, pass "
                    "--gateway-ip 127.0.0.1 for local-only testing, or pass an address "
                    "that Mosquitto actually accepts."
                )
            print(f"[CHECK] Broker is up at {broker_host}:{broker_port}")

        gateway_proc = _start_gateway(args.gateway_cmd, args.dry_run)
        if args.dry_run:
            print("[DONE] Dry run completed.")
            return 0

        print("[RUNNING] Gateway stack is running. Press Ctrl+C to stop gateway.py.")
        while True:
            if gateway_proc is not None and gateway_proc.poll() is not None:
                raise RuntimeError(f"gateway.py exited with code {gateway_proc.returncode}")
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n[STOP] Interrupted by user.")
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    finally:
        _terminate_gateway(gateway_proc)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
