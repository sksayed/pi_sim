#!/usr/bin/env python3
"""One-command cloud PC setup for the LAN emulator.

From the repo root on Windows/WSL:

    python -m cloud.setup_pc
    python -m cloud.setup_pc --ip 10.111.108.55
    python -m cloud.setup_pc --no-serve

It will:
  1. Detect the Windows LAN/Wi-Fi IP the Pis should dial (or use --ip)
  2. Create missing cloud/gateway keys and trust pins
  3. Refresh the TLS cert when the IP changes
  4. Write .env.cloud with CLOUD_URL and key paths
  5. Best-effort Windows portproxy + firewall for :8443 → this WSL host
  6. Rebuild keys/for_gateway_pi.tar.gz for copying to the gateway Pi
  7. Start python -m cloud.https_server (unless --no-serve)
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from cloud.provision import _write_role, _write_tls  # noqa: E402
from cloud.uplink_keys import fingerprint, record_pin  # noqa: E402

KEYS = REPO / "keys"
ENV_CLOUD = REPO / ".env.cloud"
PORT = int(os.getenv("CLOUD_PORT", "8443"))


def _run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _powershell(script: str) -> str:
    r = _run([
        "powershell.exe", "-NoProfile", "-Command", script,
    ])
    return (r.stdout or "") + (r.stderr or "")


def detect_windows_lan_ip() -> str | None:
    """Prefer Wi-Fi, then Ethernet; skip WSL/vEthernet/loopback/APIPA."""
    script = r"""
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object {
    $_.IPAddress -notlike '127.*' -and
    $_.IPAddress -notlike '169.254.*' -and
    $_.InterfaceAlias -notmatch 'WSL|vEthernet|Loopback|Hyper-V'
  } |
  Sort-Object @{
    Expression = {
      if ($_.InterfaceAlias -match 'Wi-?Fi|WLAN|Wireless') { 0 }
      elseif ($_.InterfaceAlias -match 'Ethernet') { 1 }
      else { 2 }
    }
  }, InterfaceAlias |
  Select-Object -ExpandProperty IPAddress
"""
    out = _powershell(script)
    for line in out.splitlines():
        ip = line.strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
            return ip
    # Fallback: first non-loopback address on this host
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def wsl_listen_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def cert_has_ip(cert_path: Path, ip: str) -> bool:
    if not cert_path.exists():
        return False
    r = _run(["openssl", "x509", "-in", str(cert_path), "-noout", "-text"])
    return ip in (r.stdout or "")


def _repin(trust: Path, label: str, pk_path: Path) -> str:
    """Record or replace a trust pin when the public key file changes."""
    import json
    digest = fingerprint(pk_path.read_bytes())
    data = json.loads(trust.read_text()) if trust.exists() else {}
    if data.get(label) == digest:
        return digest
    data[label] = digest
    trust.parent.mkdir(parents=True, exist_ok=True)
    tmp = trust.with_suffix(trust.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, trust)
    return digest


def ensure_keys() -> None:
    cloud_dir, gw_dir = KEYS / "cloud", KEYS / "gateway"
    if not (cloud_dir / "kem.sk").exists():
        if (cloud_dir / "kem.pk").exists():
            raise RuntimeError(
                f"{cloud_dir / 'kem.sk'} is missing but kem.pk exists. "
                "Restore the private key; do not regenerate or the gateway pin will break."
            )
        print("[setup] Generating cloud ML-KEM keypair …")
        _write_role("cloud", cloud_dir)
    if not (gw_dir / "sig.sk").exists():
        if (gw_dir / "sig.pk").exists():
            raise RuntimeError(
                f"{gw_dir / 'sig.sk'} is missing but sig.pk exists. Restore the private key."
            )
        print("[setup] Generating gateway ML-DSA keypair (copy sig.sk to the gateway Pi) …")
        _write_role("gateway", gw_dir)
    trust = KEYS / "trust.json"
    _repin(trust, "cloud_kem_pk", cloud_dir / "kem.pk")
    _repin(trust, "gateway_sig_pk", gw_dir / "sig.pk")
    print(f"[setup] trust pins OK  cloud={fingerprint((cloud_dir / 'kem.pk').read_bytes())[:16]}…")


def ensure_tls(ip: str) -> None:
    tls_dir = KEYS / "tls"
    cert = tls_dir / "cloud.crt"
    key = tls_dir / "cloud.key"
    if cert_has_ip(cert, ip) and key.exists():
        print(f"[setup] TLS cert already covers {ip}")
        return
    print(f"[setup] Writing TLS cert for {ip} …")
    _write_tls(ip, tls_dir)


def write_env_cloud(ip: str) -> None:
    saved: dict[str, str] = {}
    if ENV_CLOUD.exists():
        for key in ("GATEWAY_SSH", "GATEWAY_SSH_DIR"):
            m = re.search(rf"^{key}=(.+)$", ENV_CLOUD.read_text(), re.M)
            if m:
                saved[key] = m.group(1).strip()
    lines = [
        "# Generated by python -m cloud.setup_pc — do not hand-edit unless you mean to.",
        f"# PC LAN/Wi-Fi IP in the TLS certificate: {ip}",
        "GW_CLOUD_FORWARD=0",
        f"CLOUD_URL=https://{ip}:{PORT}/v1/envelope",
        "CLOUD_KEM_SK=keys/cloud/kem.sk",
        "CLOUD_GATEWAY_PK=keys/gateway/sig.pk",
        "CLOUD_TRUST=keys/trust.json",
        "CLOUD_TLS_CERT=keys/tls/cloud.crt",
        "CLOUD_TLS_KEY=keys/tls/cloud.key",
        "CLOUD_BIND=0.0.0.0",
        f"CLOUD_PORT={PORT}",
        "CLOUD_LOG=results/cloud/uplink.jsonl",
        "CLOUD_REPLAY=results/cloud/replay_state.json",
        "GATEWAY_SIG_SK=keys/gateway/sig.sk",
        "GATEWAY_CLOUD_PK=keys/cloud/kem.pk",
        "GATEWAY_TRUST=keys/trust.json",
        "GW_CLOUD_LOG=results/gateway/cloud_uplink.jsonl",
        "GW_CLOUD_RETRIES=3",
        "# Optional auto-push when the bundle refreshes:",
        "# GATEWAY_SSH=sayed@<gateway-pi-ip>",
        "# GATEWAY_SSH_DIR=~/Desktop/pi_project/pi_sim",
    ]
    for key, val in saved.items():
        lines.append(f"{key}={val}")
    ENV_CLOUD.write_text("\n".join(lines) + "\n")
    print(f"[setup] Wrote {ENV_CLOUD}  CLOUD_URL=https://{ip}:{PORT}/v1/envelope")


def ensure_windows_forward(wsl_ip: str) -> None:
    """Forward host :8443 into this WSL address and allow the firewall."""
    print(f"[setup] Windows portproxy 0.0.0.0:{PORT} → {wsl_ip}:{PORT}")
    # delete then add (ignore failures)
    _powershell(
        f"netsh interface portproxy delete v4tov4 listenport={PORT} listenaddress=0.0.0.0; "
        f"netsh interface portproxy add v4tov4 listenport={PORT} listenaddress=0.0.0.0 "
        f"connectport={PORT} connectaddress={wsl_ip}"
    )
    fw = (
        "if (-not (Get-NetFirewallRule -DisplayName 'pi_sim cloud 8443' "
        "-ErrorAction SilentlyContinue)) { "
        "New-NetFirewallRule -DisplayName 'pi_sim cloud 8443' -Direction Inbound "
        f"-Protocol TCP -LocalPort {PORT} -Action Allow -Profile Any | Out-Null "
        "}"
    )
    _powershell(fw)
    show = _powershell("netsh interface portproxy show all")
    if str(PORT) in show and wsl_ip in show:
        print("[setup] portproxy installed")
    else:
        print("[setup] WARNING: portproxy may need an elevated PowerShell. "
              f"Run as Admin:\n  netsh interface portproxy add v4tov4 "
              f"listenport={PORT} listenaddress=0.0.0.0 connectport={PORT} connectaddress={wsl_ip}")


def build_gateway_bundle(ip: str) -> Path:
    bundle = KEYS / "for_gateway_pi"
    if bundle.exists():
        shutil.rmtree(bundle)
    for sub in ("cloud", "gateway", "tls"):
        (bundle / sub).mkdir(parents=True)
    shutil.copy2(KEYS / "cloud" / "kem.pk", bundle / "cloud" / "kem.pk")
    shutil.copy2(KEYS / "cloud" / "kem.alg", bundle / "cloud" / "kem.alg")
    for name in ("sig.pk", "sig.alg", "sig.sk"):
        shutil.copy2(KEYS / "gateway" / name, bundle / "gateway" / name)
    shutil.copy2(KEYS / "tls" / "cloud.crt", bundle / "tls" / "cloud.crt")
    shutil.copy2(KEYS / "trust.json", bundle / "trust.json")
    (bundle / "APPEND_TO_GATEWAY_ENV.txt").write_text(
        f"# Append once to the gateway Pi .env (or replace existing CLOUD_* lines).\n"
        f"GW_CLOUD_FORWARD=1\n"
        f"CLOUD_URL=https://{ip}:{PORT}/v1/envelope\n"
        f"GATEWAY_SIG_SK=keys/gateway/sig.sk\n"
        f"GATEWAY_CLOUD_PK=keys/cloud/kem.pk\n"
        f"GATEWAY_TRUST=keys/trust.json\n"
        f"CLOUD_TLS_CERT=keys/tls/cloud.crt\n"
        f"GW_CLOUD_LOG=results/gateway/cloud_uplink.jsonl\n"
        f"GW_CLOUD_RETRIES=3\n"
    )
    (bundle / "INSTALL.txt").write_text(
        f"On the gateway Pi:\n\n"
        f"  cd ~/Desktop/pi_project/pi_sim\n"
        f"  tar xzf for_gateway_pi.tar.gz\n"
        f"  mkdir -p keys\n"
        f"  cp -a for_gateway_pi/cloud keys/\n"
        f"  cp -a for_gateway_pi/gateway keys/\n"
        f"  cp -a for_gateway_pi/tls keys/\n"
        f"  cp for_gateway_pi/trust.json keys/\n"
        f"  chmod 600 keys/gateway/sig.sk\n"
        f"  # Edit .env: set/replace CLOUD_* from APPEND_TO_GATEWAY_ENV.txt\n"
        f"  ping -c 2 {ip}\n"
        f"  sudo .venv/bin/python experiments/gateway_agent.py\n"
    )
    tar_path = KEYS / "for_gateway_pi.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        tf.add(bundle, arcname="for_gateway_pi")
    print(f"[setup] Gateway bundle → {tar_path}")
    return tar_path


def stop_existing_server() -> None:
    r = _run(["bash", "-lc", f"ss -ltnp 'sport = :{PORT}' 2>/dev/null || true"])
    for m in re.finditer(r"pid=(\d+)", r.stdout or ""):
        pid = m.group(1)
        print(f"[setup] Stopping old listener pid={pid}")
        _run(["kill", pid])
    time.sleep(0.4)


def start_server() -> int:
    stop_existing_server()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    print(f"[setup] Starting cloud HTTPS on 0.0.0.0:{PORT} …")
    print("[setup] Ctrl+C to stop.")
    return subprocess.call([sys.executable, "-m", "cloud.https_server"], cwd=str(REPO), env=env)


def current_env_cloud_ip() -> str | None:
    if not ENV_CLOUD.exists():
        return None
    m = re.search(r"CLOUD_URL=https://([^:/]+):", ENV_CLOUD.read_text())
    return m.group(1) if m else None


def needs_refresh(ip: str) -> bool:
    """True when keys/env/cert are missing or the reachability IP changed."""
    if not (KEYS / "cloud" / "kem.sk").exists():
        return True
    if not (KEYS / "gateway" / "sig.sk").exists():
        return True
    if not (KEYS / "trust.json").exists():
        return True
    if not cert_has_ip(KEYS / "tls" / "cloud.crt", ip):
        return True
    if not (KEYS / "tls" / "cloud.key").exists():
        return True
    if current_env_cloud_ip() != ip:
        return True
    return False


def push_bundle_to_gateway(tar_path: Path) -> None:
    """Optional: GATEWAY_SSH=user@gateway-ip copies and installs the bundle."""
    target = os.getenv("GATEWAY_SSH", "").strip()
    if not target:
        return
    remote_dir = os.getenv("GATEWAY_SSH_DIR", "~/Desktop/pi_project/pi_sim").strip()
    print(f"[setup] Pushing bundle to {target}:{remote_dir} …")
    r = _run(["scp", str(tar_path), f"{target}:{remote_dir}/for_gateway_pi.tar.gz"])
    if r.returncode != 0:
        print(f"[setup] WARNING: scp failed:\n{r.stderr}")
        return
    remote_cmd = (
        f"cd {remote_dir} && "
        f"(test -x .venv/bin/python && PY=.venv/bin/python || PY=python3); "
        f"$PY -m cloud.setup_gateway"
    )
    r = _run(["ssh", target, remote_cmd])
    if r.returncode != 0:
        print(f"[setup] WARNING: remote install failed:\n{r.stdout}\n{r.stderr}")
    else:
        print(f"[setup] Gateway install OK on {target}")
        if r.stdout.strip():
            print(r.stdout.strip())


def prepare_cloud_pc(ip: str | None = None, *, skip_portproxy: bool = False,
                     force: bool = False) -> str:
    """Refresh keys/TLS/env/bundle when needed. Returns the PC reachability IP."""
    ip = ip or detect_windows_lan_ip()
    if not ip:
        raise RuntimeError("Could not detect a LAN IP. Pass --ip <WINDOWS_WIFI_IP>.")
    KEYS.mkdir(parents=True, exist_ok=True)
    if force or needs_refresh(ip):
        print(f"[setup] Preparing cloud PC for {ip} …")
        ensure_keys()
        ensure_tls(ip)
        write_env_cloud(ip)
        if not skip_portproxy:
            ensure_windows_forward(wsl_listen_ip())
        tar_path = build_gateway_bundle(ip)
        push_bundle_to_gateway(tar_path)
    else:
        print(f"[setup] Cloud PC already current for {ip}")
        tar_path = KEYS / "for_gateway_pi.tar.gz"
        if not tar_path.exists():
            tar_path = build_gateway_bundle(ip)
    return ip


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ip", help="Windows LAN/Wi-Fi IP the Pis dial (default: auto-detect)")
    parser.add_argument("--no-serve", action="store_true", help="Prepare keys/env/bundle only")
    parser.add_argument("--skip-portproxy", action="store_true",
                        help="Do not touch Windows portproxy/firewall")
    parser.add_argument("--force", action="store_true", help="Rebuild even if IP unchanged")
    args = parser.parse_args()

    try:
        ip = prepare_cloud_pc(args.ip, skip_portproxy=args.skip_portproxy, force=args.force)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1

    print()
    print("Gateway Pi:")
    print(f"  scp {KEYS / 'for_gateway_pi.tar.gz'} <user>@<gateway-pi>:~/Desktop/pi_project/pi_sim/")
    print("  # on the Pi:  python -m cloud.setup_gateway")
    print("  # or set GATEWAY_SSH=user@gateway-ip in .env.cloud to auto-push")
    print(f"  # CLOUD_URL must be https://{ip}:{PORT}/v1/envelope")
    print()

    if args.no_serve:
        return 0
    # Serve in-process so https_server's auto-prepare does not spawn another process.
    from cloud.https_server import main as https_main
    return https_main()


if __name__ == "__main__":
    raise SystemExit(main())
