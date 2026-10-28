#!/usr/bin/env python3
"""Install the cloud uplink bundle on the gateway Pi.

Copy keys/for_gateway_pi.tar.gz from the PC into the repo root (or keys/), then:

    python -m cloud.setup_gateway

Or let experiments/gateway_agent.py call this automatically when the tarball is present.

It extracts keys, merges CLOUD_* lines into .env, and checks that the PC is reachable.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import sys
import tarfile
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[1]
CLOUD_KEYS = (
    "GW_CLOUD_FORWARD",
    "CLOUD_URL",
    "GATEWAY_SIG_SK",
    "GATEWAY_CLOUD_PK",
    "GATEWAY_TRUST",
    "CLOUD_TLS_CERT",
    "GW_CLOUD_LOG",
    "GW_CLOUD_RETRIES",
)


def _find_bundle() -> Path | None:
    candidates = [
        REPO / "for_gateway_pi.tar.gz",
        REPO / "keys" / "for_gateway_pi.tar.gz",
        REPO / "for_gateway_pi",
        REPO / "keys" / "for_gateway_pi",
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def _extract(bundle: Path) -> Path:
    dest = REPO / "keys" / "_bundle_extract"
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    if bundle.is_dir():
        src = bundle
    else:
        with tarfile.open(bundle, "r:gz") as tf:
            tf.extractall(dest)
        src = dest / "for_gateway_pi"
        if not src.is_dir():
            # tarball may contain files at top level
            nested = [p for p in dest.iterdir() if p.is_dir()]
            src = nested[0] if len(nested) == 1 else dest
    return src


def _install_files(src: Path) -> None:
    keys = REPO / "keys"
    keys.mkdir(parents=True, exist_ok=True)

    # Cloud public material only. Never delete keys/cloud/kem.sk if present
    # (that private key belongs on the Windows PC; wiping it breaks the PC).
    cloud_src = src / "cloud"
    if cloud_src.is_dir():
        cloud_dst = keys / "cloud"
        cloud_dst.mkdir(parents=True, exist_ok=True)
        for name in ("kem.pk", "kem.alg"):
            f = cloud_src / name
            if f.exists():
                shutil.copy2(f, cloud_dst / name)

    gw_src = src / "gateway"
    if gw_src.is_dir():
        gw_dst = keys / "gateway"
        if gw_dst.exists():
            shutil.rmtree(gw_dst)
        shutil.copytree(gw_src, gw_dst)

    tls_src = src / "tls"
    if tls_src.is_dir():
        tls_dst = keys / "tls"
        tls_dst.mkdir(parents=True, exist_ok=True)
        crt = tls_src / "cloud.crt"
        if crt.exists():
            shutil.copy2(crt, tls_dst / "cloud.crt")
        # Do not overwrite cloud.key on the PC if this script is run there by mistake.

    if (src / "trust.json").exists():
        shutil.copy2(src / "trust.json", keys / "trust.json")
    sk = keys / "gateway" / "sig.sk"
    if sk.exists():
        os.chmod(sk, 0o600)
    print(f"[gw-setup] Installed keys under {keys}")


def _read_append_env(src: Path) -> dict[str, str]:
    path = src / "APPEND_TO_GATEWAY_ENV.txt"
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        values[k.strip()] = v.strip()
    return values


def _merge_env(values: dict[str, str]) -> None:
    env_path = REPO / ".env"
    lines: list[str] = []
    if env_path.exists():
        lines = env_path.read_text().splitlines()
    keys = set(values)
    kept = []
    for line in lines:
        raw = line.strip()
        if raw and not raw.startswith("#") and "=" in raw:
            k = raw.split("=", 1)[0].strip()
            if k in keys:
                continue
        kept.append(line)
    if kept and kept[-1].strip():
        kept.append("")
    kept.append("# ── Cloud HTTPS (managed by python -m cloud.setup_gateway) ──")
    for k in CLOUD_KEYS:
        if k in values:
            kept.append(f"{k}={values[k]}")
    for k, v in values.items():
        if k not in CLOUD_KEYS:
            kept.append(f"{k}={v}")
    text = "\n".join(kept) + "\n"
    try:
        env_path.write_text(text)
    except PermissionError:
        alt = REPO / ".env.cloud.gateway"
        alt.write_text(text)
        print(f"[gw-setup] WARNING: cannot write .env (permission). Wrote {alt}")
        print("[gw-setup] Merge those lines into .env as root, or: sudo tee -a .env")
        return
    print(f"[gw-setup] Updated {env_path} (GW_CLOUD_FORWARD={values.get('GW_CLOUD_FORWARD')})")


def _ping_cloud(url: str) -> None:
    host = urlparse(url).hostname
    if not host:
        return
    try:
        socket.create_connection((host, urlparse(url).port or 8443), timeout=3).close()
        print(f"[gw-setup] Reachable: {host}")
    except OSError as exc:
        print(f"[gw-setup] WARNING: cannot connect to {host}: {exc}")
        print("[gw-setup] Check Wi-Fi, PC cloud server, and CLOUD_URL IP.")


def ensure_gateway_cloud(*, require_bundle: bool = False) -> bool:
    """Install/update cloud keys from the PC bundle if present. Returns True if cloud ready."""
    bundle = _find_bundle()
    if bundle is None:
        if require_bundle:
            raise RuntimeError(
                "No for_gateway_pi.tar.gz found. Copy it from the PC into the repo root, then retry."
            )
        # Already installed?
        ready = (REPO / "keys" / "gateway" / "sig.sk").exists() and (REPO / "keys" / "tls" / "cloud.crt").exists()
        if ready:
            print("[gw-setup] Cloud keys already present (no new bundle).")
        return ready

    print(f"[gw-setup] Using bundle {bundle}")
    src = _extract(bundle)
    _install_files(src)
    values = _read_append_env(src)
    if not values:
        values = {
            "GW_CLOUD_FORWARD": "1",
            "GATEWAY_SIG_SK": "keys/gateway/sig.sk",
            "GATEWAY_CLOUD_PK": "keys/cloud/kem.pk",
            "GATEWAY_TRUST": "keys/trust.json",
            "CLOUD_TLS_CERT": "keys/tls/cloud.crt",
            "GW_CLOUD_LOG": "results/gateway/cloud_uplink.jsonl",
            "GW_CLOUD_RETRIES": "3",
        }
    values.setdefault("GW_CLOUD_FORWARD", "1")
    _merge_env(values)
    if values.get("CLOUD_URL"):
        _ping_cloud(values["CLOUD_URL"])
    # Keep a copy under keys/ for the next boot
    tar_dst = REPO / "keys" / "for_gateway_pi.tar.gz"
    if bundle.is_file() and bundle.resolve() != tar_dst.resolve():
        shutil.copy2(bundle, tar_dst)
    print("[gw-setup] Done. Start: sudo .venv/bin/python experiments/gateway_agent.py")
    return True


def main() -> int:
    try:
        ok = ensure_gateway_cloud(require_bundle=True)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
