#!/usr/bin/env python3
"""Install the cloud uplink bundle on the gateway Pi.

Copy keys/for_gateway_pi.tar.gz from the PC into the repo root (or keys/), then:

    python -m cloud.setup_gateway

Or let experiments/gateway_agent.py call this automatically when the tarball is present.

It extracts keys, merges CLOUD_* lines into .env, and checks that the PC is reachable.
"""

from __future__ import annotations

import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
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


def _invoker_user() -> str:
    """Login user who invoked sudo, else the current non-root user."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user
    return pwd.getpwuid(os.geteuid()).pw_name


def _reclaim_ownership(path: Path) -> bool:
    """Best-effort chown path to the invoking user. Never prompts for a password."""
    if not path.exists():
        return True
    user = _invoker_user()
    if os.geteuid() == 0:
        subprocess.run(["chown", "-R", f"{user}:{user}", str(path)], check=False)
        return True
    proc = subprocess.run(
        ["sudo", "-n", "chown", "-R", f"{user}:{user}", str(path)],
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def _rmtree(path: Path) -> None:
    """Remove a tree; reclaim ownership once if a prior sudo/sandbox left it unwritable."""
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
        return
    except OSError:
        pass
    if _reclaim_ownership(path):
        try:
            shutil.rmtree(path)
            return
        except OSError:
            pass
    raise PermissionError(
        f"Cannot remove {path} (wrong ownership). Run: "
        f"sudo chown -R \"$USER:$USER\" {path.parent}"
    )


def _chown_keys_to_invoker() -> None:
    """When run via sudo, hand keys/ back to the login user so next setup works."""
    if os.geteuid() != 0:
        return
    keys = REPO / "keys"
    if keys.exists():
        user = _invoker_user()
        subprocess.run(["chown", "-R", f"{user}:{user}", str(keys)], check=False)


def _cleanup_stale_extracts(keys: Path, keep: Path | None = None) -> None:
    for path in keys.glob("_bundle_extract*"):
        if keep is not None and path.resolve() == keep.resolve():
            continue
        try:
            _rmtree(path)
        except OSError:
            # Leave stale dirs; each run uses a fresh mkdtemp name so setup still proceeds.
            pass


def _extract(bundle: Path) -> tuple[Path, Path | None]:
    """Extract bundle. Returns (source_dir, extract_root_to_delete_or_None)."""
    keys = REPO / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    _cleanup_stale_extracts(keys)

    if bundle.is_dir():
        return bundle, None

    # Fresh dir every run so a stuck nobody/root-owned _bundle_extract cannot block setup.
    dest = Path(tempfile.mkdtemp(prefix="_bundle_extract_", dir=str(keys)))
    try:
        with tarfile.open(bundle, "r:gz") as tf:
            # filter="data": no archive ownership/xattrs → avoids nobody/root-owned trees.
            tf.extractall(dest, filter="data")
        src = dest / "for_gateway_pi"
        if not src.is_dir():
            # tarball may contain files at top level
            nested = [p for p in dest.iterdir() if p.is_dir()]
            src = nested[0] if len(nested) == 1 else dest
        return src, dest
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise


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
            _rmtree(gw_dst)
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


def _read_dotenv_key(key: str) -> str | None:
    """Return key from process env or repo .env (first match)."""
    env_val = os.environ.get(key)
    if env_val and env_val.strip():
        return env_val.strip()
    env_path = REPO / ".env"
    if not env_path.exists():
        return None
    try:
        lines = env_path.read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        k, _, v = raw.partition("=")
        if k.strip() == key:
            v = v.strip()
            return v or None
    return None


def _prefer_existing_cloud_url(values: dict[str, str]) -> None:
    """Keep a Pi-local CLOUD_URL so a stale bundle IP cannot overwrite a fixed DHCP/static address."""
    existing = _read_dotenv_key("CLOUD_URL")
    if not existing:
        return
    bundled = values.get("CLOUD_URL")
    if bundled and bundled != existing:
        print(
            f"[gw-setup] Keeping existing CLOUD_URL ({urlparse(existing).hostname}) "
            f"— ignoring bundle IP ({urlparse(bundled).hostname})"
        )
    values["CLOUD_URL"] = existing


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


def _cert_covers_host(cert_path: Path, host: str) -> bool:
    if not cert_path.exists() or not host:
        return False
    try:
        text = subprocess.check_output(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-text"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    return host in text


def _fetch_server_cert_pem(host: str, port: int) -> str | None:
    """Pull the leaf PEM the cloud PC is presenting (for IP-matched pinning)."""
    try:
        raw = subprocess.check_output(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input="",
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    try:
        return subprocess.check_output(
            ["openssl", "x509"],
            input=raw,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None


def _ensure_tls_matches_url(url: str) -> None:
    """If cloud.crt is for an old IP, replace it with the cert the PC currently serves.

    TCP can succeed while HTTPS fails with CERTIFICATE_VERIFY_FAILED when the
    pinned cert SAN still has a previous DHCP/static address.
    """
    host = urlparse(url).hostname
    port = urlparse(url).port or 8443
    if not host:
        return
    cert_path = REPO / "keys" / "tls" / "cloud.crt"
    if _cert_covers_host(cert_path, host):
        print(f"[gw-setup] TLS cert covers {host}")
        return
    print(
        f"[gw-setup] TLS cert does not cover {host} "
        f"(stale pin) — fetching from cloud PC {host}:{port} …"
    )
    pem = _fetch_server_cert_pem(host, port)
    if not pem or "BEGIN CERTIFICATE" not in pem:
        print(
            "[gw-setup] WARNING: could not fetch cloud TLS cert. "
            "Re-run python -m cloud.setup_pc on the PC and copy a fresh for_gateway_pi.tar.gz."
        )
        return
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_text(pem if pem.endswith("\n") else pem + "\n")
    if _cert_covers_host(cert_path, host):
        print(f"[gw-setup] Updated {cert_path} for {host}")
    else:
        print(
            f"[gw-setup] WARNING: fetched cert still does not name {host}. "
            "Regenerate TLS on the PC for this IP."
        )


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
            url = _read_dotenv_key("CLOUD_URL")
            if url:
                _ensure_tls_matches_url(url)
                _ping_cloud(url)
        return ready

    print(f"[gw-setup] Using bundle {bundle}")
    src, extract_root = _extract(bundle)
    try:
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
        _prefer_existing_cloud_url(values)
        _merge_env(values)
        if values.get("CLOUD_URL"):
            _ensure_tls_matches_url(values["CLOUD_URL"])
            _ping_cloud(values["CLOUD_URL"])
        # Keep a copy under keys/ for the next boot
        tar_dst = REPO / "keys" / "for_gateway_pi.tar.gz"
        if bundle.is_file() and bundle.resolve() != tar_dst.resolve():
            shutil.copy2(bundle, tar_dst)
    finally:
        if extract_root is not None:
            try:
                _rmtree(extract_root)
            except OSError:
                shutil.rmtree(extract_root, ignore_errors=True)
        _chown_keys_to_invoker()
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
