#!/usr/bin/env python3
"""
Exercise implemented features: padding, key derivation, classical/PQC message build,
gateway decrypt handlers, ECDH/ECDSA gateway key cache, analyzer, optional MQTT RTT.

Run from repo root:
  python scripts/test_all_features.py

Requires .env with MASTER_SECRET. Optionally MQTT on GATEWAY_IP:GATEWAY_PORT for RTT test.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_gateway_module(root: Path):
    path = root / "gateway" / "gateway.py"
    spec = importlib.util.spec_from_file_location("pi_sim_gateway_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load gateway module")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    root = _repo_root()
    os.chdir(root)
    sys.path.insert(0, str(root))

    tmpdir = tempfile.mkdtemp(prefix="pi_sim_test_")
    client_csv = str(Path(tmpdir) / "client.csv")
    gateway_csv = str(Path(tmpdir) / "gateway.csv")
    rtt_csv = str(Path(tmpdir) / "rtt.csv")
    os.environ["BENCH_CSV_PATH"] = client_csv
    os.environ["GATEWAY_BENCH_CSV_PATH"] = gateway_csv

    from dotenv import load_dotenv

    load_dotenv(root / ".env")
    if not os.getenv("MASTER_SECRET", "").strip():
        _fail("MASTER_SECRET missing in .env")

    print("== 1) payload_pad ==")
    from shared.payload_pad import pad_json_plaintext

    small = pad_json_plaintext({"a": 1}, 0)
    assert b"a" in small
    pad5k = pad_json_plaintext({"k": "v"}, 5120)
    assert len(pad5k) >= 5120
    print("   ok")

    print("== 2) KeyManager classical ECDH/ECDSA + AES ==")
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from shared.key_manager import load_key_manager

    km = load_key_manager()
    eph = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_c = eph.exchange(ec.ECDH(), km.ecdh_p256_static_peer_public_key())
    shared_g = km.ecdh_p256_static_private_key().exchange(ec.ECDH(), eph.public_key())
    assert shared_c == shared_g
    k1 = km.derive_classical_ecdh_aes_key(shared_c)
    k2 = km.derive_classical_ecdh_aes_key(shared_g)
    assert k1 == k2
    n = os.urandom(12)
    ct = AESGCM(k1).encrypt(n, b"unit-test-plain", None)
    assert AESGCM(k2).decrypt(n, ct, None) == b"unit-test-plain"

    from cryptography.hazmat.primitives import hashes

    dev = "cache-test-device-99"
    sk = km.ecdsa_p256_signing_key(dev)
    sig = sk.sign(b"payload", ec.ECDSA(hashes.SHA256()))
    vk = km.ecdsa_p256_signing_key(dev).public_key()
    vk.verify(sig, b"payload", ec.ECDSA(hashes.SHA256()))
    print("   ok")

    print("== 3) Gateway module: decrypt handlers (in-process) ==")
    gw = _load_gateway_module(root)
    gw._sessions.clear()
    gw._ecdh_p256_static_sk = None
    gw._ecdsa_p256_verify_key_by_device.clear()

    from client.research_base_client import ResearchProfileClient
    from client.classic_research_client import (
        ClassicResearchAES,
        ClassicResearchChaCha,
        ClassicResearchECDH_ECDSA,
    )

    uid = uuid.uuid4().hex[:10]

    class PqcT(ResearchProfileClient):
        DEVICE_ID = f"tst-pqc-{uid}"
        PROFILE_NAME = "T"
        ALG_KEM = "ML-KEM-512"
        ALG_SIG = "ML-DSA-44"
        SECURITY_BITS = 128

        def sample_data(self, seq: int) -> str:
            return f"pqc-{seq}"

    pqc = PqcT()
    m_pqc = pqc.build_message(1)
    m_pqc["_payload_bytes"] = 1000
    gw._decrypt_research_profile(km, dict(m_pqc))
    print("   PQC-RESEARCH-PROFILE ok")

    gw._sessions.clear()

    class AesT(ClassicResearchAES):
        DEVICE_ID = f"tst-aes-{uid}"
        PROFILE_NAME = "TA"
        SECURITY_BITS = 128

        def sample_data(self, seq: int) -> str:
            return f"aes-{seq}"

    aes_c = AesT()
    m_aes = aes_c.build_message(1)
    m_aes["_payload_bytes"] = 500
    gw._decrypt_classical_aes_research(km, dict(m_aes))
    print("   CLASSICAL-AES-GCM ok")

    gw._sessions.clear()

    class ChT(ClassicResearchChaCha):
        DEVICE_ID = f"tst-ch-{uid}"
        PROFILE_NAME = "TC"
        SECURITY_BITS = 128

        def sample_data(self, seq: int) -> str:
            return f"ch-{seq}"

    ch_c = ChT()
    m_ch = ch_c.build_message(1)
    m_ch["_payload_bytes"] = 500
    gw._decrypt_classical_chacha_research(km, dict(m_ch))
    print("   CLASSICAL-CHACHA20 ok")

    gw._sessions.clear()

    class EcdhT(ClassicResearchECDH_ECDSA):
        DEVICE_ID = f"tst-ecdh-{uid}"
        PROFILE_NAME = "TE"
        SECURITY_BITS = 128

        def sample_data(self, seq: int) -> str:
            return f"ecdh-{seq}"

    ecdh_c = EcdhT()
    m_ec = ecdh_c.build_message(1)
    m_ec["_payload_bytes"] = 800
    gw._decrypt_classical_ecdh_ecdsa_research(km, dict(m_ec))
    print("   CLASSICAL-ECDH-ECDSA ok")

    print("== 4) Gateway ECDH/ECDSA caches ==")
    sk1 = gw._cached_ecdh_p256_static_private_key(km)
    sk2 = gw._cached_ecdh_p256_static_private_key(km)
    assert sk1 is sk2, "static ECDH private key should be cached"

    d2 = f"tst-ecdh-{uid}"
    vk_a = gw._cached_ecdsa_p256_verify_key(km, d2)
    vk_b = gw._cached_ecdsa_p256_verify_key(km, d2)
    assert vk_a is vk_b, "ECDSA verify key should be cached per device_id"
    print("   ok")

    print("== 5) analyze_pqc_benchmarks ==")
    ana_path = root / "scripts" / "analyze_pqc_benchmarks.py"
    spec_a = importlib.util.spec_from_file_location("pi_sim_analyze_test", ana_path)
    if spec_a is None or spec_a.loader is None:
        _fail("Cannot load analyze_pqc_benchmarks")
    ana = importlib.util.module_from_spec(spec_a)
    sys.modules[spec_a.name] = ana
    spec_a.loader.exec_module(ana)

    sample_client = root / "benchmarks" / "client" / "pqc_metrics.csv"
    sample_gw = root / "benchmarks" / "gateway" / "pqc_metrics_gateway.csv"
    if not sample_client.exists():
        sample_client = root / "benchmarks" / "pqc_metrics.csv"
        sample_gw = root / "benchmarks" / "pqc_metrics_gateway.csv"
    if not sample_client.exists():
        _fail(f"missing client CSV (try benchmarks/client/pqc_metrics.csv)")
    text = ana.build_report(sample_client, sample_gw, rtt_path=Path(rtt_csv))
    if "Matches:" not in text and "Matched" not in text:
        _fail("analyzer report missing match section")
    Path(tmpdir, "report.txt").write_text(text, encoding="utf-8")
    print("   ok (report generated)")

    print("== 6) MQTT RTT baseline (needs gateway.py subscribed to benchmark/rtt/*) ==")
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(root / "scripts" / "mqtt_rtt_baseline.py"),
                "-n",
                "3",
                "--out",
                rtt_csv,
            ],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            print(f"   FAIL/CONNECT (rc={proc.returncode}) stderr={proc.stderr[:400]!r}")
        elif "sample" in proc.stdout and Path(rtt_csv).exists():
            print(f"   ok — {proc.stdout.strip().splitlines()[-3:]}")
        else:
            print(
                "   SKIPPED (no RTT replies — start `python gateway/gateway.py` with broker up, "
                "or check GATEWAY_IP/PORT)"
            )
            if proc.stderr:
                print(f"   stderr tail: {proc.stderr.strip()[-300:]}")
    except subprocess.TimeoutExpired:
        print("   TIMEOUT — increase timeout or fix MQTT/gateway")
    except FileNotFoundError:
        print("   mqtt_rtt_baseline.py missing")

    print("== 7) py_compile (sanity) ==")
    mods = [
        root / "shared" / "key_manager.py",
        root / "shared" / "metrics.py",
        root / "shared" / "payload_pad.py",
        root / "client" / "classic_research_client.py",
        root / "client" / "research_base_client.py",
        root / "gateway" / "gateway.py",
        root / "scripts" / "analyze_pqc_benchmarks.py",
        root / "scripts" / "mqtt_rtt_baseline.py",
        root / "scripts" / "test_all_features.py",
    ]
    rc = subprocess.run([sys.executable, "-m", "py_compile", *[str(p) for p in mods]])
    if rc.returncode != 0:
        _fail("py_compile failed")
    print("   ok")

    print("\nAll automated checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
