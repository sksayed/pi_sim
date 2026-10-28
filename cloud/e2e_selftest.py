#!/usr/bin/env python3
"""One-message HTTPS check on this machine.

Accepts one envelope, repeats that POST (duplicate, not a second delivery),
rejects an older seq, rejects a bad signature, and checks the replay file
after a server restart. Prints the three timings from this run. Those numbers
are a local wiring check, not an experiment.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BASE = Path(tempfile.mkdtemp(prefix="cloud-e2e-"))
os.environ["CLOUD_PORT"] = "18443"
os.environ["CLOUD_BIND"] = "127.0.0.1"
os.environ["CLOUD_LOG"] = str(BASE / "uplink.jsonl")
os.environ["CLOUD_REPLAY"] = str(BASE / "replay_state.json")
os.environ["GW_REENCRYPT_CSV_PATH"] = str(BASE / "reencrypt.csv")

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "gateway"))

from cloud.https_server import make_server
from cloud.provision import _write_role, _write_tls
from cloud.uplink_keys import load_pinned, read_alg, record_pin
from cloud_uplink import CloudUplink
from benign_pipeline import handle_benign, use_provisioned_uplink
from shared.key_manager import KeyManager, PQC_AVAILABLE


def _lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def _wait(path: Path, pred, timeout: float = 20.0) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = _lines(path)
        if pred(rows):
            return rows
        time.sleep(0.05)
    raise SystemExit(f"Timed out waiting for {path}")


def _envelope(km, seq: int) -> dict:
    msg = {
        "device_id": "dev-e2e",
        "seq": seq,
        "temp": 21.5,
        "crypto_type": "benign",
        "t_publish_ns": time.time_ns(),
    }
    payload = handle_benign(km, msg, time.time_ns(), time.perf_counter_ns())
    if not isinstance(payload, dict):
        raise SystemExit("Stage 2 did not build an envelope")
    return payload


def main() -> int:
    if not PQC_AVAILABLE:
        print("liboqs is not installed, so this check cannot run.", file=sys.stderr)
        return 1

    _write_role("cloud", BASE / "cloud")
    _write_role("gateway", BASE / "gateway")
    trust = BASE / "trust.json"
    record_pin(trust, "cloud_kem_pk", BASE / "cloud" / "kem.pk")
    record_pin(trust, "gateway_sig_pk", BASE / "gateway" / "sig.pk")
    _write_tls("127.0.0.1", BASE / "tls")

    empty = BASE / "trust-empty.json"
    empty.write_text("{}\n")
    try:
        load_pinned(BASE / "cloud" / "kem.pk", empty, "cloud_kem_pk")
        raise SystemExit("A missing pin was accepted")
    except RuntimeError:
        pass
    bad = BASE / "trust-bad.json"
    bad.write_text(json.dumps({"cloud_kem_pk": "00" * 32}) + "\n")
    try:
        load_pinned(BASE / "cloud" / "kem.pk", bad, "cloud_kem_pk")
        raise SystemExit("A mismatched pin was accepted")
    except RuntimeError:
        pass

    os.environ["CLOUD_TRUST"] = str(trust)
    os.environ["CLOUD_GATEWAY_PK"] = str(BASE / "gateway" / "sig.pk")
    os.environ["CLOUD_KEM_SK"] = str(BASE / "cloud" / "kem.sk")
    os.environ["CLOUD_TLS_CERT"] = str(BASE / "tls" / "cloud.crt")
    os.environ["CLOUD_TLS_KEY"] = str(BASE / "tls" / "cloud.key")

    server = make_server()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)

    cloud_pk = load_pinned(BASE / "cloud" / "kem.pk", trust, "cloud_kem_pk")
    use_provisioned_uplink(
        read_alg(BASE / "cloud" / "kem.pk", "ML-KEM-768"),
        read_alg(BASE / "gateway" / "sig.sk", "ML-DSA-65"),
        cloud_pk,
        (BASE / "gateway" / "sig.sk").read_bytes(),
        "gateway",
    )
    km = KeyManager("local-selftest")
    first = _envelope(km, 5)
    gw_log = BASE / "gateway.jsonl"
    uplink = CloudUplink(
        "https://127.0.0.1:18443/v1/envelope",
        os.environ["CLOUD_TLS_CERT"],
        gw_log,
        retries=2,
    )
    uplink.start()
    t_recv = time.time_ns()
    uplink.submit(first, t_recv)

    cloud_log = Path(os.environ["CLOUD_LOG"])
    _wait(cloud_log, lambda rows: any(r.get("event") == "accept" and r.get("seq") == 5 for r in rows))
    uplink.submit(dict(first), t_recv)
    _wait(cloud_log, lambda rows: any(r.get("event") == "duplicate" and r.get("seq") == 5 for r in rows))

    older = _envelope(km, 1)
    uplink.submit(older, time.time_ns())
    gw = _wait(gw_log, lambda rows: any(r.get("reason") == "replay" for r in rows))

    forged = dict(first)
    sig = bytearray(base64.b64decode(forged["signature"]))
    sig[-1] ^= 0x01
    forged["signature"] = base64.b64encode(bytes(sig)).decode()
    uplink.submit(forged, time.time_ns())
    gw = _wait(gw_log, lambda rows: any(r.get("reason") == "bad_signature" for r in rows))

    accepts = [r for r in _lines(cloud_log) if r.get("event") == "accept"]
    if len(accepts) != 1:
        raise SystemExit(f"Expected 1 accepted delivery, found {len(accepts)}")
    replay = json.loads(Path(os.environ["CLOUD_REPLAY"]).read_text())
    if replay.get("dev-e2e") != 5:
        raise SystemExit(f"Replay file is {replay}")

    server.shutdown()
    server.server_close()
    time.sleep(0.2)
    server2 = make_server()
    threading.Thread(target=server2.serve_forever, daemon=True).start()
    time.sleep(0.3)
    uplink.submit(dict(first), time.time_ns())
    _wait(
        cloud_log,
        lambda rows: sum(1 for r in rows if r.get("event") == "duplicate" and r.get("seq") == 5) >= 2,
    )
    accepts = [r for r in _lines(cloud_log) if r.get("event") == "accept"]
    if len(accepts) != 1:
        raise SystemExit("Restart processed the same message again")

    ok = next(r for r in gw if r.get("event") == "https_result" and r.get("ok") and not r.get("duplicate"))
    for key in ("https_rtt_ns", "mqtt_to_ack_ns", "t_verify_decrypt_ns"):
        if not isinstance(ok.get(key), int) or ok[key] < 0:
            raise SystemExit(f"Missing timing {key}")
    replay_row = next(r for r in gw if r.get("reason") == "replay")
    if replay_row.get("attempts") != 1:
        raise SystemExit("Replay was retried")

    print(
        "E2E self-test passed (local wiring check, not an experiment): "
        f"https_rtt_ns={ok['https_rtt_ns']} "
        f"t_verify_decrypt_ns={ok['t_verify_decrypt_ns']} "
        f"mqtt_to_ack_ns={ok['mqtt_to_ack_ns']}"
    )
    print(f"Temp files: {BASE}")
    server2.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
