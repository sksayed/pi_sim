"""HTTPS cloud receiver. Listens on port 8443.

Verifies the gateway ML-DSA signature, decapsulates ML-KEM, decrypts AES-GCM,
then applies the replay rule. An HTTP 200 is returned only after all of those
succeed. A retry of the latest accepted (device_id, seq) returns 200 with
duplicate=true and is not stored again. An older seq returns 409.

    python -m cloud.https_server
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "gateway"))

from benign_pipeline import encode_signed_envelope
from cloud.uplink_keys import decapsulate, load_pinned, read_alg, verify

PORT = int(os.getenv("CLOUD_PORT", "8443"))
BIND = os.getenv("CLOUD_BIND", "0.0.0.0")
LOG_PATH = Path(os.getenv("CLOUD_LOG", str(REPO_ROOT / "results" / "cloud" / "uplink.jsonl")))
REPLAY_PATH = Path(os.getenv("CLOUD_REPLAY", str(REPO_ROOT / "results" / "cloud" / "replay_state.json")))
MAX_BODY = 256 * 1024


class ReplayStore:
    """Last accepted seq per device. The file is replaced atomically."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.last: dict[str, int] = {}
        if path.exists():
            self.last = {k: int(v) for k, v in json.loads(path.read_text()).items()}

    def decide(self, device_id: str, seq: int) -> str:
        """accept, duplicate, or replay. accept is persisted before return."""
        with self._lock:
            prev = self.last.get(device_id)
            if prev is None or seq > prev:
                self.last[device_id] = seq
                self._save()
                return "accept"
            if seq == prev:
                return "duplicate"
            return "replay"

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.last, indent=2) + "\n")
        os.replace(tmp, self.path)


class CloudState:
    def __init__(self) -> None:
        trust = Path(os.environ["CLOUD_TRUST"])
        pk_path = Path(os.environ["CLOUD_GATEWAY_PK"])
        sk_path = Path(os.environ["CLOUD_KEM_SK"])
        self.gateway_pk = load_pinned(pk_path, trust, "gateway_sig_pk")
        self.sig_alg = read_alg(pk_path, "ML-DSA-65")
        self.kem_sk = sk_path.read_bytes()
        self.kem_alg = read_alg(sk_path, "ML-KEM-768")
        self.replay = ReplayStore(REPLAY_PATH)
        self.log_lock = threading.Lock()
        self.counter_lock = threading.Lock()
        self.accepted = 0
        self.duplicates = 0
        self.rejected = 0
        self.crypto_ns_sum = 0
        self.crypto_n = 0
        self.started = time.perf_counter()
        self.proc = psutil.Process()
        self.proc.cpu_percent(interval=None)
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    def log(self, record: dict) -> None:
        with self.counter_lock:
            accepted = self.accepted
            duplicates = self.duplicates
            rejected = self.rejected
            crypto_n = self.crypto_n
            crypto_sum = self.crypto_ns_sum
        elapsed = max(time.perf_counter() - self.started, 1e-9)
        decisions = accepted + rejected
        record.setdefault("t_ns", time.time_ns())
        record["rss_kb"] = self.proc.memory_info().rss // 1024
        record["cpu_percent"] = self.proc.cpu_percent(interval=None)
        record["accepted_total"] = accepted
        record["duplicate_total"] = duplicates
        record["rejected_total"] = rejected
        record["elapsed_s"] = round(elapsed, 3)
        record["accept_per_s"] = round(accepted / elapsed, 6)
        record["delivery_ratio"] = round(accepted / decisions, 6) if decisions else None
        record["mean_verify_decrypt_ns"] = int(crypto_sum / crypto_n) if crypto_n else None
        line = json.dumps(record, separators=(",", ":"))
        with self.log_lock:
            with LOG_PATH.open("a") as fh:
                fh.write(line + "\n")


STATE: CloudState | None = None


def open_envelope(payload: dict) -> tuple[bool, str, bytes, int]:
    """Return ok, reason, plaintext, verify/decrypt nanoseconds."""
    assert STATE is not None
    t0 = time.perf_counter_ns()
    try:
        kem_ct = base64.b64decode(payload["kem_ciphertext"], validate=True)
        nonce = base64.b64decode(payload["nonce"], validate=True)
        ciphertext = base64.b64decode(payload["ciphertext"], validate=True)
        signature = base64.b64decode(payload["signature"], validate=True)
        message = encode_signed_envelope(
            payload["device_id"], int(payload["seq"]), kem_ct, nonce, ciphertext
        )
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"malformed:{exc}", b"", time.perf_counter_ns() - t0
    if not verify(STATE.sig_alg, STATE.gateway_pk, message, signature):
        return False, "bad_signature", b"", time.perf_counter_ns() - t0
    try:
        ss = decapsulate(STATE.kem_alg, STATE.kem_sk, kem_ct)
        plain = AESGCM(ss[:32]).decrypt(nonce, ciphertext, None)
    except Exception:
        return False, "decrypt_failed", b"", time.perf_counter_ns() - t0
    return True, "ok", plain, time.perf_counter_ns() - t0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, status: int, body: dict) -> None:
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path != "/health":
            self._send(404, {"ok": False, "reason": "not_found"})
            return
        self._send(200, {"ok": True})

    def do_POST(self) -> None:
        assert STATE is not None
        if self.path != "/v1/envelope":
            self._send(404, {"ok": False, "reason": "not_found"})
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n <= 0 or n > MAX_BODY:
            STATE.rejected += 1
            STATE.log({"event": "reject", "reason": "bad_length"})
            self._send(400, {"ok": False, "reason": "bad_length"})
            return
        try:
            payload = json.loads(self.rfile.read(n))
            device_id = str(payload["device_id"])
            seq = int(payload["seq"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, UnicodeError):
            STATE.rejected += 1
            STATE.log({"event": "reject", "reason": "malformed"})
            self._send(400, {"ok": False, "reason": "malformed"})
            return

        ok, reason, plain, crypto_ns = open_envelope(payload)
        if not ok:
            with STATE.counter_lock:
                STATE.rejected += 1
                STATE.crypto_ns_sum += crypto_ns
                STATE.crypto_n += 1
            STATE.log({
                "event": "reject", "device_id": device_id, "seq": seq,
                "reason": reason, "t_verify_decrypt_ns": crypto_ns,
            })
            status = 401 if reason == "bad_signature" else 400
            self._send(status, {"ok": False, "reason": reason, "device_id": device_id, "seq": seq})
            return

        decision = STATE.replay.decide(device_id, seq)
        if decision == "replay":
            with STATE.counter_lock:
                STATE.rejected += 1
                STATE.crypto_ns_sum += crypto_ns
                STATE.crypto_n += 1
            STATE.log({
                "event": "replay", "device_id": device_id, "seq": seq,
                "t_verify_decrypt_ns": crypto_ns,
            })
            self._send(409, {
                "ok": False, "reason": "replay", "device_id": device_id, "seq": seq,
                "t_verify_decrypt_ns": crypto_ns,
            })
            return
        if decision == "duplicate":
            with STATE.counter_lock:
                STATE.duplicates += 1
            STATE.log({
                "event": "duplicate", "device_id": device_id, "seq": seq,
                "t_verify_decrypt_ns": crypto_ns,
            })
            self._send(200, {
                "ok": True, "duplicate": True, "device_id": device_id, "seq": seq,
                "t_verify_decrypt_ns": crypto_ns,
            })
            return

        with STATE.counter_lock:
            STATE.accepted += 1
            STATE.crypto_ns_sum += crypto_ns
            STATE.crypto_n += 1
        STATE.log({
            "event": "accept", "device_id": device_id, "seq": seq,
            "payload_bytes": len(plain), "t_verify_decrypt_ns": crypto_ns,
        })
        self._send(200, {
            "ok": True, "duplicate": False, "device_id": device_id, "seq": seq,
            "t_verify_decrypt_ns": crypto_ns,
        })


def _resource_loop(stop: threading.Event) -> None:
    assert STATE is not None
    while not stop.wait(5.0):
        STATE.log({"event": "resource"})


def make_server() -> ThreadingHTTPServer:
    global STATE
    from cloud.uplink_keys import kem_algorithm
    kem_algorithm()
    STATE = CloudState()
    cert = os.environ["CLOUD_TLS_CERT"]
    key = os.environ["CLOUD_TLS_KEY"]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


def main() -> int:
    missing = [k for k in ("CLOUD_TRUST", "CLOUD_GATEWAY_PK", "CLOUD_KEM_SK", "CLOUD_TLS_CERT", "CLOUD_TLS_KEY")
               if not os.getenv(k)]
    if missing:
        print("Missing environment variables: " + ", ".join(missing), file=sys.stderr)
        return 1
    server = make_server()
    stop = threading.Event()
    threading.Thread(target=_resource_loop, args=(stop,), daemon=True).start()
    print(f"[CLOUD] HTTPS on {BIND}:{PORT}  log={LOG_PATH}  replay={REPLAY_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[CLOUD] Stopped.")
    finally:
        stop.set()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
