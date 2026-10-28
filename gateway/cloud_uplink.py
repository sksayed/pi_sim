"""Background HTTPS POST of Stage 2 envelopes.

The MQTT callback only queues the envelope. This thread performs the POST, so
a slow cloud does not stall Mosquitto. Transport failures are retried.
Application failures (bad signature, replay) are not retried.
A duplicate=true response counts as one delivery, not a second message.
"""

from __future__ import annotations

import json
import os
import queue
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _flag(name: str) -> bool:
    return os.getenv(name, "0").strip().lower() in ("1", "true", "yes", "on")


class CloudUplink:
    def __init__(self, url: str, tls_cert: str, log_path: Path, retries: int) -> None:
        self.url = url
        self.retries = max(1, retries)
        self.log_path = log_path
        self._ctx = ssl.create_default_context()
        self._ctx.load_verify_locations(tls_cert)
        self._ctx.check_hostname = True
        self._ctx.verify_mode = ssl.CERT_REQUIRED
        self._q: queue.Queue = queue.Queue(maxsize=10000)
        self._log_lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="cloud-https", daemon=True)

    def start(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._thread.start()
        print(f"[GATEWAY] Cloud HTTPS ON → {self.url} (TLS verify on)")

    def submit(self, payload: dict, t_mqtt_recv_ns: int) -> None:
        try:
            self._q.put_nowait((payload, t_mqtt_recv_ns))
        except queue.Full:
            self._write({
                "event": "drop",
                "reason": "queue_full",
                "device_id": payload.get("device_id"),
                "seq": payload.get("seq"),
                "t_ns": time.time_ns(),
            })

    def _write(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"))
        with self._log_lock:
            with self.log_path.open("a") as fh:
                fh.write(line + "\n")

    def _post_once(self, body: bytes) -> tuple[int, dict, int]:
        req = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        t0 = time.perf_counter_ns()
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=5) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
            t0_rtt = time.perf_counter_ns() - t0
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"ok": False, "reason": "bad_response"}
            return status, parsed, t0_rtt
        rtt = time.perf_counter_ns() - t0
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"ok": False, "reason": "bad_response"}
        return status, parsed, rtt

    def _run(self) -> None:
        while True:
            payload, t_mqtt = self._q.get()
            body = json.dumps(payload, separators=(",", ":")).encode()
            device_id = payload.get("device_id")
            seq = payload.get("seq")
            attempts = 0
            last_status = 0
            last_body: dict = {}
            rtt = 0
            reason = "transport"
            while attempts < self.retries:
                attempts += 1
                try:
                    last_status, last_body, rtt = self._post_once(body)
                except Exception as exc:
                    reason = f"transport:{exc}"
                    time.sleep(0.05 * attempts)
                    continue
                if last_status == 200 and last_body.get("ok"):
                    self._write({
                        "event": "https_result",
                        "t_ns": time.time_ns(),
                        "device_id": device_id,
                        "seq": seq,
                        "ok": True,
                        "duplicate": bool(last_body.get("duplicate")),
                        "http_status": last_status,
                        "https_rtt_ns": rtt,
                        "mqtt_to_ack_ns": time.time_ns() - t_mqtt,
                        "t_verify_decrypt_ns": last_body.get("t_verify_decrypt_ns"),
                        "attempts": attempts,
                        "reason": "duplicate" if last_body.get("duplicate") else "ok",
                    })
                    break
                if last_status in (400, 401, 409):
                    self._write({
                        "event": "https_result",
                        "t_ns": time.time_ns(),
                        "device_id": device_id,
                        "seq": seq,
                        "ok": False,
                        "duplicate": False,
                        "http_status": last_status,
                        "https_rtt_ns": rtt,
                        "mqtt_to_ack_ns": time.time_ns() - t_mqtt,
                        "t_verify_decrypt_ns": last_body.get("t_verify_decrypt_ns"),
                        "attempts": attempts,
                        "reason": last_body.get("reason", "rejected"),
                    })
                    break
                reason = last_body.get("reason", f"http_{last_status}")
                time.sleep(0.05 * attempts)
            else:
                self._write({
                    "event": "https_result",
                    "t_ns": time.time_ns(),
                    "device_id": device_id,
                    "seq": seq,
                    "ok": False,
                    "duplicate": False,
                    "http_status": last_status,
                    "https_rtt_ns": rtt,
                    "mqtt_to_ack_ns": time.time_ns() - t_mqtt,
                    "attempts": attempts,
                    "reason": reason,
                })


def start_from_env():
    """Load pinned keys, install them in Stage 2, and start the POST thread."""
    if not _flag("GW_CLOUD_FORWARD"):
        return None
    sys.path.insert(0, str(REPO))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from cloud.uplink_keys import load_pinned, read_alg
    from benign_pipeline import use_provisioned_uplink
    from shared.key_manager import PQC_AVAILABLE

    if not PQC_AVAILABLE:
        raise RuntimeError("GW_CLOUD_FORWARD=1 requires liboqs. Refusing the shared-secret fallback.")
    missing = [k for k in (
        "CLOUD_URL", "GATEWAY_SIG_SK", "GATEWAY_CLOUD_PK", "GATEWAY_TRUST", "CLOUD_TLS_CERT",
    ) if not os.getenv(k)]
    if missing:
        raise RuntimeError("GW_CLOUD_FORWARD=1 but missing: " + ", ".join(missing))
    trust = Path(os.environ["GATEWAY_TRUST"])
    cloud_pk_path = Path(os.environ["GATEWAY_CLOUD_PK"])
    sig_sk_path = Path(os.environ["GATEWAY_SIG_SK"])
    cloud_pk = load_pinned(cloud_pk_path, trust, "cloud_kem_pk")
    gateway_sk = sig_sk_path.read_bytes()
    use_provisioned_uplink(
        read_alg(cloud_pk_path, "ML-KEM-768"),
        read_alg(sig_sk_path, "ML-DSA-65"),
        cloud_pk,
        gateway_sk,
        "gateway",
    )
    uplink = CloudUplink(
        os.environ["CLOUD_URL"],
        os.environ["CLOUD_TLS_CERT"],
        Path(os.getenv("GW_CLOUD_LOG", str(REPO / "results" / "gateway" / "cloud_uplink.jsonl"))),
        int(os.getenv("GW_CLOUD_RETRIES", "3")),
    )
    uplink.start()
    return uplink
