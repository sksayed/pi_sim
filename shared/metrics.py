"""
metrics.py — High-resolution benchmarking utilities.

Designed for Raspberry Pi / Linux environments where context switching can
skew coarse timing. Captures:
  - wall time via perf_counter_ns()
  - RSS delta via psutil
  - CPU time delta (user + system) via psutil

Results are logged to a thread-safe CSV writer so that cryptographic timing
is minimally perturbed by IO.
"""

from __future__ import annotations

import csv
import json
import os
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import psutil


@dataclass(frozen=True)
class BenchSample:
    ts_unix_ns: int
    device_id: str
    session_id: str
    seq: int
    profile: str
    alg_kem: str
    alg_sig: str
    crypto_type: str
    crypto_kind: str
    payload_target_bytes: int
    security_bits: int
    t_total_ns: int
    t_encap_ns: int
    t_sign_ns: int
    t_aes_ns: int
    cpu_user_ns: int
    cpu_sys_ns: int
    rss_delta_kb: int
    payload_bytes: int
    eta: float
    pqc_available: bool


@dataclass(frozen=True)
class GatewayBenchSample:
    ts_unix_ns: int
    device_id: str
    session_id: str
    seq: int
    profile: str
    alg_kem: str
    alg_sig: str
    crypto_type: str
    crypto_kind: str
    payload_target_bytes: int
    security_bits: int
    t_total_ns: int
    t_decap_ns: int
    t_aes_dec_ns: int
    t_verify_ns: int
    cpu_user_ns: int
    cpu_sys_ns: int
    rss_delta_kb: int
    payload_bytes: int
    pqc_available: bool
    accepted: bool
    t_publish_ns: int        # time.time_ns() on client just before mqtt.publish()
    t_broker_transit_ns: int # t_recv_ns (gateway) - t_publish_ns (client); 0 if unavailable
    t_total_gateway_ns: int  # perf_counter wall time from on_message entry to handler exit


class CsvBenchLogger:
    """
    Thread-safe CSV logger with a single background writer thread.
    """

    _instance: Optional["CsvBenchLogger"] = None
    _lock = threading.Lock()

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._q: "queue.Queue[Optional[BenchSample]]" = queue.Queue(maxsize=10000)
        self._thread = threading.Thread(target=self._run, name="bench-csv-writer", daemon=True)
        self._thread.start()

    @classmethod
    def get(cls, path: str) -> "CsvBenchLogger":
        with cls._lock:
            if cls._instance is None:
                cls._instance = CsvBenchLogger(path)
            return cls._instance

    def log(self, sample: BenchSample) -> None:
        try:
            self._q.put_nowait(sample)
        except queue.Full:
            # Drop samples rather than blocking crypto/MQTT loop.
            pass

    def _run(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        file_exists = self._path.exists()
        with self._path.open("a", newline="") as f:
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "ts_unix_ns",
                    "device_id",
                    "session_id",
                    "seq",
                    "profile",
                    "alg_kem",
                    "alg_sig",
                    "crypto_type",
                    "crypto_kind",
                    "payload_target_bytes",
                    "security_bits",
                    "t_total_ns",
                    "t_encap_ns",
                    "t_sign_ns",
                    "t_aes_ns",
                    "cpu_user_ns",
                    "cpu_sys_ns",
                    "rss_delta_kb",
                    "payload_bytes",
                    "eta",
                    "pqc_available",
                ],
            )
            if not file_exists:
                w.writeheader()

            while True:
                item = self._q.get()
                if item is None:
                    return
                w.writerow(item.__dict__)
                f.flush()


class CsvGatewayBenchLogger:
    """
    Thread-safe gateway CSV logger with a single background writer thread.
    """

    _instance: Optional["CsvGatewayBenchLogger"] = None
    _lock = threading.Lock()

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._q: "queue.Queue[Optional[GatewayBenchSample]]" = queue.Queue(maxsize=10000)
        self._thread = threading.Thread(target=self._run, name="gateway-bench-csv-writer", daemon=True)
        self._thread.start()

    @classmethod
    def get(cls, path: str) -> "CsvGatewayBenchLogger":
        with cls._lock:
            if cls._instance is None:
                cls._instance = CsvGatewayBenchLogger(path)
            return cls._instance

    def log(self, sample: GatewayBenchSample) -> None:
        try:
            self._q.put_nowait(sample)
        except queue.Full:
            # Drop samples rather than blocking the gateway loop.
            pass

    def _run(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        file_exists = self._path.exists()
        with self._path.open("a", newline="") as f:
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "ts_unix_ns",
                    "device_id",
                    "session_id",
                    "seq",
                    "profile",
                    "alg_kem",
                    "alg_sig",
                    "crypto_type",
                    "crypto_kind",
                    "payload_target_bytes",
                    "security_bits",
                    "t_total_ns",
                    "t_decap_ns",
                    "t_aes_dec_ns",
                    "t_verify_ns",
                    "cpu_user_ns",
                    "cpu_sys_ns",
                    "rss_delta_kb",
                    "payload_bytes",
                    "pqc_available",
                    "accepted",
                    "t_publish_ns",
                    "t_broker_transit_ns",
                    "t_total_gateway_ns",
                ],
            )
            if not file_exists:
                w.writeheader()

            while True:
                item = self._q.get()
                if item is None:
                    return
                w.writerow(item.__dict__)
                f.flush()


def _cpu_times_ns(process: psutil.Process) -> tuple[int, int]:
    t = process.cpu_times()
    # psutil returns seconds as float; convert to integer nanoseconds.
    return int(t.user * 1e9), int(t.system * 1e9)


def benchmark_pqc(func: Callable[..., Dict[str, Any]]) -> Callable[..., Dict[str, Any]]:
    """
    Decorator for ResearchProfileClient.build_message().

    Expectations:
      - `self` provides:
          DEVICE_ID, CRYPTO_TYPE, PROFILE_NAME, ALG_KEM, ALG_SIG,
          SECURITY_BITS, PQC_AVAILABLE (bool), session_id (str)
      - the wrapped function returns a dict that includes internal timing
        keys (nanoseconds):
          _t_encap_ns, _t_sign_ns, _t_aes_ns
    """

    def wrapper(self, *args, **kwargs):
        process = psutil.Process()

        start_rss = process.memory_info().rss
        start_cpu_user, start_cpu_sys = _cpu_times_ns(process)
        start_ns = time.perf_counter_ns()

        result: Dict[str, Any] = func(self, *args, **kwargs)

        end_ns = time.perf_counter_ns()
        end_cpu_user, end_cpu_sys = _cpu_times_ns(process)
        end_rss = process.memory_info().rss

        t_total_ns = end_ns - start_ns

        t_encap_ns = int(result.pop("_t_encap_ns", 0))
        t_sign_ns = int(result.pop("_t_sign_ns", 0))
        t_aes_ns = int(result.pop("_t_aes_ns", 0))

        # Measure payload size as actual JSON-on-wire bytes (excluding internal keys).
        payload_bytes = len(json.dumps(result, separators=(",", ":")).encode("utf-8"))

        rss_delta_kb = int((end_rss - start_rss) / 1024)
        cpu_user_ns = end_cpu_user - start_cpu_user
        cpu_sys_ns = end_cpu_sys - start_cpu_sys

        # Efficiency coefficient η = security_bits / (ΔT × payload_bytes)
        # Use summed crypto time (encap+sign+aes) to avoid psutil overhead skew.
        t_crypto_ns = int(t_encap_ns + t_sign_ns + t_aes_ns)
        denom = float(max(t_crypto_ns, 1) * max(payload_bytes, 1))
        eta = float(getattr(self, "SECURITY_BITS", 0)) / denom

        pt_target = int(getattr(self, "PAYLOAD_TARGET_BYTES", 0) or 0)
        if pt_target == 0:
            _pte = os.getenv("PAYLOAD_TARGET_BYTES", "").strip()
            if _pte:
                try:
                    pt_target = int(_pte)
                except ValueError:
                    pt_target = 0

        sample = BenchSample(
            ts_unix_ns=time.time_ns(),
            device_id=self.DEVICE_ID,
            session_id=getattr(self, "_session_id", "unknown"),
            seq=int(result.get("seq", -1)),
            profile=getattr(self, "PROFILE_NAME", ""),
            alg_kem=getattr(self, "ALG_KEM", ""),
            alg_sig=getattr(self, "ALG_SIG", ""),
            crypto_type=str(getattr(self, "CRYPTO_TYPE", "")),
            crypto_kind=str(getattr(self, "CRYPTO_KIND", "PQC")),
            payload_target_bytes=pt_target,
            security_bits=int(getattr(self, "SECURITY_BITS", 0)),
            t_total_ns=t_total_ns,
            t_encap_ns=t_encap_ns,
            t_sign_ns=t_sign_ns,
            t_aes_ns=t_aes_ns,
            cpu_user_ns=cpu_user_ns,
            cpu_sys_ns=cpu_sys_ns,
            rss_delta_kb=rss_delta_kb,
            payload_bytes=payload_bytes,
            eta=eta,
            pqc_available=bool(getattr(self, "PQC_AVAILABLE", False)),
        )

        out_path = os.getenv("BENCH_CSV_PATH", "benchmarks/client/pqc_metrics.csv")
        CsvBenchLogger.get(out_path).log(sample)

        # Optionally attach a minimal metrics block on the wire.
        if os.getenv("INCLUDE_METRICS_ON_WIRE", "0") == "1":
            result["metrics"] = {
                "t_total_ns": t_total_ns,
                "t_encap_ns": t_encap_ns,
                "t_sign_ns": t_sign_ns,
                "t_aes_ns": t_aes_ns,
                "rss_delta_kb": rss_delta_kb,
                "cpu_user_ns": cpu_user_ns,
                "cpu_sys_ns": cpu_sys_ns,
                "payload_bytes": payload_bytes,
                "eta": eta,
            }

        return result

    return wrapper


def log_gateway_pqc(
    *,
    device_id: str,
    session_id: str,
    seq: int,
    profile: str,
    alg_kem: str,
    alg_sig: str,
    crypto_type: str = "",
    crypto_kind: str = "PQC",
    payload_target_bytes: int = 0,
    security_bits: int = 0,
    payload_bytes: int,
    pqc_available: bool,
    accepted: bool,
    t_total_ns: int,
    t_decap_ns: int,
    t_aes_dec_ns: int,
    t_verify_ns: int,
    cpu_user_ns: int,
    cpu_sys_ns: int,
    rss_delta_kb: int,
    t_publish_ns: int = 0,
    t_broker_transit_ns: int = 0,
    t_total_gateway_ns: int = 0,
) -> None:
    """
    Append one gateway-side PQC decrypt/verify benchmark row to CSV.

    Output path defaults to `benchmarks/gateway/pqc_metrics_gateway.csv` and can be
    overridden via `GATEWAY_BENCH_CSV_PATH`.
    """
    sample = GatewayBenchSample(
        ts_unix_ns=time.time_ns(),
        device_id=device_id,
        session_id=session_id,
        seq=int(seq),
        profile=profile,
        alg_kem=alg_kem,
        alg_sig=alg_sig,
        crypto_type=crypto_type,
        crypto_kind=crypto_kind,
        payload_target_bytes=int(payload_target_bytes),
        security_bits=int(security_bits),
        t_total_ns=int(t_total_ns),
        t_decap_ns=int(t_decap_ns),
        t_aes_dec_ns=int(t_aes_dec_ns),
        t_verify_ns=int(t_verify_ns),
        cpu_user_ns=int(cpu_user_ns),
        cpu_sys_ns=int(cpu_sys_ns),
        rss_delta_kb=int(rss_delta_kb),
        payload_bytes=int(payload_bytes),
        pqc_available=bool(pqc_available),
        accepted=bool(accepted),
        t_publish_ns=int(t_publish_ns),
        t_broker_transit_ns=int(t_broker_transit_ns),
        t_total_gateway_ns=int(t_total_gateway_ns),
    )

    out_path = os.getenv("GATEWAY_BENCH_CSV_PATH", "benchmarks/gateway/pqc_metrics_gateway.csv")
    CsvGatewayBenchLogger.get(out_path).log(sample)

