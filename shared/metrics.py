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

        payload_bytes = len(str(result).encode("utf-8"))
        t_total_ns = end_ns - start_ns

        t_encap_ns = int(result.pop("_t_encap_ns", 0))
        t_sign_ns = int(result.pop("_t_sign_ns", 0))
        t_aes_ns = int(result.pop("_t_aes_ns", 0))

        rss_delta_kb = int((end_rss - start_rss) / 1024)
        cpu_user_ns = end_cpu_user - start_cpu_user
        cpu_sys_ns = end_cpu_sys - start_cpu_sys

        # Efficiency coefficient η = security_bits / (ΔT × payload_bytes)
        # Use total wall latency as ΔT by default.
        denom = float(max(t_total_ns, 1) * max(payload_bytes, 1))
        eta = float(getattr(self, "SECURITY_BITS", 0)) / denom

        sample = BenchSample(
            ts_unix_ns=time.time_ns(),
            device_id=self.DEVICE_ID,
            session_id=getattr(self, "_session_id", "unknown"),
            seq=int(result.get("seq", -1)),
            profile=getattr(self, "PROFILE_NAME", ""),
            alg_kem=getattr(self, "ALG_KEM", ""),
            alg_sig=getattr(self, "ALG_SIG", ""),
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

        out_path = os.getenv("BENCH_CSV_PATH", "benchmarks/pqc_metrics.csv")
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

