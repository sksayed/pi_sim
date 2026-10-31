"""Gateway-clock offset and client-to-cloud delay.

offset_ns is gateway time minus local time, from the median of control-port
pings. A local stamp moves onto the gateway clock by adding that offset.
End-to-end delay is then cloud-accept minus client-publish, both on the
gateway clock. This removes a constant offset. It does not remove Wi-Fi delay
inside the ping itself.
"""

from __future__ import annotations

import json
import socket
import statistics
import time


def e2e_ns(
    t_publish_ns: int,
    client_offset_ns: int,
    t_cloud_ns: int,
    cloud_offset_ns: int,
) -> int:
    """Client publish to cloud accept, both stamps on the gateway clock."""
    publish_gw = int(t_publish_ns) + int(client_offset_ns)
    cloud_gw = int(t_cloud_ns) + int(cloud_offset_ns)
    return cloud_gw - publish_gw


def measure_offset_ns(
    host: str,
    port: int,
    samples: int = 5,
    timeout: float = 2.0,
) -> tuple[int, int]:
    """Return (offset_ns, median_rtt_ns). offset_ns is gateway minus local.

    Raises OSError or RuntimeError when every sample fails.
    """
    offsets: list[int] = []
    rtts: list[int] = []
    errors: list[str] = []
    for _ in range(samples):
        try:
            gw_ns, t0, t1 = _ping(host, port, timeout)
        except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
            errors.append(str(exc))
            continue
        offsets.append(gw_ns - (t0 + t1) // 2)
        rtts.append(t1 - t0)
    if not offsets:
        detail = errors[-1] if errors else "no samples"
        raise RuntimeError(f"clock sync to {host}:{port} failed: {detail}")
    return int(statistics.median(offsets)), int(statistics.median(rtts))


def _ping(host: str, port: int, timeout: float) -> tuple[int, int, int]:
    """Return gateway time_ns and the local send/recv stamps around the ping."""
    req = b'{"cmd":"ping"}\n'
    t0 = time.time_ns()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(req)
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    t1 = time.time_ns()
    resp = json.loads(data.decode())
    if not resp.get("ok"):
        raise RuntimeError(resp.get("error", "ping refused"))
    if "gw_time_ns" in resp:
        gw_ns = int(resp["gw_time_ns"])
    else:
        gw_ns = int(float(resp["gw_time"]) * 1_000_000_000)
    return gw_ns, t0, t1
