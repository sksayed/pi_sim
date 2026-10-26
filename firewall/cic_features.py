"""
cic_features.py — Live flow features aligned with the CIC IoMT 2024 columns.

Definitions follow the values observed in the dataset itself:
  - packet lengths are Ethernet frame lengths (IP total length + 14), so a
    bare TCP ACK is 54 B (66 B with timestamps)
  - Duration is the mean IP TTL, not a time
  - *_flag_number is the share of packets carrying that flag
  - Rate = Srate = packets per second; Drate is always 0 in the dataset
  - Tot size equals AVG; Magnitue = sqrt(2*AVG); Radius = sqrt(2)*Std
  - IPv and LLC are 1 for every row

Header_Length, the *_count columns, Tot sum, IAT, Number, Covariance,
Variance, and Weight depend on how the dataset was captured and windowed and
cannot be reproduced live. They are still computed (for logging) but are
excluded from the model through firewall/feature_columns.json.
"""

from __future__ import annotations

import math

ETH_HEADER_BYTES = 14

CIC_COLUMNS = [
    "Header_Length", "Protocol Type", "Duration", "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
    "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP",
    "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number",
    "Magnitue", "Radius", "Covariance", "Variance", "Weight",
]

NOT_REPRODUCIBLE = [
    "Header_Length", "ack_count", "syn_count", "fin_count", "rst_count",
    "Tot sum", "IAT", "Number", "Covariance", "Variance", "Weight",
]

_FLAG_BITS = {
    "fin_flag_number": 0x01, "syn_flag_number": 0x02, "rst_flag_number": 0x04,
    "psh_flag_number": 0x08, "ack_flag_number": 0x10, "ece_flag_number": 0x40,
    "cwr_flag_number": 0x80,
}


def compute(proto: int, src_port: int, dst_port: int, frame_lens: list[int],
            ttls: list[int], flags: list[int], times: list[float],
            hdr_lens: list[int], fwd_pkts: int, bwd_pkts: int) -> dict[str, float]:
    n = len(frame_lens)
    if n == 0:
        return {c: 0.0 for c in CIC_COLUMNS}
    duration = times[-1] - times[0]
    rate = n / duration if duration > 0 else 0.0
    avg = sum(frame_lens) / n
    std = math.sqrt(sum((x - avg) ** 2 for x in frame_lens) / n)
    iats = [b - a for a, b in zip(times, times[1:])]
    sp, dp = src_port, dst_port

    feats: dict[str, float] = {
        "Header_Length": float(sum(hdr_lens)),
        "Protocol Type": float(proto),
        "Duration": sum(ttls) / n,
        "Rate": rate,
        "Srate": rate,
        "Drate": 0.0,
        "ack_count": float(sum(1 for f in flags if f & 0x10)),
        "syn_count": float(sum(1 for f in flags if f & 0x02)),
        "fin_count": float(sum(1 for f in flags if f & 0x01)),
        "rst_count": float(sum(1 for f in flags if f & 0x04)),
        "HTTP": float(80 in (sp, dp)),
        "HTTPS": float(443 in (sp, dp)),
        "DNS": float(53 in (sp, dp)),
        "Telnet": float(23 in (sp, dp)),
        "SMTP": float(25 in (sp, dp)),
        "SSH": float(22 in (sp, dp)),
        "IRC": float(6667 in (sp, dp)),
        "TCP": float(proto == 6),
        "UDP": float(proto == 17),
        "DHCP": float(dp in (67, 68)),
        "ARP": 0.0,
        "ICMP": float(proto == 1),
        "IGMP": float(proto == 2),
        "IPv": 1.0,
        "LLC": 1.0,
        "Tot sum": float(sum(frame_lens)),
        "Min": float(min(frame_lens)),
        "Max": float(max(frame_lens)),
        "AVG": avg,
        "Std": std,
        "Tot size": avg,
        "IAT": sum(iats) / len(iats) if iats else 0.0,
        "Number": float(n),
        "Magnitue": math.sqrt(2 * avg),
        "Radius": math.sqrt(2) * std,
        "Covariance": 0.0,
        "Variance": 0.0,
        "Weight": float(fwd_pkts * bwd_pkts),
    }
    for name, bit in _FLAG_BITS.items():
        feats[name] = sum(1 for f in flags if f & bit) / n
    return feats
