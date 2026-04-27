#!/usr/bin/env python3
"""
mqtt_firewall.py — Inline LightGBM Firewall for MQTT (port 1883)
================================================================
Feature set matches CIC-IoMT 2024 dataset column order EXACTLY:
    Header_Length, Protocol Type, Duration, Rate, Srate, Drate,
    fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
    ack_flag_number, ece_flag_number, cwr_flag_number,
    ack_count, syn_count, fin_count, rst_count,
    HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC,
    TCP, UDP, DHCP, ARP, ICMP, IGMP, IPv, LLC,
    Tot sum, Min, Max, AVG, Std, Tot size, IAT,
    Number, Magnitue, Radius, Covariance, Variance, Weight

Requirements:
    pip install netfilterqueue dpkt lightgbm numpy joblib

iptables setup (run once before starting):
    sudo iptables -I INPUT  -p tcp --dport 1883 -j NFQUEUE --queue-num 0
    sudo iptables -I INPUT  -p tcp --dport 1883 -m conntrack --ctstate ESTABLISHED -j NFQUEUE --queue-num 0
    sudo iptables -I OUTPUT -p tcp --sport 1883 -j NFQUEUE --queue-num 0

Run:
    sudo python3 mqtt_firewall.py
"""

import os
import math
import time
import threading
import subprocess
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
import lightgbm as lgb
import dpkt
import netfilterqueue

# ─── Configuration ────────────────────────────────────────────────────────────
QUEUE_NUM          = 0
MODEL_PATH         = "model.txt"
SCALER_PATH        = None          # e.g. "scaler.pkl"  — set None if unused
FLOW_TIMEOUT_S     = 10.0          # Classify flow after N seconds idle
MIN_PKTS_CLASSIFY  = 3             # Skip flows with fewer packets
ATTACK_THRESHOLD   = 0.5           # Probability threshold for "attack" label
BLOCK_VERDICT      = True          # False = IDS-only (log but don't block)
LOG_FILE           = "/var/log/mqtt_firewall.log"
REAPER_INTERVAL_S  = 1.0

# CIC-IoMT 2024 exact feature order (45 features, label excluded)
FEATURE_NAMES = [
    "Header_Length", "Protocol Type", "Duration", "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
    "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT",
    "Number", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
]

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ─── Type alias ───────────────────────────────────────────────────────────────
FlowKey = Tuple[str, str, int, int, int]  # src_ip, dst_ip, sport, dport, proto


# ─── Flow record ──────────────────────────────────────────────────────────────
@dataclass
class Flow:
    # 5-tuple identity
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    proto:    int       # IP protocol number (6=TCP)
    ip_ver:   int = 4   # 4 or 6

    # Timestamps
    start_ts: float = field(default_factory=time.time)
    last_ts:  float = field(default_factory=time.time)
    _prev_ts: float = 0.0   # for inter-arrival time tracking

    # Packet payload lengths (all directions combined)
    pkt_lens: List[int] = field(default_factory=list)

    # Forward / backward payload lengths (for Radius / Covariance)
    fwd_lens: List[int] = field(default_factory=list)
    bwd_lens: List[int] = field(default_factory=list)

    # Accumulated header bytes (IP header + TCP header per packet)
    total_header_bytes: int = 0

    # Packet counts
    fwd_pkts: int = 0
    bwd_pkts: int = 0

    # Inter-arrival times (seconds between consecutive packets, any direction)
    iats: List[float] = field(default_factory=list)

    # TCP flag counters
    fin_flag_number: int = 0
    syn_flag_number: int = 0
    rst_flag_number: int = 0
    psh_flag_number: int = 0
    ack_flag_number: int = 0
    ece_flag_number: int = 0
    cwr_flag_number: int = 0

    classified: bool = False

    # ── helpers ──────────────────────────────────────────────────────────────
    def is_forward(self, src_ip: str, src_port: int) -> bool:
        return src_ip == self.src_ip and src_port == self.src_port

    def add_packet(self, payload_len: int, tcp_flags: int, ts: float,
                   ip_hdr_len: int, tcp_hdr_len: int,
                   is_fwd: bool) -> None:
        self.last_ts = ts
        self.total_header_bytes += ip_hdr_len + tcp_hdr_len
        self.pkt_lens.append(payload_len)

        # IAT: time since previous packet (any direction)
        if self._prev_ts > 0:
            self.iats.append(ts - self._prev_ts)
        self._prev_ts = ts

        # Direction split for Radius / Covariance
        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_lens.append(payload_len)
        else:
            self.bwd_pkts += 1
            self.bwd_lens.append(payload_len)

        # TCP flags  (FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08
        #             ACK=0x10 URG=0x20 ECE=0x40 CWR=0x80)
        if tcp_flags & 0x01: self.fin_flag_number += 1
        if tcp_flags & 0x02: self.syn_flag_number += 1
        if tcp_flags & 0x04: self.rst_flag_number += 1
        if tcp_flags & 0x08: self.psh_flag_number += 1
        if tcp_flags & 0x10: self.ack_flag_number += 1
        if tcp_flags & 0x40: self.ece_flag_number += 1
        if tcp_flags & 0x80: self.cwr_flag_number += 1

    # ── CIC-IoMT 2024 feature extraction ─────────────────────────────────────
    def extract_features(self) -> np.ndarray:
        duration    = max(self.last_ts - self.start_ts, 1e-9)
        total_pkts  = self.fwd_pkts + self.bwd_pkts
        lens        = self.pkt_lens
        fwd_lens    = self.fwd_lens
        bwd_lens    = self.bwd_lens

        # ── helpers ──────────────────────────────────────────────────────────
        def smean(lst): return float(np.mean(lst))    if lst else 0.0
        def sstd(lst):  return float(np.std(lst))     if len(lst) > 1 else 0.0
        def svar(lst):  return float(np.var(lst))     if len(lst) > 1 else 0.0
        def smin(lst):  return float(min(lst))         if lst else 0.0
        def smax(lst):  return float(max(lst))         if lst else 0.0

        avg_len = smean(lens)
        std_len = sstd(lens)
        var_len = svar(lens)

        # Magnitude  =  sqrt(mean² + std²)
        magnitude = math.sqrt(avg_len ** 2 + std_len ** 2)

        # Radius  =  sqrt(var_fwd + var_bwd)
        radius = math.sqrt(svar(fwd_lens) + svar(bwd_lens))

        # Covariance between fwd and bwd lengths
        # Pad shorter list with 0s to equal length for np.cov
        if fwd_lens and bwd_lens:
            min_len = min(len(fwd_lens), len(bwd_lens))
            cov_matrix = np.cov(
                fwd_lens[:min_len],
                bwd_lens[:min_len]
            )
            covariance = float(cov_matrix[0, 1]) if cov_matrix.shape == (2, 2) else 0.0
        else:
            covariance = 0.0

        # Weight  =  total_pkts * mean_payload
        weight = float(total_pkts) * avg_len

        # Protocol-type binary flags
        ports = {self.src_port, self.dst_port}
        is_http   = int(bool(ports & {80}))
        is_https  = int(bool(ports & {443}))
        is_dns    = int(bool(ports & {53}))
        is_telnet = int(bool(ports & {23}))
        is_smtp   = int(bool(ports & {25}))
        is_ssh    = int(bool(ports & {22}))
        is_irc    = int(bool(ports & {194}))
        is_tcp    = int(self.proto == 6)
        is_udp    = int(self.proto == 17)
        is_dhcp   = int(bool(ports & {67, 68}))
        is_arp    = 0   # ARP never reaches NFQUEUE as IP packet
        is_icmp   = int(self.proto == 1)
        is_igmp   = int(self.proto == 2)
        ipv       = float(self.ip_ver)
        is_llc    = 0   # LLC frames don't appear in standard IP flows

        feats = [
            # ── 0  Header_Length ──────────────────────────────────────────
            float(self.total_header_bytes),

            # ── 1  Protocol Type ──────────────────────────────────────────
            float(self.proto),

            # ── 2  Duration ───────────────────────────────────────────────
            duration,

            # ── 3  Rate   (total pkts / duration) ─────────────────────────
            float(total_pkts) / duration,

            # ── 4  Srate  (fwd pkts / duration) ──────────────────────────
            float(self.fwd_pkts) / duration,

            # ── 5  Drate  (bwd pkts / duration) ──────────────────────────
            float(self.bwd_pkts) / duration,

            # ── 6-12  TCP flag *_flag_number ──────────────────────────────
            float(self.fin_flag_number),
            float(self.syn_flag_number),
            float(self.rst_flag_number),
            float(self.psh_flag_number),
            float(self.ack_flag_number),
            float(self.ece_flag_number),
            float(self.cwr_flag_number),

            # ── 13-16  *_count (same values — dataset duplicates) ─────────
            float(self.ack_flag_number),   # ack_count
            float(self.syn_flag_number),   # syn_count
            float(self.fin_flag_number),   # fin_count
            float(self.rst_flag_number),   # rst_count

            # ── 17-31  Protocol binary flags ──────────────────────────────
            float(is_http),
            float(is_https),
            float(is_dns),
            float(is_telnet),
            float(is_smtp),
            float(is_ssh),
            float(is_irc),
            float(is_tcp),
            float(is_udp),
            float(is_dhcp),
            float(is_arp),
            float(is_icmp),
            float(is_igmp),
            ipv,
            float(is_llc),

            # ── 32  Tot sum  (sum of all payload bytes) ───────────────────
            float(sum(lens)),

            # ── 33  Min  (min payload length) ─────────────────────────────
            smin(lens),

            # ── 34  Max  (max payload length) ─────────────────────────────
            smax(lens),

            # ── 35  AVG  (mean payload length) ────────────────────────────
            avg_len,

            # ── 36  Std  (std dev of payload lengths) ─────────────────────
            std_len,

            # ── 37  Tot size  (total payload bytes — same as Tot sum) ─────
            float(sum(lens)),

            # ── 38  IAT  (mean inter-arrival time) ────────────────────────
            smean(self.iats),

            # ── 39  Number  (total packet count) ──────────────────────────
            float(total_pkts),

            # ── 40  Magnitue  [sic]  sqrt(mean² + std²) ──────────────────
            magnitude,

            # ── 41  Radius   sqrt(var_fwd + var_bwd) ─────────────────────
            radius,

            # ── 42  Covariance (fwd vs bwd lengths) ───────────────────────
            covariance,

            # ── 43  Variance  (payload lengths) ──────────────────────────
            var_len,

            # ── 44  Weight   total_pkts * mean_payload ────────────────────
            weight,
        ]

        assert len(feats) == 45, f"Feature count mismatch: {len(feats)}"
        return np.array(feats, dtype=np.float32).reshape(1, -1)


# ─── Flow Table ───────────────────────────────────────────────────────────────
class FlowTable:
    def __init__(self):
        self._flows: Dict[FlowKey, Flow] = {}
        self._lock = threading.Lock()

    def _canonical(self, src_ip, dst_ip, sport, dport,
                   proto) -> Tuple[FlowKey, bool]:
        fwd = (src_ip, dst_ip, sport, dport, proto)
        bwd = (dst_ip, src_ip, dport, sport, proto)
        with self._lock:
            if fwd in self._flows: return fwd, True
            if bwd in self._flows: return bwd, False
        return fwd, True  # new flow → forward direction

    def update(self, src_ip, dst_ip, sport, dport, proto,
               payload_len, tcp_flags, ts,
               ip_hdr_len, tcp_hdr_len,
               ip_ver=4) -> Tuple[FlowKey, "Flow"]:
        key, is_fwd = self._canonical(src_ip, dst_ip, sport, dport, proto)
        with self._lock:
            if key not in self._flows:
                self._flows[key] = Flow(
                    src_ip=key[0], dst_ip=key[1],
                    src_port=key[2], dst_port=key[3],
                    proto=proto, ip_ver=ip_ver,
                    start_ts=ts, last_ts=ts,
                )
            flow = self._flows[key]
            flow.add_packet(payload_len, tcp_flags, ts,
                            ip_hdr_len, tcp_hdr_len, is_fwd)
        return key, flow

    def get_expired(self, timeout: float) -> List[Tuple[FlowKey, "Flow"]]:
        now = time.time()
        out = []
        with self._lock:
            for key, flow in list(self._flows.items()):
                pkt_count = flow.fwd_pkts + flow.bwd_pkts
                if (not flow.classified
                        and (now - flow.last_ts) > timeout
                        and pkt_count >= MIN_PKTS_CLASSIFY):
                    out.append((key, flow))
        return out

    def remove(self, key: FlowKey):
        with self._lock:
            self._flows.pop(key, None)

    def mark_classified(self, key: FlowKey):
        with self._lock:
            if key in self._flows:
                self._flows[key].classified = True

    def get(self, key: FlowKey) -> Optional[Flow]:
        with self._lock:
            return self._flows.get(key)


# ─── Blocklist ────────────────────────────────────────────────────────────────
class Blocklist:
    def __init__(self):
        self._blocked: set = set()
        self._lock = threading.Lock()

    def block(self, ip: str):
        with self._lock:
            if ip in self._blocked:
                return
            self._blocked.add(ip)
        if BLOCK_VERDICT:
            try:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True)
                log.warning(f"[BLOCK] All traffic from {ip} dropped via iptables")
            except subprocess.CalledProcessError as e:
                log.error(f"iptables block failed for {ip}: {e.stderr.decode()}")
        else:
            log.warning(f"[IDS-ONLY] Attack detected from {ip} (blocking disabled)")

    def unblock(self, ip: str):
        with self._lock:
            if ip not in self._blocked:
                return
            self._blocked.discard(ip)
        if BLOCK_VERDICT:
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True)
                log.info(f"[UNBLOCK] Removed iptables rule for {ip}")
            except subprocess.CalledProcessError:
                pass

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked


# ─── Main Firewall ────────────────────────────────────────────────────────────
class MQTTFirewall:
    def __init__(self):
        log.info(f"Loading LightGBM model: {MODEL_PATH}")
        self.model = lgb.Booster(model_file=MODEL_PATH)

        model_feats = self.model.feature_name()
        log.info(f"Model expects {self.model.num_feature()} features: {model_feats}")

        # Sanity-check feature names against CIC-IoMT 2024 list
        if model_feats != FEATURE_NAMES:
            log.warning("Model feature names differ from FEATURE_NAMES list — "
                        "verify column order matches your training data!")
            log.warning(f"Expected : {FEATURE_NAMES}")
            log.warning(f"Got      : {model_feats}")

        # Optional scaler
        self.scaler = None
        if SCALER_PATH:
            if os.path.exists(SCALER_PATH):
                import joblib
                self.scaler = joblib.load(SCALER_PATH)
                log.info(f"Scaler loaded from {SCALER_PATH}")
            else:
                log.warning(f"SCALER_PATH set but not found: {SCALER_PATH}")

        self.flow_table = FlowTable()
        self.blocklist  = Blocklist()
        self._stop      = threading.Event()

        self._reaper = threading.Thread(
            target=self._flow_reaper, daemon=True, name="flow-reaper")
        self._reaper.start()
        log.info("MQTTFirewall initialised and ready.")

    # ── Packet parsing ────────────────────────────────────────────────────────
    def _parse(self, raw: bytes):
        """
        Parse raw IP packet (no Ethernet header — NFQUEUE delivers raw IP).
        Returns (src_ip, dst_ip, sport, dport, proto,
                 payload_len, tcp_flags, ip_hdr_len, tcp_hdr_len, ip_ver)
        or None on failure / non-TCP packet.
        """
        ip_ver = 4
        try:
            ip = dpkt.ip.IP(raw)
            ip_hdr_len = ip.hl * 4
        except Exception:
            try:
                ip = dpkt.ip6.IP6(raw)
                ip_hdr_len = 40          # IPv6 fixed header
                ip_ver = 6
            except Exception:
                return None

        if not isinstance(ip.data, dpkt.tcp.TCP):
            return None  # MQTT uses TCP only

        tcp         = ip.data
        tcp_hdr_len = tcp.off * 4
        payload_len = len(tcp.data)

        try:
            src = dpkt.utils.inet_to_str(ip.src)
            dst = dpkt.utils.inet_to_str(ip.dst)
        except Exception:
            return None

        return (src, dst, tcp.sport, tcp.dport,
                ip.p, payload_len, tcp.flags,
                ip_hdr_len, tcp_hdr_len, ip_ver)

    # ── Inference ─────────────────────────────────────────────────────────────
    def _classify(self, key: FlowKey, flow: Flow):
        features = flow.extract_features()  # shape (1, 45)

        if self.scaler is not None:
            features = self.scaler.transform(features)

        proba = self.model.predict(features)
        # Binary: shape (1,) → raw score or probability
        # Multiclass: shape (1, n_classes) → index 1 = attack probability
        if proba.ndim == 2:
            attack_prob = float(proba[0][1])
        else:
            attack_prob = float(proba[0])

        label    = "ATTACK" if attack_prob > ATTACK_THRESHOLD else "benign"
        duration = flow.last_ts - flow.start_ts
        n_pkts   = flow.fwd_pkts + flow.bwd_pkts

        log.info(
            f"[FLOW] {flow.src_ip}:{flow.src_port} → "
            f"{flow.dst_ip}:{flow.dst_port}  "
            f"pkts={n_pkts}  dur={duration:.3f}s  "
            f"proto={flow.proto}  → {label}  (p={attack_prob:.4f})"
        )

        if label == "ATTACK":
            self.blocklist.block(flow.src_ip)

        self.flow_table.mark_classified(key)
        self.flow_table.remove(key)

    # ── Reaper thread ─────────────────────────────────────────────────────────
    def _flow_reaper(self):
        while not self._stop.is_set():
            for key, flow in self.flow_table.get_expired(FLOW_TIMEOUT_S):
                try:
                    self._classify(key, flow)
                except Exception as exc:
                    log.error(f"Reaper classify error: {exc}", exc_info=True)
                    self.flow_table.remove(key)
            self._stop.wait(REAPER_INTERVAL_S)

    # ── NFQUEUE callback ──────────────────────────────────────────────────────
    def handle_packet(self, pkt):
        raw = bytes(pkt.get_payload())
        ts  = time.time()

        parsed = self._parse(raw)
        if parsed is None:
            pkt.accept()
            return

        (src_ip, dst_ip, sport, dport, proto,
         payload_len, flags, ip_hdr_len, tcp_hdr_len, ip_ver) = parsed

        # Drop immediately if source already blocked
        if self.blocklist.is_blocked(src_ip):
            pkt.drop()
            return

        key, flow = self.flow_table.update(
            src_ip, dst_ip, sport, dport, proto,
            payload_len, flags, ts,
            ip_hdr_len, tcp_hdr_len, ip_ver=ip_ver,
        )

        # Always accept packet (async classification — no added latency)
        pkt.accept()

        # FIN or RST = flow ended → classify immediately if enough packets
        if (flags & 0x01) or (flags & 0x04):
            n = flow.fwd_pkts + flow.bwd_pkts
            if not flow.classified and n >= MIN_PKTS_CLASSIFY:
                try:
                    self._classify(key, flow)
                except Exception as exc:
                    log.error(f"FIN/RST classify error: {exc}", exc_info=True)
                    self.flow_table.remove(key)
            elif not flow.classified:
                self.flow_table.remove(key)  # too short, discard silently

    # ── Entry point ───────────────────────────────────────────────────────────
    def run(self):
        nfq = netfilterqueue.NetfilterQueue()
        nfq.bind(QUEUE_NUM, self.handle_packet)
        log.info(
            f"Bound to NFQUEUE {QUEUE_NUM}. "
            f"Intercepting MQTT (port 1883). Ctrl-C to stop."
        )
        try:
            nfq.run()
        except KeyboardInterrupt:
            log.info("Shutdown requested by user.")
        finally:
            self._stop.set()
            nfq.unbind()
            log.info("NFQUEUE unbound. Firewall stopped.")


# ─── Entry ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: must run as root  →  sudo python3 mqtt_firewall.py")
        raise SystemExit(1)
    fw = MQTTFirewall()
    fw.run()
