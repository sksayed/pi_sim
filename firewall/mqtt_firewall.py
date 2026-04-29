#!/usr/bin/env python3
"""
mqtt_firewall.py — Inline LightGBM firewall for MQTT (port 1883)
Dataset: CIC IoMT 2024 | Model: LightGBM (model.txt)
Features: 45 CIC IoMT 2024 columns (exact alignment)
Platform: Raspberry Pi 4, Raspbian, Python 3.9+
"""

import os
import math
import time
import threading
import subprocess
import logging
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Tuple

import numpy as np
import lightgbm as lgb
import dpkt
import netfilterqueue

# ─── Configuration ────────────────────────────────────────────────────────────
def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


QUEUE_NUM = int(os.getenv("FW_QUEUE_NUM", "0"))
MODEL_PATH = os.getenv("FW_MODEL_PATH", "lightgbm_model.txt")
_scaler_raw = os.getenv("FW_SCALER_PATH", "")
SCALER_PATH = _scaler_raw if _scaler_raw else None   # set empty to disable scaler
FLOW_TIMEOUT_S = float(os.getenv("FW_FLOW_TIMEOUT_S", "10"))
MIN_PKTS_CLASSIFY = int(os.getenv("FW_MIN_PKTS_CLASSIFY", "3"))
# Classify a persistent flow every N packets even if it never closes/idles.
# Needed for long-lived MQTT connections that never send FIN/RST.
CLASSIFY_EVERY_N_PKTS = int(os.getenv("FW_CLASSIFY_EVERY_N_PKTS", "20"))
ATTACK_THRESHOLD = float(os.getenv("FW_ATTACK_THRESHOLD", "0.5"))
# Comma-separated ordered class names matching the model's training label encoding.
# Index 0 is treated as the benign class; all other indices are attack classes.
# Example: "Benign,DoS,Reconnaissance,MQTT_Flood,Mirai"
# Leave empty to fall back to "class_0", "class_1", ... labels.
_CLASS_NAMES_RAW = os.getenv("FW_CLASS_NAMES", "")
CLASS_NAMES: list[str] = (
    [c.strip() for c in _CLASS_NAMES_RAW.split(",") if c.strip()]
    if _CLASS_NAMES_RAW else []
)
BENIGN_LABEL = os.getenv("FW_BENIGN_LABEL", "Benign")  # exact name of the benign class
BLOCK_VERDICT = _env_bool("FW_BLOCK_VERDICT", True)   # False = IDS mode (log only)
BLOCK_TTL_S = float(os.getenv("FW_BLOCK_TTL_S", "0")) # <=0 means no auto-unblock
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_DIR = REPO_ROOT / "Firewall_logs"
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "mqtt_firewall.log"
LOG_FILE = os.getenv("FW_LOG_FILE", str(DEFAULT_LOG_FILE))
VERBOSE_PACKET_LOGS = _env_bool("FW_VERBOSE_PACKET_LOGS", True)
JSON_EVENT_LOGS = _env_bool("FW_JSON_EVENT_LOGS", True)
_jsonl_raw = os.getenv("FW_JSONL_FILE", "")
DEFAULT_JSONL_FILE = DEFAULT_LOG_DIR / "mqtt_firewall.jsonl"
JSONL_FILE = _jsonl_raw if _jsonl_raw else str(DEFAULT_JSONL_FILE)

# Ensure log directory exists for file-based logging.
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# Separate logger for machine-readable JSON events (one JSON object per line).
# Writes only to JSONL_FILE — never appears in the human log.
_jsonl_logger = logging.getLogger("fw.jsonl")
_jsonl_logger.propagate = False   # do not bubble up to root handler
_jsonl_logger.setLevel(logging.INFO)
if JSON_EVENT_LOGS:
    _jh = logging.FileHandler(JSONL_FILE)
    _jh.setFormatter(logging.Formatter("%(message)s"))  # raw JSON, no prefix
    _jsonl_logger.addHandler(_jh)


def log_event(event: str, **data) -> None:
    """Write a structured JSON event to the .jsonl sidecar file only."""
    if not JSON_EVENT_LOGS:
        return
    payload = {"event": event, "ts": time.time(), **data}
    _jsonl_logger.info(json.dumps(payload, separators=(",", ":"), sort_keys=True))

# ─── Flow Record ──────────────────────────────────────────────────────────────
@dataclass
class Flow:
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    proto:    int
    start_ts: float = field(default_factory=time.time)
    last_ts:  float = field(default_factory=time.time)

    # Packet counters
    fwd_pkts:  int = 0
    bwd_pkts:  int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # Packet length lists
    fwd_pkt_lens: list = field(default_factory=list)
    bwd_pkt_lens: list = field(default_factory=list)

    # Inter-arrival times
    fwd_iats: list = field(default_factory=list)
    bwd_iats: list = field(default_factory=list)
    _last_fwd_ts: float = 0.0
    _last_bwd_ts: float = 0.0

    # TCP flag counts
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    ece_count: int = 0
    cwr_count: int = 0

    # Header lengths
    hdr_lens: list = field(default_factory=list)

    classified: bool = False

    def is_forward(self, src_ip: str, src_port: int) -> bool:
        return src_ip == self.src_ip and src_port == self.src_port

    def add_packet(self, pkt_len: int, tcp_flags: int, ts: float,
                   is_fwd: bool, hdr_len: int = 0) -> None:
        self.last_ts = ts

        # TCP flags — full 8-bit field
        if tcp_flags & 0x01: self.fin_count += 1
        if tcp_flags & 0x02: self.syn_count += 1
        if tcp_flags & 0x04: self.rst_count += 1
        if tcp_flags & 0x08: self.psh_count += 1
        if tcp_flags & 0x10: self.ack_count += 1
        if tcp_flags & 0x40: self.ece_count += 1
        if tcp_flags & 0x80: self.cwr_count += 1

        self.hdr_lens.append(hdr_len)

        if is_fwd:
            if self._last_fwd_ts > 0:
                self.fwd_iats.append(ts - self._last_fwd_ts)
            self._last_fwd_ts = ts
            self.fwd_pkts  += 1
            self.fwd_bytes += pkt_len
            self.fwd_pkt_lens.append(pkt_len)
        else:
            if self._last_bwd_ts > 0:
                self.bwd_iats.append(ts - self._last_bwd_ts)
            self._last_bwd_ts = ts
            self.bwd_pkts  += 1
            self.bwd_bytes += pkt_len
            self.bwd_pkt_lens.append(pkt_len)

    def extract_features(self) -> np.ndarray:
        """
        Extract exactly 45 features matching CIC IoMT 2024 column order:

        [00] Header_Length     [01] Protocol Type     [02] Duration
        [03] Rate              [04] Srate              [05] Drate
        [06] fin_flag_number   [07] syn_flag_number    [08] rst_flag_number
        [09] psh_flag_number   [10] ack_flag_number    [11] ece_flag_number
        [12] cwr_flag_number   [13] ack_count          [14] syn_count
        [15] fin_count         [16] rst_count          [17] HTTP
        [18] HTTPS             [19] DNS                [20] Telnet
        [21] SMTP              [22] SSH                [23] IRC
        [24] TCP               [25] UDP                [26] DHCP
        [27] ARP               [28] ICMP               [29] IGMP
        [30] IPv               [31] LLC                [32] Tot sum
        [33] Min               [34] Max                [35] AVG
        [36] Std               [37] Tot size           [38] IAT
        [39] Number            [40] Magnitue           [41] Radius
        [42] Covariance        [43] Variance           [44] Weight
        """
        duration   = max(self.last_ts - self.start_ts, 1e-9)
        total_pkts = self.fwd_pkts + self.bwd_pkts
        all_lens   = self.fwd_pkt_lens + self.bwd_pkt_lens
        all_iats   = self.fwd_iats + self.bwd_iats

        # ── Helper functions ──────────────────────────────────────────────────
        def safe_mean(lst): return float(np.mean(lst)) if lst        else 0.0
        def safe_std(lst):  return float(np.std(lst))  if len(lst)>1 else 0.0
        def safe_var(lst):  return float(np.var(lst))  if len(lst)>1 else 0.0
        def safe_min(lst):  return float(min(lst))     if lst        else 0.0
        def safe_max(lst):  return float(max(lst))     if lst        else 0.0

        # ── Flow-level packet size stats ──────────────────────────────────────
        avg = safe_mean(all_lens)
        std = safe_std(all_lens)
        mn  = safe_min(all_lens)
        mx  = safe_max(all_lens)
        hdr = safe_mean(self.hdr_lens)

        # ── Directional packet size stats ─────────────────────────────────────
        mean_fwd = safe_mean(self.fwd_pkt_lens)
        mean_bwd = safe_mean(self.bwd_pkt_lens)
        var_fwd  = safe_var(self.fwd_pkt_lens)
        var_bwd  = safe_var(self.bwd_pkt_lens)

        # ── CIC IoMT 2024 derived statistical features ────────────────────────

        # Magnitude: Root mean square of directional means
        magnitude = math.sqrt((mean_fwd**2 + mean_bwd**2) / 2)

        # Radius: Root mean square of directional variances
        radius = math.sqrt((var_fwd**2 + var_bwd**2) / 2)

        # Covariance: statistical covariance between fwd and bwd packet lengths
        # np.cov returns a 2x2 matrix — [0,1] is the off-diagonal cross-covariance
        min_len = min(len(self.fwd_pkt_lens), len(self.bwd_pkt_lens))
        if min_len > 1:
            cov_matrix = np.cov(
                self.fwd_pkt_lens[:min_len],
                self.bwd_pkt_lens[:min_len]
            )
            covariance = float(cov_matrix[0, 1])
        else:
            covariance = 0.0

        # Variance: ratio of fwd variance to bwd variance
        # Zero bwd variance (e.g. SYN flood with no responses) → near-zero weight
        variance = var_fwd / (var_bwd + 1e-6)

        # Weight: product of directional packet counts
        # Unidirectional flows (attacks) → 0; bidirectional (benign) → large
        weight = float(self.fwd_pkts * self.bwd_pkts)

        # ── Port shortcuts ─────────────────────────────────────────────────────
        sp, dp = self.src_port, self.dst_port

        # ── Feature vector (45 elements, CIC IoMT 2024 column order) ──────────
        feats = [
            # [00-01] Header & protocol
            hdr,                               # Header_Length (mean across flow)
            float(self.proto),                 # Protocol Type (6=TCP, 17=UDP)

            # [02-05] Timing & rates
            duration,                          # Duration (seconds)
            total_pkts / duration,             # Rate     (pkts/sec, all directions)
            self.fwd_pkts / duration,          # Srate    (pkts/sec, src→dst)
            self.bwd_pkts / duration,          # Drate    (pkts/sec, dst→src)

            # [06-12] TCP flag counts (per-flow cumulative)
            float(self.fin_count),             # fin_flag_number
            float(self.syn_count),             # syn_flag_number
            float(self.rst_count),             # rst_flag_number
            float(self.psh_count),             # psh_flag_number
            float(self.ack_count),             # ack_flag_number
            float(self.ece_count),             # ece_flag_number
            float(self.cwr_count),             # cwr_flag_number

            # [13-16] Redundant flag columns (CIC dataset has both sets)
            float(self.ack_count),             # ack_count
            float(self.syn_count),             # syn_count
            float(self.fin_count),             # fin_count
            float(self.rst_count),             # rst_count

            # [17-31] Application/protocol binary indicators (1 or 0)
            float(sp == 80   or dp == 80),     # HTTP
            float(sp == 443  or dp == 443),    # HTTPS
            float(sp == 53   or dp == 53),     # DNS
            float(sp == 23   or dp == 23),     # Telnet
            float(sp == 25   or dp == 25),     # SMTP
            float(sp == 22   or dp == 22),     # SSH
            float(sp == 6667 or dp == 6667),   # IRC
            float(self.proto == 6),            # TCP
            float(self.proto == 17),           # UDP
            float(dp in (67, 68)),             # DHCP
            0.0,                               # ARP  — not in raw IP, always 0
            float(self.proto == 1),            # ICMP
            float(self.proto == 2),            # IGMP
            1.0,                               # IPv  — always IPv4 here
            0.0,                               # LLC  — not in raw IP, always 0

            # [32-37] Packet size statistics (all packets combined)
            float(sum(all_lens)),              # Tot sum  (total bytes)
            mn,                                # Min      (smallest packet)
            mx,                                # Max      (largest packet)
            avg,                               # AVG      (mean packet size)
            std,                               # Std      (std dev packet size)
            float(self.fwd_bytes + self.bwd_bytes),  # Tot size

            # [38-39] Inter-arrival time & count
            safe_mean(all_iats),               # IAT    (mean inter-arrival time)
            float(total_pkts),                 # Number (total packet count)

            # [40-44] CIC-specific derived statistical features
            magnitude,                         # Magnitue   (RMS of directional means)
            radius,                            # Radius     (RMS of directional variances)
            covariance,                        # Covariance (fwd↔bwd cross-covariance)
            variance,                          # Variance   (var_fwd / var_bwd ratio)
            weight,                            # Weight     (fwd_pkts × bwd_pkts)
        ]

        assert len(feats) == 45, f"Feature count mismatch: {len(feats)}"
        return np.array(feats, dtype=np.float32).reshape(1, -1)


# ─── Flow Table ───────────────────────────────────────────────────────────────
FlowKey = Tuple[str, str, int, int, int]  # (src_ip, dst_ip, src_port, dst_port, proto)

class FlowTable:
    def __init__(self):
        self._flows: Dict[FlowKey, Flow] = {}
        self._lock  = threading.Lock()

    def _resolve_key(self, src_ip, dst_ip, src_port, dst_port,
                     proto) -> Tuple[FlowKey, bool]:
        fwd = (src_ip, dst_ip, src_port, dst_port, proto)
        bwd = (dst_ip, src_ip, dst_port, src_port, proto)
        with self._lock:
            if fwd in self._flows: return fwd, True
            if bwd in self._flows: return bwd, False
        return fwd, True   # new flow — treat as forward

    def update(self, src_ip, dst_ip, src_port, dst_port, proto,
               pkt_len, tcp_flags, ts, hdr_len=0) -> Tuple[FlowKey, Flow]:
        key, is_fwd = self._resolve_key(src_ip, dst_ip, src_port,
                                        dst_port, proto)
        with self._lock:
            if key not in self._flows:
                self._flows[key] = Flow(
                    src_ip=key[0], dst_ip=key[1],
                    src_port=key[2], dst_port=key[3],
                    proto=proto,
                    start_ts=ts, last_ts=ts,
                    _last_fwd_ts=0.0, _last_bwd_ts=0.0
                )
            flow = self._flows[key]
            flow.add_packet(pkt_len, tcp_flags, ts, is_fwd, hdr_len)
        return key, flow

    def get_expired(self, timeout: float):
        now = time.time()
        result = []
        with self._lock:
            for key, flow in list(self._flows.items()):
                idle = (now - flow.last_ts) > timeout
                enough_pkts = (flow.fwd_pkts + flow.bwd_pkts) >= MIN_PKTS_CLASSIFY
                if not flow.classified and idle and enough_pkts:
                    result.append((key, flow))
        return result

    def remove(self, key: FlowKey):
        with self._lock:
            self._flows.pop(key, None)

    def mark_classified(self, key: FlowKey):
        with self._lock:
            if key in self._flows:
                self._flows[key].classified = True

    def get_flow(self, key: FlowKey):
        with self._lock:
            return self._flows.get(key)


# ─── Blocklist ────────────────────────────────────────────────────────────────
class Blocklist:
    def __init__(self):
        self._ips: set[str] = set()
        self._blocked_at: Dict[str, float] = {}
        self._lock = threading.Lock()

    def block(self, ip: str):
        with self._lock:
            if ip not in self._ips:
                self._ips.add(ip)
                self._blocked_at[ip] = time.time()
                if BLOCK_VERDICT:
                    subprocess.run(
                        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                        check=False
                    )
                log.warning(f"🚫 BLOCKED {ip}")
                log_event("block_applied", ip=ip, block_verdict=BLOCK_VERDICT, block_ttl_s=BLOCK_TTL_S)

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ips

    def unblock(self, ip: str):
        with self._lock:
            if ip in self._ips:
                self._ips.discard(ip)
                self._blocked_at.pop(ip, None)
                if BLOCK_VERDICT:
                    subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                        check=False
                    )
                log.info(f"✅ UNBLOCKED {ip}")
                log_event("block_removed", ip=ip, block_verdict=BLOCK_VERDICT)

    def list_blocked(self):
        with self._lock:
            return list(self._ips)

    def unblock_expired(self, ttl_s: float) -> int:
        if ttl_s <= 0:
            return 0
        now = time.time()
        expired: list[str] = []
        with self._lock:
            for ip in list(self._ips):
                blocked_at = self._blocked_at.get(ip, now)
                if now - blocked_at >= ttl_s:
                    expired.append(ip)
        for ip in expired:
            self.unblock(ip)
            log_event("block_ttl_expired", ip=ip, ttl_s=ttl_s)
        return len(expired)


# ─── Main Firewall ─────────────────────────────────────────────────────────────
class MQTTFirewall:
    def __init__(self):
        log.info(f"Loading model: {MODEL_PATH}")
        self.model = lgb.Booster(model_file=MODEL_PATH)
        log_event(
            "firewall_startup",
            model_path=MODEL_PATH,
            queue_num=QUEUE_NUM,
            flow_timeout_s=FLOW_TIMEOUT_S,
            min_pkts_classify=MIN_PKTS_CLASSIFY,
            attack_threshold=ATTACK_THRESHOLD,
            block_verdict=BLOCK_VERDICT,
            block_ttl_s=BLOCK_TTL_S,
            scaler_path=SCALER_PATH or "",
        )

        # Verify feature count
        n = self.model.num_feature()
        log.info(f"Model expects {n} features: {self.model.feature_name()}")
        assert n == 45, (
            f"Feature mismatch! Model expects {n} features but extract_features() "
            f"produces 45. Update extract_features() to match model.feature_name()."
        )

        # Resolve class names for multiclass output.
        # Priority: (1) stored in model metadata, (2) FW_CLASS_NAMES env var,
        # (3) generic class_0 / class_1 / ... labels.
        #
        # NOTE: Some LightGBM versions do not expose Booster.num_class(), so derive
        # the class count via dump_model()/num_model_per_iteration() fallbacks.
        model_info = self.model.dump_model()
        n_classes = int(model_info.get("num_class", 1))
        if n_classes <= 1:
            n_classes = int(getattr(self.model, "num_model_per_iteration", lambda: 1)())
        if n_classes <= 0:
            n_classes = 1
        self._n_classes = n_classes

        # Some LightGBM builds do not expose Booster.attr().
        # Try metadata attribute first, then dump_model() fallback.
        stored = None
        attr_getter = getattr(self.model, "attr", None)
        if callable(attr_getter):
            stored = attr_getter("class_names")   # returns None if not saved
        if not stored:
            raw_names = model_info.get("class_names")
            if isinstance(raw_names, list):
                stored = ",".join(str(c) for c in raw_names)
            elif isinstance(raw_names, str):
                stored = raw_names
        if stored:
            self._class_names = [c.strip() for c in stored.split(",")]
            log.info(f"Class names loaded from model metadata: {self._class_names}")
            if len(self._class_names) != n_classes:
                log.warning(
                    f"model attr 'class_names' has {len(self._class_names)} entries "
                    f"but model has {n_classes} classes — falling back to generic labels."
                )
                self._class_names = [f"class_{i}" for i in range(n_classes)]
        elif CLASS_NAMES:
            if len(CLASS_NAMES) != n_classes:
                log.warning(
                    f"FW_CLASS_NAMES has {len(CLASS_NAMES)} entries but model has "
                    f"{n_classes} classes — falling back to generic labels."
                )
                self._class_names = [f"class_{i}" for i in range(n_classes)]
            else:
                self._class_names = CLASS_NAMES
                log.info(f"Class names loaded from FW_CLASS_NAMES: {self._class_names}")
        else:
            self._class_names = [f"class_{i}" for i in range(n_classes)]
            log.warning(
                f"No class names found in model metadata or FW_CLASS_NAMES. "
                f"Using generic labels: {self._class_names}. "
                f"Run firewall/embed_class_names.py to bake class names into the model."
            )

        # Index of the benign class (used to decide ATTACK vs benign)
        if BENIGN_LABEL in self._class_names:
            self._benign_idx = self._class_names.index(BENIGN_LABEL)
        else:
            self._benign_idx = 0   # assume class 0 is benign if label not found
            log.warning(
                f"Benign label '{BENIGN_LABEL}' not found in class names — "
                f"assuming class_0 ('{self._class_names[0]}') is benign."
            )

        log.info(
            f"Classifier: {n_classes} class(es) | "
            f"benign='{self._class_names[self._benign_idx]}' (idx={self._benign_idx}) | "
            f"classes={self._class_names}"
        )

        # Optional scaler
        self.scaler = None
        if SCALER_PATH and os.path.exists(SCALER_PATH):
            import joblib
            self.scaler = joblib.load(SCALER_PATH)
            log.info(f"Scaler loaded: {SCALER_PATH}")

        self.flow_table = FlowTable()
        self.blocklist  = Blocklist()
        self._stop      = threading.Event()

        # Background reaper thread
        self._reaper = threading.Thread(target=self._flow_reaper, daemon=True)
        self._reaper.start()
        log.info("MQTTFirewall ready.")

    # ── Packet parser ──────────────────────────────────────────────────────────
    def _parse(self, raw: bytes):
        """
        Parse raw IP bytes (NFQUEUE delivers raw IP, no Ethernet header).
        Returns (src_ip, dst_ip, sport, dport, proto, payload_len, flags, hdr_len)
        or None on failure.
        """
        try:
            ip = dpkt.ip.IP(raw)
        except Exception:
            return None

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp     = ip.data
            src_ip  = dpkt.utils.inet_to_str(ip.src)
            dst_ip  = dpkt.utils.inet_to_str(ip.dst)
            hdr_len = (ip.hl * 4) + (tcp.off * 4)   # IP header + TCP header bytes
            return (src_ip, dst_ip, tcp.sport, tcp.dport,
                    ip.p, len(tcp.data), tcp.flags, hdr_len)

        # UDP (e.g. udp_flood_client) — requires iptables NFQUEUE on UDP ports; flags unused (0).
        if isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            src_ip  = dpkt.utils.inet_to_str(ip.src)
            dst_ip  = dpkt.utils.inet_to_str(ip.dst)
            hdr_len = (ip.hl * 4) + 8   # IP + UDP header
            return (src_ip, dst_ip, udp.sport, udp.dport,
                    ip.p, len(udp.data), 0, hdr_len)

        return None

    # ── Classifier ────────────────────────────────────────────────────────────
    def _classify(self, key: FlowKey, flow: Flow):
        feats = flow.extract_features()
        pkts  = flow.fwd_pkts + flow.bwd_pkts
        dur   = flow.last_ts - flow.start_ts

        # Full 45-feature vector goes to the .jsonl sidecar only.
        log_event(
            "pre_infer",
            flow_src_ip=flow.src_ip,
            flow_src_port=flow.src_port,
            flow_dst_ip=flow.dst_ip,
            flow_dst_port=flow.dst_port,
            pkts=pkts,
            features=feats.flatten().tolist(),
        )

        if self.scaler:
            feats = self.scaler.transform(feats)

        proba = self.model.predict(feats)  # shape (1, n_classes) for multiclass, (1,) for binary

        if proba.ndim == 2 and self._n_classes > 2:
            # ── Multiclass ────────────────────────────────────────────────────
            # proba[0] is a probability vector over all classes.
            # The predicted class is whichever has the highest probability.
            class_probs = proba[0]                          # shape: (n_classes,)
            pred_idx    = int(np.argmax(class_probs))       # winning class index
            pred_label  = self._class_names[pred_idx]       # e.g. "DoS", "Benign"
            pred_prob   = float(class_probs[pred_idx])      # confidence in that class
            benign_prob = float(class_probs[self._benign_idx])

            # It is an attack if the predicted class is not the benign class
            # AND the model is confident enough (benign_prob < 1 - threshold).
            is_attack = (pred_idx != self._benign_idx) and (benign_prob < 1.0 - ATTACK_THRESHOLD)
            attack_type = pred_label if is_attack else "benign"
            attack_prob = 1.0 - benign_prob   # "how non-benign is this flow"

            all_probs = {self._class_names[i]: round(float(class_probs[i]), 4)
                         for i in range(self._n_classes)}
        else:
            # ── Binary (or binary-treated multiclass with 2 classes) ──────────
            attack_prob = float(proba[0][1]) if proba.ndim == 2 else float(proba[0])
            is_attack   = attack_prob > ATTACK_THRESHOLD
            pred_label  = self._class_names[1] if (is_attack and self._n_classes >= 2) else self._class_names[0]
            attack_type = pred_label if is_attack else "benign"
            all_probs   = {self._class_names[0]: round(1 - attack_prob, 4),
                           self._class_names[1] if self._n_classes >= 2 else "attack": round(attack_prob, 4)}

        label = "ATTACK" if is_attack else "benign"

        # Human-readable single-line verdict — includes specific attack type for multiclass.
        log.info(
            f"[VERDICT] {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} | "
            f"verdict={label}  type={attack_type}  confidence={attack_prob:.4f}  "
            f"pkts={pkts}  bytes={flow.fwd_bytes+flow.bwd_bytes}  dur={dur:.3f}s"
        )
        log_event(
            "verdict",
            verdict=label,
            attack_type=attack_type,
            attack_prob=attack_prob,
            threshold=ATTACK_THRESHOLD,
            class_probabilities=all_probs,
            flow_src_ip=flow.src_ip,
            flow_src_port=flow.src_port,
            flow_dst_ip=flow.dst_ip,
            flow_dst_port=flow.dst_port,
            flow_pkts=pkts,
            flow_bytes=flow.fwd_bytes + flow.bwd_bytes,
            flow_duration_s=dur,
        )

        if label == "ATTACK" and BLOCK_VERDICT:
            self.blocklist.block(flow.src_ip)

        self.flow_table.mark_classified(key)
        self.flow_table.remove(key)

    # ── Background reaper: classify idle/expired flows ────────────────────────
    def _flow_reaper(self):
        while not self._stop.is_set():
            expired_blocks = self.blocklist.unblock_expired(BLOCK_TTL_S)
            if expired_blocks:
                log.info(f"Auto-unblocked {expired_blocks} IP(s) due to BLOCK_TTL_S={BLOCK_TTL_S}")
            for key, flow in self.flow_table.get_expired(FLOW_TIMEOUT_S):
                try:
                    self._classify(key, flow)
                except Exception as e:
                    log.error(f"Classification error: {e}")
            time.sleep(1.0)

    # ── NFQUEUE callback ───────────────────────────────────────────────────────
    def handle_packet(self, pkt):
        raw = bytes(pkt.get_payload())
        ts  = time.time()

        parsed = self._parse(raw)
        if parsed is None:
            pkt.accept()
            return

        src_ip, dst_ip, sport, dport, proto, pkt_len, flags, hdr_len = parsed

        # Per-packet line: concise, readable. Skipped when VERBOSE_PACKET_LOGS=false.
        if VERBOSE_PACKET_LOGS:
            log.info(
                f"[PKT] {src_ip}:{sport} -> {dst_ip}:{dport}  "
                f"len={pkt_len}  flags=0x{flags:02x}"
            )
        # Full detail goes to .jsonl only.
        log_event(
            "packet_parsed",
            src_ip=src_ip,
            dst_ip=dst_ip,
            sport=sport,
            dport=dport,
            proto=proto,
            payload_len=pkt_len,
            flags=flags,
            hdr_len=hdr_len,
        )

        # In IPS mode: drop (or accept per config) packets from blocked IPs and skip analysis.
        # In IDS mode (BLOCK_VERDICT=False): never skip analysis — every packet is inspected.
        if BLOCK_VERDICT and self.blocklist.is_blocked(src_ip):
            pkt.accept()
            return

        # Update flow table
        key, flow = self.flow_table.update(
            src_ip, dst_ip, sport, dport, proto,
            pkt_len, flags, ts, hdr_len
        )

        # Accept all packets first (passive-classify model)
        # Prevents added latency on legitimate MQTT traffic
        pkt.accept()

        # Immediate classification on flow termination (FIN or RST)
        if (flags & 0x01) or (flags & 0x04):
            f = self.flow_table.get_flow(key)
            if f and not f.classified:
                total = f.fwd_pkts + f.bwd_pkts
                if total >= MIN_PKTS_CLASSIFY:
                    try:
                        self._classify(key, f)
                    except Exception as e:
                        log.error(f"FIN/RST classification error: {e}")

        # Periodic classification: classify every CLASSIFY_EVERY_N_PKTS packets
        # on persistent connections that never send FIN/RST (e.g. long-lived MQTT).
        # After classification the flow entry is removed so counters reset fresh.
        else:
            f = self.flow_table.get_flow(key)
            if f and not f.classified:
                total = f.fwd_pkts + f.bwd_pkts
                if total >= CLASSIFY_EVERY_N_PKTS:
                    try:
                        self._classify(key, f)
                    except Exception as e:
                        log.error(f"Periodic classification error: {e}")

    # ── Entry point ────────────────────────────────────────────────────────────
    def run(self):
        nfq = netfilterqueue.NetfilterQueue()
        nfq.bind(QUEUE_NUM, self.handle_packet)
        log.info(f"Bound to NFQUEUE {QUEUE_NUM}. Intercepting MQTT on port 1883...")
        try:
            nfq.run()
        except KeyboardInterrupt:
            log.info("Interrupted. Shutting down.")
        finally:
            self._stop.set()
            nfq.unbind()
            log.info(f"Blocked IPs at shutdown: {self.blocklist.list_blocked()}")


# ─── Entry ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: must run as root  →  sudo python3 mqtt_firewall.py")
        raise SystemExit(1)

    fw = MQTTFirewall()
    fw.run()
