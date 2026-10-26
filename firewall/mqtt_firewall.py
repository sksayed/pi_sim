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

import cic_features

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
# Ordered model inputs written by ml/train_lgbm.py; without it, all 45 CIC columns.
FEATURES_PATH = os.getenv(
    "FW_FEATURES_PATH", str(Path(__file__).resolve().parent / "feature_columns.json"))
FEATURE_COLUMNS: list[str] = (
    json.loads(Path(FEATURES_PATH).read_text()) if Path(FEATURES_PATH).exists()
    else list(cic_features.CIC_COLUMNS)
)
# Comma-separated client IPs that are classified and logged but never blocked.
ALLOW_IPS = {ip.strip() for ip in os.getenv("FW_ALLOW_IPS", "").split(",") if ip.strip()}
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

    # Per-packet series used by cic_features.compute
    frame_lens: list = field(default_factory=list)
    ttls: list = field(default_factory=list)
    flag_list: list = field(default_factory=list)
    times: list = field(default_factory=list)

    classified: bool = False
    # Wall time (time.time_ns) when this flow’s first packet was seen in NFQUEUE — on-host only.
    nfqueue_first_wall_ns: int = 0

    def is_forward(self, src_ip: str, src_port: int) -> bool:
        return src_ip == self.src_ip and src_port == self.src_port

    def add_packet(self, pkt_len: int, tcp_flags: int, ts: float,
                   is_fwd: bool, hdr_len: int = 0, ttl: int = 64) -> None:
        self.last_ts = ts
        self.frame_lens.append(pkt_len + hdr_len + cic_features.ETH_HEADER_BYTES)
        self.ttls.append(ttl)
        self.flag_list.append(tcp_flags)
        self.times.append(ts)

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
        """Feature vector in FEATURE_COLUMNS order (see cic_features.py)."""
        feats = cic_features.compute(
            self.proto, self.src_port, self.dst_port, self.frame_lens, self.ttls,
            self.flag_list, self.times, self.hdr_lens, self.fwd_pkts, self.bwd_pkts,
        )
        return np.array([feats[c] for c in FEATURE_COLUMNS], dtype=np.float32).reshape(1, -1)


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
               pkt_len, tcp_flags, ts, hdr_len=0, ttl=64) -> Tuple[FlowKey, Flow]:
        key, is_fwd = self._resolve_key(src_ip, dst_ip, src_port,
                                        dst_port, proto)
        with self._lock:
            if key not in self._flows:
                self._flows[key] = Flow(
                    src_ip=key[0], dst_ip=key[1],
                    src_port=key[2], dst_port=key[3],
                    proto=proto,
                    start_ts=ts, last_ts=ts,
                    _last_fwd_ts=0.0, _last_bwd_ts=0.0,
                    nfqueue_first_wall_ns=int(time.time_ns()),
                )
            flow = self._flows[key]
            flow.add_packet(pkt_len, tcp_flags, ts, is_fwd, hdr_len, ttl)
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

    def pop_idle_unclassifiable(self, timeout: float):
        """Remove and return idle flows that never reached MIN_PKTS_CLASSIFY."""
        now = time.time()
        result = []
        with self._lock:
            for key, flow in list(self._flows.items()):
                idle = (now - flow.last_ts) > timeout
                too_small = (flow.fwd_pkts + flow.bwd_pkts) < MIN_PKTS_CLASSIFY
                if not flow.classified and idle and too_small:
                    result.append(flow)
                    del self._flows[key]
        return result

    def snapshot(self):
        with self._lock:
            return [f for f in self._flows.values() if not f.classified]

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
BlockKey = Tuple[str, int, int, int]  # (src_ip, proto, src_port, dst_port)


class Blocklist:
    def __init__(self):
        self._flows: set[BlockKey] = set()
        self._blocked_at: Dict[BlockKey, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _proto_name(proto: int) -> str | None:
        if proto == 6:
            return "tcp"
        if proto == 17:
            return "udp"
        return None

    @classmethod
    def _iptables_args(cls, key: BlockKey, action: str) -> list[str] | None:
        ip, proto, sport, dport = key
        proto_name = cls._proto_name(proto)
        if proto_name is None:
            return None
        return [
            "iptables", action, "INPUT",
            "-s", ip,
            "-p", proto_name,
            "--sport", str(sport),
            "--dport", str(dport),
            "-m", "comment",
            "--comment", "pi_sim_ips_block",
            "-j", "DROP",
        ]

    @staticmethod
    def _fmt_key(key: BlockKey) -> str:
        ip, proto, sport, dport = key
        proto_name = Blocklist._proto_name(proto) or f"proto-{proto}"
        return f"{ip}:{sport}->{dport}/{proto_name}"

    def block(self, ip: str, proto: int, sport: int, dport: int):
        key = (ip, proto, sport, dport)
        with self._lock:
            if key not in self._flows:
                self._flows.add(key)
                self._blocked_at[key] = time.time()
                if BLOCK_VERDICT:
                    args = self._iptables_args(key, "-I")
                    if args:
                        subprocess.run(args, check=False)
                    else:
                        log.warning(f"Cannot port-block non-TCP/UDP flow: {self._fmt_key(key)}")
                log.warning(f"🚫 BLOCKED flow {self._fmt_key(key)}")
                log_event(
                    "block_applied",
                    ip=ip,
                    proto=proto,
                    src_port=sport,
                    dst_port=dport,
                    block_key=self._fmt_key(key),
                    block_verdict=BLOCK_VERDICT,
                    block_ttl_s=BLOCK_TTL_S,
                )

    def is_blocked(self, ip: str, proto: int, sport: int, dport: int) -> bool:
        key = (ip, proto, sport, dport)
        with self._lock:
            return key in self._flows

    def unblock(self, key: BlockKey):
        with self._lock:
            if key in self._flows:
                self._flows.discard(key)
                self._blocked_at.pop(key, None)
                if BLOCK_VERDICT:
                    args = self._iptables_args(key, "-D")
                    if args:
                        subprocess.run(args, check=False)
                ip, proto, sport, dport = key
                log.info(f"✅ UNBLOCKED flow {self._fmt_key(key)}")
                log_event(
                    "block_removed",
                    ip=ip,
                    proto=proto,
                    src_port=sport,
                    dst_port=dport,
                    block_key=self._fmt_key(key),
                    block_verdict=BLOCK_VERDICT,
                )

    def list_blocked(self):
        with self._lock:
            return [self._fmt_key(key) for key in self._flows]

    def unblock_expired(self, ttl_s: float) -> int:
        if ttl_s <= 0:
            return 0
        now = time.time()
        expired: list[BlockKey] = []
        with self._lock:
            for key in list(self._flows):
                blocked_at = self._blocked_at.get(key, now)
                if now - blocked_at >= ttl_s:
                    expired.append(key)
        for key in expired:
            self.unblock(key)
            ip, proto, sport, dport = key
            log_event(
                "block_ttl_expired",
                ip=ip,
                proto=proto,
                src_port=sport,
                dst_port=dport,
                block_key=self._fmt_key(key),
                ttl_s=ttl_s,
            )
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
            feature_columns=FEATURE_COLUMNS,
            classify_every_n_pkts=CLASSIFY_EVERY_N_PKTS,
            allow_ips=sorted(ALLOW_IPS),
        )

        # Verify feature count
        n = self.model.num_feature()
        log.info(f"Model expects {n} features: {self.model.feature_name()}")
        assert n == len(FEATURE_COLUMNS), (
            f"Feature mismatch! Model expects {n} features but {FEATURES_PATH} lists "
            f"{len(FEATURE_COLUMNS)}. Retrain with ml/train_lgbm.py or fix FW_FEATURES_PATH."
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

    @staticmethod
    def _client_side_block_tuple(flow: Flow) -> tuple[str, int, int, int]:
        """
        Return (client_ip, proto, client_src_port, server_dst_port).

        NFQUEUE sees both INPUT and OUTPUT, especially on localhost tests. A flow
        can therefore be first observed from either direction. For MQTT traffic,
        normalize blocks to the client-side ephemeral source port -> broker port
        so we avoid blocking all broker replies from source port 1883.
        """
        if flow.src_port == 1883 and flow.dst_port != 1883:
            return (flow.dst_ip, flow.proto, flow.dst_port, flow.src_port)
        return (flow.src_ip, flow.proto, flow.src_port, flow.dst_port)

    # ── Packet parser ──────────────────────────────────────────────────────────
    def _parse(self, raw: bytes):
        """
        Parse raw IP bytes (NFQUEUE delivers raw IP, no Ethernet header).
        Returns (src_ip, dst_ip, sport, dport, proto, payload_len, flags, hdr_len, ttl)
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
                    ip.p, len(tcp.data), tcp.flags, hdr_len, ip.ttl)

        # UDP (e.g. udp_flood_client) — requires iptables NFQUEUE on UDP ports; flags unused (0).
        if isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            src_ip  = dpkt.utils.inet_to_str(ip.src)
            dst_ip  = dpkt.utils.inet_to_str(ip.dst)
            hdr_len = (ip.hl * 4) + 8   # IP + UDP header
            return (src_ip, dst_ip, udp.sport, udp.dport,
                    ip.p, len(udp.data), 0, hdr_len, ip.ttl)

        return None

    # ── Classifier ────────────────────────────────────────────────────────────
    def _classify(self, key: FlowKey, flow: Flow, t_arrival_ns: int = 0):
        t_classify_start_ns = time.perf_counter_ns()
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

        t_inf_start = time.perf_counter_ns()
        proba = self.model.predict(feats)  # shape (1, n_classes) for multiclass, (1,) for binary
        t_inf_end = time.perf_counter_ns()
        t_inference_ns = t_inf_end - t_inf_start

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
        client_ip, _, client_port, _ = self._client_side_block_tuple(flow)
        allowlisted = client_ip in ALLOW_IPS

        t_verdict_ns    = time.perf_counter_ns()
        t_inspection_ns = (t_verdict_ns - t_arrival_ns) if t_arrival_ns > 0 else 0
        t_classify_ns   = t_verdict_ns - t_classify_start_ns

        # Human-readable single-line verdict — includes specific attack type for multiclass.
        log.info(
            f"[VERDICT] {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} | "
            f"verdict={label}  type={attack_type}  confidence={attack_prob:.4f}  "
            f"pkts={pkts}  bytes={flow.fwd_bytes+flow.bwd_bytes}  dur={dur:.3f}s  "
            f"infer={t_inference_ns/1e6:.3f}ms  classify={t_classify_ns/1e6:.3f}ms"
            + (f"  inspect={t_inspection_ns/1e6:.3f}ms" if t_inspection_ns > 0 else "")
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
            flow_proto=flow.proto,
            client_ip=client_ip,
            client_port=client_port,
            allowlisted=allowlisted,
            flow_pkts=pkts,
            flow_bytes=flow.fwd_bytes + flow.bwd_bytes,
            flow_duration_s=dur,
            t_inference_ns=t_inference_ns,
            t_classify_ns=t_classify_ns,
            t_inspection_ns=t_inspection_ns,
            nfqueue_first_wall_ns=flow.nfqueue_first_wall_ns,
            t_verdict_wall_ns=int(time.time_ns()),
        )

        if label == "ATTACK" and BLOCK_VERDICT:
            if allowlisted:
                log_event("block_skipped_allowlist", ip=client_ip, proto=flow.proto,
                          src_port=client_port, attack_type=attack_type)
            else:
                self.blocklist.block(*self._client_side_block_tuple(flow))

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
            for flow in self.flow_table.pop_idle_unclassifiable(FLOW_TIMEOUT_S):
                self._log_unclassified("flow_unclassified", flow)
            time.sleep(1.0)

    def _log_unclassified(self, event: str, flow: Flow):
        client_ip, _, client_port, _ = self._client_side_block_tuple(flow)
        log_event(
            event,
            client_ip=client_ip,
            client_port=client_port,
            flow_proto=flow.proto,
            flow_pkts=flow.fwd_pkts + flow.bwd_pkts,
            flow_duration_s=flow.last_ts - flow.start_ts,
            nfqueue_first_wall_ns=flow.nfqueue_first_wall_ns,
        )

    # ── NFQUEUE callback ───────────────────────────────────────────────────────
    def handle_packet(self, pkt):
        t_arrival_ns = time.perf_counter_ns()
        raw = bytes(pkt.get_payload())
        ts  = time.time()

        parsed = self._parse(raw)
        if parsed is None:
            pkt.accept()
            return

        src_ip, dst_ip, sport, dport, proto, pkt_len, flags, hdr_len, ttl = parsed

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
            ttl=ttl,
        )

        # In IPS mode: drop packets from blocked source-port flows and skip analysis.
        # In IDS mode (BLOCK_VERDICT=False): never skip analysis — every packet is inspected.
        if BLOCK_VERDICT and self.blocklist.is_blocked(src_ip, proto, sport, dport):
            pkt.drop()
            log_event("packet_dropped", src_ip=src_ip, sport=sport, dport=dport, proto=proto)
            return

        # Update flow table
        key, flow = self.flow_table.update(
            src_ip, dst_ip, sport, dport, proto,
            pkt_len, flags, ts, hdr_len, ttl
        )

        # Accept all packets first (passive-classify model): this packet continues
        # through the stack toward Mosquitto before LightGBM runs below. Inference
        # time can delay subsequent queued packets; per-MQTT-message latency is not
        # a single field — see verdict JSONL (t_inference_ns, …) vs gateway CSV.
        pkt.accept()

        # Immediate classification on flow termination (FIN or RST)
        if (flags & 0x01) or (flags & 0x04):
            f = self.flow_table.get_flow(key)
            if f and not f.classified:
                total = f.fwd_pkts + f.bwd_pkts
                if total >= MIN_PKTS_CLASSIFY:
                    try:
                        self._classify(key, f, t_arrival_ns=t_arrival_ns)
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
                        self._classify(key, f, t_arrival_ns=t_arrival_ns)
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
            for flow in self.flow_table.snapshot():
                self._log_unclassified("flow_open_at_shutdown", flow)
            log_event("firewall_shutdown")
            log.info(f"Blocked IPs at shutdown: {self.blocklist.list_blocked()}")


# ─── Entry ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: must run as root  →  sudo python3 mqtt_firewall.py")
        raise SystemExit(1)

    import signal

    def _sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _sigterm)
    fw = MQTTFirewall()
    fw.run()
