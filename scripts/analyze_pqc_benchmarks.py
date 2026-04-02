#!/usr/bin/env python3
"""
Read client (`benchmarks/client/pqc_metrics.csv`) and gateway
(`benchmarks/gateway/pqc_metrics_gateway.csv`) benchmark CSVs by default,
compute summary statistics, and print (or save) a report.

Uses pandas for loading, tolerant column defaults, groupby summaries, and
client–gateway joins on (device_id, session_id, seq).

Usage (from repo root):
  python scripts/analyze_pqc_benchmarks.py
  python scripts/analyze_pqc_benchmarks.py \\
      --client benchmarks/client/pqc_metrics.csv \\
      --gateway benchmarks/gateway/pqc_metrics_gateway.csv \\
      -o benchmarks/analysis_report.txt
"""

from __future__ import annotations

import argparse
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _to_bool(v: Any) -> bool | None:
    if v is True or v is False:
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "yes"):
            return True
        if s in ("false", "0", "no"):
            return False
    return None


def _series_bool(s: pd.Series) -> pd.Series:
    """Map column to boolean tri-state; unknown → False for counting 'is True'."""

    def one(x: Any) -> bool | None:
        if pd.isna(x):
            return None
        return _to_bool(x)

    return s.map(one)


def ns_to_ms(ns: float) -> float:
    return ns / 1_000_000.0


def _nist_band_vec(sb: pd.Series) -> pd.Series:
    s = pd.to_numeric(sb, errors="coerce").fillna(0).astype(np.int64)
    out = pd.Series(np.where(s <= 0, "—", np.where(s >= 256, "L5", np.where(s >= 192, "L3", "L1"))), index=sb.index)
    return out


@dataclass(frozen=True)
class ColStats:
    n: int
    mean: float
    median: float
    stdev: float
    min_v: float
    max_v: float
    p95: float

    def fmt_ms(self) -> str:
        if self.n == 0:
            return "—"
        return (
            f"n={self.n}  mean={ns_to_ms(self.mean):.3f} ms  "
            f"median={ns_to_ms(self.median):.3f} ms  stdev={ns_to_ms(self.stdev):.3f} ms  "
            f"min={ns_to_ms(self.min_v):.3f} ms  max={ns_to_ms(self.max_v):.3f} ms  "
            f"p95={ns_to_ms(self.p95):.3f} ms"
        )


def _quantile(sorted_xs: Sequence[float], q: float) -> float:
    if not sorted_xs:
        return float("nan")
    pos = (len(sorted_xs) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_xs) - 1)
    return sorted_xs[lo] + (pos - lo) * (sorted_xs[hi] - sorted_xs[lo])


def col_stats(values: Iterable[float]) -> ColStats:
    xs = [float(x) for x in values if not math.isnan(x) and x is not None]
    if not xs:
        return ColStats(0, float("nan"), float("nan"), float("nan"), float("nan"), float("nan"), float("nan"))
    s = sorted(xs)
    mean = float(sum(xs) / len(xs))
    med = float(pd.Series(xs).median())
    st = float(pd.Series(xs).std(ddof=1)) if len(xs) > 1 else 0.0
    return ColStats(
        n=len(xs),
        mean=mean,
        median=med,
        stdev=st,
        min_v=s[0],
        max_v=s[-1],
        p95=_quantile(s, 0.95),
    )


def _to_int_series(s: pd.Series, default: int = 0) -> pd.Series:
    return pd.to_numeric(s, errors="coerce").fillna(default).astype(np.int64)


def load_client_df(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path, encoding="utf-8")
    need = [
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
    ]
    for c in need:
        if c not in df.columns:
            df[c] = np.nan
    df["device_id"] = df["device_id"].fillna("").astype(str)
    df["session_id"] = df["session_id"].fillna("").astype(str)
    df["profile"] = df["profile"].fillna("").astype(str).str.strip()
    df["alg_kem"] = df["alg_kem"].fillna("").astype(str)
    df["alg_sig"] = df["alg_sig"].fillna("").astype(str)
    df["crypto_type"] = df["crypto_type"].fillna("").astype(str).str.strip()
    df["crypto_kind"] = df["crypto_kind"].fillna("PQC").astype(str).str.strip()
    for col in (
        "ts_unix_ns",
        "seq",
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
    ):
        df[col] = _to_int_series(df[col], 0)
    df["eta"] = pd.to_numeric(df["eta"], errors="coerce")
    return df


def load_gateway_df(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path, encoding="utf-8")
    need = [
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
    ]
    for c in need:
        if c not in df.columns:
            df[c] = np.nan
    df["device_id"] = df["device_id"].fillna("").astype(str)
    df["session_id"] = df["session_id"].fillna("").astype(str)
    df["profile"] = df["profile"].fillna("").astype(str).str.strip()
    df["alg_kem"] = df["alg_kem"].fillna("").astype(str)
    df["alg_sig"] = df["alg_sig"].fillna("").astype(str)
    df["crypto_type"] = df["crypto_type"].fillna("").astype(str).str.strip()
    df["crypto_kind"] = df["crypto_kind"].fillna("PQC").astype(str).str.strip()
    df["accepted"] = _series_bool(df["accepted"]).eq(True).fillna(False).astype(bool)
    for col in (
        "ts_unix_ns",
        "seq",
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
    ):
        df[col] = _to_int_series(df[col], 0)
    return df


def _add_bucket_column(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    ck = out["crypto_kind"].fillna("PQC").astype(str)
    pt = out["payload_target_bytes"]
    prof = out["profile"].replace("", "?")
    nb = _nist_band_vec(out["security_bits"])
    kem = out["alg_kem"].fillna("").astype(str)
    sig = out["alg_sig"].fillna("").astype(str)
    out["_bucket"] = (
        ck + " | profile=" + prof.astype(str) + " | nist≈" + nb + " | payload_target_B=" + pt.astype(str) + " | "
        + kem
        + " + "
        + sig
    )
    return out


def ts_range_label_df(df: pd.DataFrame) -> str:
    if df.empty or "ts_unix_ns" not in df.columns:
        return "(no timestamps)"
    ts = df.loc[df["ts_unix_ns"] > 0, "ts_unix_ns"]
    if ts.empty:
        return "(no timestamps)"
    lo = float(ts.min()) / 1e9
    hi = float(ts.max()) / 1e9
    try:
        a = datetime.fromtimestamp(lo, tz=timezone.utc).isoformat()
        b = datetime.fromtimestamp(hi, tz=timezone.utc).isoformat()
        return f"{a} … {b} (UTC)"
    except (ValueError, OSError):
        return f"{lo} … {hi}"


def load_rtt_samples(path: Path) -> list[int]:
    """Return RTT samples in ns from mqtt_rtt_baseline.py CSV (column rtt_ns)."""
    if not path.exists():
        return []
    df = pd.read_csv(path, encoding="utf-8")
    if "rtt_ns" not in df.columns:
        return []
    s = pd.to_numeric(df["rtt_ns"], errors="coerce").dropna()
    s = s[s > 0]
    return [int(x) for x in s.tolist()]


def build_report(
    client_path: Path,
    gateway_path: Path,
    rtt_path: Path | None = None,
) -> str:
    lines: list[str] = []
    c = load_client_df(client_path)
    g = load_gateway_df(gateway_path)

    lines.append("Benchmark analysis report (PQC and classical)")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Client CSV : {client_path.resolve()}")
    lines.append(f"Gateway CSV: {gateway_path.resolve()}")
    if rtt_path is not None:
        lines.append(f"MQTT RTT CSV (no crypto): {rtt_path.resolve()}")
    lines.append("")

    # --- Client ---
    lines.append("1) Client (edge) samples — build_message / publish path")
    lines.append("-" * 72)
    if c.empty:
        lines.append("  (no client rows; file missing or empty)")
    else:
        lines.append(f"  Rows: {len(c)}")
        lines.append(f"  Time span (ts_unix_ns): {ts_range_label_df(c)}")
        pqc = int(_series_bool(c["pqc_available"]).eq(True).fillna(False).sum())
        lines.append(f"  pqc_available=True: {pqc} / {len(c)}")
        lines.append("")

        c_b = _add_bucket_column(c)
        lines.append(
            "  Per bucket: crypto_kind, profile, NIST band (from security_bits), "
            "payload target, algorithm pair (times in ms):"
        )
        for key, grp in c_b.groupby("_bucket", sort=True):
            encap = col_stats(grp["t_encap_ns"].astype(float))
            sign = col_stats(grp["t_sign_ns"].astype(float))
            aes = col_stats(grp["t_aes_ns"].astype(float))
            ctot = col_stats((grp["t_encap_ns"] + grp["t_sign_ns"] + grp["t_aes_ns"]).astype(float))
            t_wall = col_stats(grp["t_total_ns"].astype(float))
            pay = col_stats(grp["payload_bytes"].astype(float))
            etas = grp["eta"].dropna()
            etas = etas[pd.to_numeric(etas, errors="coerce").notna()]
            eta_s = col_stats(pd.to_numeric(etas, errors="coerce").tolist())

            lines.append(f"  · {key}")
            lines.append(f"      encap:      {encap.fmt_ms()}")
            lines.append(f"      sign:       {sign.fmt_ms()}")
            lines.append(f"      aes_enc:    {aes.fmt_ms()}")
            lines.append(f"      crypto_sum: {ctot.fmt_ms()}  (encap+sign+aes)")
            lines.append(f"      build_total: {t_wall.fmt_ms()}  (wall around build_message)")
            lines.append(
                f"      payload_B:  n={pay.n} mean={pay.mean:.0f} B  median={pay.median:.0f} B"
            )
            if eta_s.n > 0:
                lines.append(
                    f"      eta:        n={eta_s.n} mean={eta_s.mean:.4g}  median={eta_s.median:.4g}"
                )
            lines.append("")
    lines.append("")

    # --- Gateway ---
    lines.append("2) Gateway samples — decrypt / verify path")
    lines.append("-" * 72)
    if g.empty:
        lines.append("  (no gateway rows; file missing or empty)")
    else:
        lines.append(f"  Rows: {len(g)}")
        lines.append(f"  Time span (ts_unix_ns): {ts_range_label_df(g)}")
        acc = int(g["accepted"].eq(True).sum())
        lines.append(f"  accepted=True: {acc} / {len(g)} ({100.0 * acc / max(len(g), 1):.1f}%)")
        lines.append("")

        g_b = _add_bucket_column(g)
        lines.append(
            "  Per bucket: crypto_kind, profile, NIST band, payload target, algorithm pair:"
        )
        for key, grp in g_b.groupby("_bucket", sort=True):
            decap = col_stats(grp["t_decap_ns"].astype(float))
            aed = col_stats(grp["t_aes_dec_ns"].astype(float))
            ver = col_stats(grp["t_verify_ns"].astype(float))
            gtot = col_stats(
                (grp["t_decap_ns"] + grp["t_aes_dec_ns"] + grp["t_verify_ns"]).astype(float)
            )
            tw = col_stats(grp["t_total_ns"].astype(float))
            lines.append(f"  · {key}")
            lines.append(f"      decap:       {decap.fmt_ms()}")
            lines.append(f"      aes_dec:     {aed.fmt_ms()}")
            lines.append(f"      verify:      {ver.fmt_ms()}")
            lines.append(f"      crypto_sum:  {gtot.fmt_ms()}  (decap+aes_dec+verify)")
            lines.append(f"      handler_wall: {tw.fmt_ms()}  (broader; includes key setup around crypto)")
            lines.append("")
    lines.append("")

    # --- Matched pairs ---
    lines.append("3) Matched client ↔ gateway rows (same device_id, session_id, seq)")
    lines.append("-" * 72)
    if c.empty or g.empty:
        lines.append("  (need both CSVs with data)")
    else:
        merged = c.merge(g, on=["device_id", "session_id", "seq"], how="inner", suffixes=("_c", "_g"))
        lines.append(f"  Matches: {len(merged)}")
        if not merged.empty:
            cl_c = merged["t_encap_ns"] + merged["t_sign_ns"] + merged["t_aes_ns"]
            gw_c = merged["t_decap_ns"] + merged["t_aes_dec_ns"] + merged["t_verify_ns"]
            d_crypto_ms = (gw_c - cl_c).astype(float) / 1e6
            total_crypto_ms = (cl_c + gw_c).astype(float) / 1e6

            ts_c = merged["ts_unix_ns_c"]
            ts_g = merged["ts_unix_ns_g"]
            valid_ts = (ts_c > 0) & (ts_g > 0)
            e2e_ms = ((ts_g - ts_c).astype(float) / 1e6).where(valid_ts)

            st = col_stats(d_crypto_ms.tolist())
            lines.append(
                "  Δ (gateway_crypto − client_crypto) [narrow sums], ms: "
                f"n={st.n} mean={st.mean:.3f} median={st.median:.3f} "
                f"stdev={st.stdev:.3f} (positive ⇒ gateway slower on this sum)"
            )

            st_t = col_stats(total_crypto_ms.tolist())
            lines.append("")
            lines.append(
                "  Total crypto (client_crypto_sum + gateway_crypto_sum), ms — same matched rows:"
            )
            lines.append(
                f"     n={st_t.n}  mean={st_t.mean:.3f}  median={st_t.median:.3f}  "
                f"stdev={st_t.stdev:.3f}  min={st_t.min_v:.3f}  max={st_t.max_v:.3f}"
            )

            e2e_drop = e2e_ms.dropna()
            if not e2e_drop.empty:
                st_e = col_stats(e2e_drop.tolist())
                lines.append("")
                lines.append(
                    "  Approx end-to-end (gateway.ts_unix_ns − client.ts_unix_ns), ms — "
                    "subset with valid timestamps; needs NTP sync between Pis for absolute accuracy:"
                )
                lines.append(
                    f"     n={st_e.n}  mean={st_e.mean:.3f}  median={st_e.median:.3f}  "
                    f"stdev={st_e.stdev:.3f}  min={st_e.min_v:.3f}  max={st_e.max_v:.3f}"
                )

            ck = merged["crypto_kind_g"]
            prof = merged["profile_g"]
            pt = merged["payload_target_bytes_g"]
            sb = merged["security_bits_g"]
            bucket = (
                ck.fillna("PQC").astype(str)
                + " | profile="
                + prof.fillna("?").astype(str)
                + " | nist≈"
                + _nist_band_vec(sb).astype(str)
                + " | payload_target_B="
                + _to_int_series(pt, 0).astype(str)
            )
            m2 = merged.assign(
                _total_ms=total_crypto_ms.astype(float),
                _e2e_ms=e2e_ms.astype(float),
                _bucket=bucket,
            )
            if m2["_bucket"].nunique() > 0:
                lines.append("")
                lines.append(
                    "  By bucket (crypto_kind | profile | NIST band | payload_target_bytes):"
                )
                for bkey, sub in m2.groupby("_bucket", sort=True):
                    st_b = col_stats(sub["_total_ms"].tolist())
                    lines.append(f"    · {bkey}")
                    lines.append(
                        f"        matches={len(sub)}  total_crypto_ms mean={st_b.mean:.3f} "
                        f"median={st_b.median:.3f}"
                    )
                    ee = sub["_e2e_ms"].dropna()
                    if not ee.empty:
                        st_ee = col_stats(ee.tolist())
                        lines.append(
                            f"        e2e_ts_delta_ms mean={st_ee.mean:.3f} median={st_ee.median:.3f}"
                        )
        lines.append("")
    lines.append("")

    if rtt_path is not None:
        lines.append("4) MQTT RTT baseline (gateway echo; no payload crypto)")
        lines.append("-" * 72)
        rtt_ns = load_rtt_samples(rtt_path)
        if not rtt_ns:
            lines.append(f"  (no rtt_ns rows in {rtt_path.resolve()} — run scripts/mqtt_rtt_baseline.py)")
        else:
            st_r = col_stats([x / 1_000_000.0 for x in rtt_ns])
            lines.append(
                f"  n={st_r.n}  mean={st_r.mean:.3f} ms  median={st_r.median:.3f} ms  "
                f"stdev={st_r.stdev:.3f} ms  p95={st_r.p95:.3f} ms"
            )
            lines.append(
                "  RTT is client wall time (publish → reply). Use as transport baseline vs crypto+handler totals."
            )
        lines.append("")

    lines.append("Notes")
    lines.append("-" * 72)
    lines.append("  • Client 'crypto_sum' is encap + sign + AES encrypt; η uses this × payload_bytes.")
    lines.append("  • Gateway 'crypto_sum' is decap + AES decrypt + verify (narrow windows).")
    lines.append("  • Gateway 'handler_wall' includes kem_keypair / base64 / sig_keypair outside narrow timers.")
    lines.append("  • Matched rows require identical device_id, session_id, seq on both sides.")
    lines.append(
        "  • CLASSICAL (symmetric-only) rows: KEM/sign timers are zero — compare to CLASSICAL-ASYM "
        "(ECDH-P256 + ECDSA-P256-SHA256 + AES) for an asymmetric classical baseline next to PQC."
    )
    lines.append(
        "  • End-to-end ts delta uses ts_unix_ns; meaningful only with clock sync (e.g. NTP) across hosts."
    )
    lines.append(
        "  • NIST band is a coarse label from security_bits (Σ): ≥256→L5, ≥192→L3, else L1; 0 → —."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    root = repo_root()
    default_rtt = root / "benchmarks" / "client" / "mqtt_rtt_samples.csv"
    p = argparse.ArgumentParser(description="Analyze PQC client + gateway benchmark CSVs (pandas).")
    p.add_argument(
        "--client",
        type=Path,
        default=root / "benchmarks" / "client" / "pqc_metrics.csv",
        help="Client benchmark CSV",
    )
    p.add_argument(
        "--gateway",
        type=Path,
        default=root / "benchmarks" / "gateway" / "pqc_metrics_gateway.csv",
        help="Gateway benchmark CSV",
    )
    p.add_argument(
        "--rtt",
        type=Path,
        nargs="?",
        const=default_rtt,
        default=None,
        metavar="CSV",
        help=(
            "Optional MQTT RTT CSV from mqtt_rtt_baseline.py; "
            "with --rtt alone defaults to benchmarks/client/mqtt_rtt_samples.csv"
        ),
    )
    p.add_argument("-o", "--out", type=Path, default=None, help="Write report to this file (UTF-8)")
    args = p.parse_args()

    text = build_report(args.client, args.gateway, args.rtt)
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"\n[written → {args.out.resolve()}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
