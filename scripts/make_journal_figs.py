"""Figures and summary numbers for the journal paper (paper/journal/)."""
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

OUT = Path("paper/journal/figures")
OUT.mkdir(parents=True, exist_ok=True)
LGBM = Path("outputs/lgbm_based_on_subroto_vai")
plt.rcParams.update({"font.size": 8, "axes.grid": True, "grid.alpha": 0.3})


def offline_per_class():
    pc = pd.read_csv(LGBM / "lightgbm_per_class_metrics.csv").sort_values("f1_score")
    fig, ax = plt.subplots(figsize=(3.5, 4.6))
    y = range(len(pc))
    ax.barh([i - 0.27 for i in y], pc.precision, 0.27, label="Precision", color="#2b6cb0")
    ax.barh(list(y), pc.recall, 0.27, label="Recall", color="#90cdf4")
    ax.barh([i + 0.27 for i in y], pc.f1_score, 0.27, label="F1", color="#c53030")
    ax.set_yticks(list(y))
    ax.set_yticklabels(pc["class"], fontsize=6)
    ax.set_xlim(0, 1.0)
    ax.set_xlabel("Score (held-out test set, N = 484,255)")
    ax.legend(loc="lower center", bbox_to_anchor=(0.4, 1.0), ncol=3, fontsize=6, frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "fig_offline_per_class.png", dpi=300)


def feature_importance(top=15):
    fi = pd.read_csv(LGBM / "lightgbm_feature_importance.csv").head(top)[::-1]
    fi["share"] = 100 * fi.importance_gain / pd.read_csv(LGBM / "lightgbm_feature_importance.csv").importance_gain.sum()
    fig, ax = plt.subplots(figsize=(3.5, 2.8))
    ax.barh(fi.feature, fi.share, color="#2b6cb0")
    ax.set_xlabel("Share of total split gain (%)")
    ax.tick_params(axis="y", labelsize=7)
    fig.tight_layout()
    fig.savefig(OUT / "fig_feature_importance.png", dpi=300)
    print("top-5 gain share %:", fi[::-1].head(5)[["feature", "share"]].round(1).values.tolist())


def stage2_latency():
    files = sorted(Path("results/gateway").glob("R*_rep*/reencrypt_metrics.csv"))
    d = pd.concat([pd.read_csv(f) for f in files])
    d = d[d.pqc_available]
    cols = {"t_encap_ns": "ML-KEM-768\nencap", "t_aes_enc_ns": "AES-256-GCM\nencrypt",
            "t_sign_ns": "ML-DSA-65\nsign", "t_reencrypt_ns": "Total\nre-encrypt",
            "t_recv_to_done_ns": "Gateway\nhandler"}
    ms = d[list(cols)] / 1e6
    print("stage-2 stats (ms):")
    print(ms.describe(percentiles=[0.5, 0.95, 0.99]).T.round(3).to_string())
    fig, ax = plt.subplots(figsize=(3.5, 2.4))
    ax.boxplot([ms[c] for c in cols], showfliers=True, whis=(5, 95),
               flierprops={"markersize": 2, "alpha": 0.5})
    ax.set_xticks(range(1, len(cols) + 1))
    ax.set_xticklabels(cols.values(), fontsize=6)
    ax.set_yscale("log")
    ax.set_ylabel("Latency (ms, log scale)")
    fig.tight_layout()
    fig.savefig(OUT / "fig_stage2_latency.png", dpi=300)


LABELS = {
    "CC": "ChaCha20-Poly1305", "CA": "AES-256-GCM", "CE": "ECDH+ECDSA P-256",
    "1": "ML-KEM-512+ML-DSA-44", "2": "ML-KEM-512+Falcon-512", "4": "ML-KEM-768+ML-DSA-65",
    "6": "ML-KEM-768+SLH-DSA-128s", "5": "FrodoKEM-640+ML-DSA-65",
    "7": "FrodoKEM-640+SLH-DSA-128s", "3": "BIKE-L1+ML-DSA-44",
}


def scheme_matrix():
    d = pd.read_csv("benchmarks/gateway/pqc_metrics_gateway.csv", dtype={"profile": str})
    d = d[d.pqc_available & (d.payload_target_bytes > 0) & d.accepted]
    d["crypto_ms"] = (d.t_decap_ns + d.t_aes_dec_ns + d.t_verify_ns) / 1e6
    g = d.groupby(["profile", "payload_target_bytes"]).agg(
        crypto=("crypto_ms", "median"), msg=("payload_bytes", "median")).reset_index()
    order = list(LABELS)
    sizes = {5120: "5 KB", 10240: "10 KB", 102400: "100 KB"}
    colors = {5120: "#2b6cb0", 10240: "#63b3ed", 102400: "#bee3f8"}
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.2, 3.4), sharey=True)
    for k, (sz, lab) in enumerate(sizes.items()):
        s = g[g.payload_target_bytes == sz].set_index("profile").loc[order]
        pos = [i + (k - 1) * 0.27 for i in range(len(order))]
        a1.barh(pos, s.crypto, 0.27, label=lab, color=colors[sz])
        a2.barh(pos, s.msg / 1024, 0.27, label=lab, color=colors[sz])
    a1.set_xscale("log")
    a1.set_xlabel("Gateway crypto latency, median (ms)")
    a2.set_xscale("log")
    a2.set_xlabel("Serialized MQTT message (KiB)")
    a1.set_yticks(range(len(order)))
    a1.set_yticklabels([LABELS[p] for p in order], fontsize=7)
    a1.invert_yaxis()
    h, lab = a1.get_legend_handles_labels()
    fig.legend(h, lab, loc="upper center", ncol=3, fontsize=7, frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(OUT / "fig_scheme_matrix.png", dpi=300)


if __name__ == "__main__":
    offline_per_class()
    feature_importance()
    stage2_latency()
    scheme_matrix()
    print("figures written to", OUT)
