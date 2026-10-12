"""Figure + table numbers for the KICS 2-page PQC scheme-comparison paper."""
import pandas as pd
import matplotlib.pyplot as plt

CSV = "benchmarks/gateway/pqc_metrics_gateway.csv"
OUT = "paper/figures/kics_pqc_matrix.png"

LABELS = {
    "CC": "ChaCha20", "CA": "AES-GCM", "CE": "ECDH+ECDSA",
    "1": "MLKEM512+MLDSA44", "2": "MLKEM512+Falcon512", "4": "MLKEM768+MLDSA65",
    "6": "MLKEM768+SLH128s", "5": "Frodo640+MLDSA65", "7": "Frodo640+SLH128s",
    "3": "BIKE-L1+MLDSA44",
}

d = pd.read_csv(CSV, dtype={"profile": str})
d = d[d.pqc_available & (d.payload_target_bytes > 0) & d.accepted]
d["crypto_ms"] = (d.t_decap_ns + d.t_aes_dec_ns + d.t_verify_ns) / 1e6
d["total_ms"] = d.t_total_ns / 1e6

g = d.groupby(["profile", "payload_target_bytes"]).agg(
    crypto=("crypto_ms", "median"), p95=("crypto_ms", lambda x: x.quantile(0.95)),
    total=("total_ms", "median"), wire=("payload_bytes", "median"),
    dec=("t_decap_ns", "median"), ver=("t_verify_ns", "median"), n=("crypto_ms", "size"),
).reset_index()
print(g.round(3).to_string())

order = list(LABELS)
s5 = g[g.payload_target_bytes == 5120].set_index("profile").loc[order]
s100 = g[g.payload_target_bytes == 102400].set_index("profile").loc[order]
names = [LABELS[p] for p in order]
y = range(len(order))

fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.2, 2.4), sharey=True)
a1.barh([i + 0.2 for i in y], s5.crypto, 0.4, label="5 KB", color="#2b6cb0")
a1.barh([i - 0.2 for i in y], s100.crypto, 0.4, label="100 KB", color="#90cdf4")
a1.set_xscale("log"); a1.set_xlabel("Gateway crypto latency, median (ms)")
a1.legend(fontsize=7, loc="upper right")
a2.barh(y, s5.total - s5.crypto, color="#c53030")
a2.set_xscale("log"); a2.set_xlabel("Non-crypto time incl. key regen. (ms)")
a1.set_yticks(list(y)); a1.set_yticklabels(names, fontsize=7)
a1.invert_yaxis()
for a in (a1, a2):
    a.tick_params(labelsize=7); a.grid(axis="x", which="both", alpha=0.3)
fig.tight_layout()
fig.savefig(OUT, dpi=300)
print("saved", OUT)
