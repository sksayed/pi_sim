# Paper revision status (from agent sessions)

Last updated: 2026-10-13.

This note records what was done across the recent writing sessions, what the evidence supports, and what is still open. It is a working log, not a manuscript section.

## Two papers

| Paper | File | Format | Status |
|---|---|---|---|
| KICS 2-page (scheme comparison) | `paper/kics_2page_pqc_matrix.tex` | IEEEtran conference | Draft largely complete; not re-checked against the later journal fairness edits |
| IEEE IoT Journal (two-stage system) | `paper/journal/main.tex` | IEEEtran journal, two-column | Draft in progress; several overclaims have been qualified |

KICS citations were removed from the journal at the author's request. IEEE usually expects an extended-journal paper to cite the conference version; that is a later policy choice, not a technical blocker.

---

## Implemented in code (this session)

**Stage 2 envelope signing** (`gateway/benign_pipeline.py`)

- `encode_signed_envelope()` signs a domain-tagged encoding of device ID, `seq`, KEM ciphertext, AES nonce, and AES ciphertext (not plaintext).
- `verify_cloud_envelope()` rebuilds the same bytes.
- `handle_benign()` returns `cloud_payload`; `gateway.py` ignores the return and does **not** publish it.
- No tests check that tampering with a signed field fails verification.
- Stage 2 live timings in the paper were recorded under the **older** plaintext-signing revision and have not been re-measured.

Do not treat cloud verification as implemented.

---

## Journal manuscript: what can be claimed now

### Offline IDS (supported)

- Accuracy 97.85%, macro-F1 0.900, weighted F1 0.979 on 484,255 held-out CICIoMT2024 flows.
- Benign precision/recall 0.979 (~2.1% benign misclassified offline).
- Weak classes: Ping_Sweep, VulScan, Malformed, OS_Scan, ARP.
- Feature gain: Variance, Rate, Tot size dominate.

### Stage 1 live (supported as **predictions and timing**, not detection rates)

- Attack-only session: 893 classified flows, all **predicted** as attack; mean confidence 0.997; latency infer 0.435 ms, classify 0.944 ms, inspect 1.201 ms.
- Combined session: 4,253 intercepted packets, 37 verdicts (36 attack, 1 benign); infer 0.906 ms, classify 2.075 ms.
- 0.944 ms is **classification processing**, not time-to-block. Packets are accepted before classification.
- Combined session used `min_pkts_classify = 20`; 216 short TCP connections were never classified.
- Blocking is per client tuple after a verdict; first packets always reach the broker.

### Combined-session IPS observation (inferred, not labelled)

- 144 Stage 2 rows = **local envelope construction**, not cloud delivery.
- At least 11 blocked connections attributed as benign publishers; 9 as subscriber-like (including the gateway).
- Stage 2 receipts paused then stopped at ~6.3 min of a 20 min session, temporally aligned with subscriber blocks.
- No benign send log → **no exact delivery ratio**.
- No per-flow ground truth → **no TPR/FPR/confusion matrix/suppression rate**.

### Stage 2 crypto (supported as gateway-side cost)

- N = 144, 188–213 B JSON, real liboqs.
- Median re-encrypt 0.156 ms; handler median 0.383 ms.
- Envelope is **not transmitted**.

### Scheme comparison (18,000 messages; supported with qualifiers)

- 10 configs × 3 sizes × 600, sequential, no repeats.
- Crypto-time advantage vs ECDH+ECDSA at 5 KB is **~36–53%** for ML-KEM + ML-DSA/Falcon only (not 36–54% “gateway processing”).
- Handler column added: ECDH+ECDSA was **faster on total handler time** because classical keys were cached and PQC keys were regenerated per message.
- AES/ChaCha are symmetric-only references, not security-equivalent.
- Receiver 0.772 ms is a **5 KB Pi reference**, not a cloud measurement; live envelopes were ~200 B plaintext.
- Key caching is an **expected** benefit, not a measured cached-PQC handler.

### Cloud / HNDL / A3

- Design goals G2/G3 only. No cloud receiver, no WAN, no uplink adversary measurement.

---

## Threat-model vs interception (Problem 5; **not yet applied to LaTeX**)

NFQUEUE rules are TCP/UDP **port 1883 only**.

| Attack | Live Stage 1 coverage |
|---|---|
| MQTT publish flood | Intercepted, classifiable, blockable after first N packets |
| UDP flood to 1883 | Same, if aimed at 1883 |
| MQTT connect flood | Often classified after FIN; block has little effect |
| SYN flood | Partial; spoofed ports not blockable in practice |
| Slowloris | Late classification; no matching CICIoMT class |
| Malformed MQTT | Flow stats only; payload not inspected |
| Port/vuln scan | Only the probe to 1883 |
| Replay | Not a Stage 1 class; gateway replay check is for encrypted research paths, not `handle_benign` |
| ICMP / ARP / ping sweep | **Outside** the iptables boundary |

`attack_manager` can randomize ports to 8883/1884/etc., which Mosquitto does not listen on and NFQUEUE does not capture.

---

## Journal LaTeX work already done

- Converted from elsarticle to `\documentclass[journal]{IEEEtran}` (IEEE IoT style).
- Removed Elsevier-only sections (highlights, CRediT, competing interest, data/AI declarations).
- Funding in `\thanks`; Index Terms; `\IEEEPARstart`; `table*`/`figure*` for wide floats; `IEEEtran` bibliography.
- KICS bib entries removed from `paper/journal/bib/references_journal.bib`.
- New subsection: Key Provisioning and Experimental Assumptions (`sec:keys`).
- IDS wording: prediction vs detection; combined-session client count; inferred blocked-connection table; enforcement timing; labelled-eval **placeholder** tables (`tab:live-detect`, `tab:ips-effect`).
- Crypto fairness: timer boundaries, sequential runs, Handler column, 36–53% wording, caching not demonstrated.
- Joint evaluation: 144 = received by Stage 2; no e2e latency sum; cloud dashed/assumed.

Figures live in `paper/journal/figures/` (regenerated at column width by `scripts/make_journal_figs.py`).

---

## What is left to do

### Must do before a labelled live claim (paper Tables A/B)

1. Bind each role to its own loopback IP (gateway, monitor, benign, attackers).
2. Ground-truth sidecar: role, IP:port, connect/reconnect, attack windows on disk.
3. Benign clients log every sent `seq`.
4. Log drops (or iptables counters) and flows that end without a verdict.
5. Same `MIN_PKTS_CLASSIFY` / `CLASSIFY_EVERY_N_PKTS` in every session; one JSONL folder per run.
6. Runs R1–R5 (IDS benign; IDS per-attack; IDS mixed; IPS allow-listed; optional IPS no allow-list), three repeats of R3/R4.
7. Fill `\TODO{}` tables in `sec:res-labelled`; remove the red TODO macro before submission.

### Must do before cloud / HNDL claims

1. Publish the Stage 2 envelope and run a cloud (or local) receiver.
2. Tests: unchanged envelope verifies; tampering any field fails; wrong key fails.
3. Re-measure Stage 2 signing after envelope signing.
4. WAN / receiver latency if claimed.

### Manuscript still open

1. **Compile** `paper/journal/main.tex` (Overleaf or TeX Live). No `pdflatex` on this machine; only static brace/ref checks were run.
2. Apply Problem 5 (attack-coverage) wording: A1, attack-client list, interception = TCP/UDP 1883.
3. Decide whether to cite the KICS papers (IEEE extended-paper custom).
4. Check Fig. 1 solid “PQC” arrow toward a dashed Cloud.
5. Author biographies/photos if required at final IEEE submission.
6. `dimatteo2026kem22` still lacks an end page.
7. Optional: add Handler discussion numbers already in `tab:matrix` are enough for reviewers.
8. KICS 2-page still uses older 36–54%-style claims and 2025 KICS citation year; align if both are submitted.

### Do not claim until re-run

- Live TPR, FPR, precision, recall, confusion matrix.
- Attack suppression rate.
- Exact benign delivery ratio.
- Continuous availability under attack.
- Cloud confidentiality/authentication/replay as **experimental** results.
- Cached-PQC handler being faster than ECDH+ECDSA on **total** time.

---

## Platform note

Combined-session `mqtt_firewall.jsonl` on this checkout contains `10.255.255.254` DNS packets typical of WSL2. The author states the experiments ran on a Raspberry Pi and were copied here. Keep the Pi raw logs with the artifact at submission. The labelled re-run should be executed on the Pi and archived as a self-contained session folder.

---

## File map

| Path | Role |
|---|---|
| `paper/journal/main.tex` | Journal manuscript |
| `paper/journal/bib/references_journal.bib` | Journal bibliography |
| `paper/journal/figures/` | Journal figures |
| `paper/kics_2page_pqc_matrix.tex` | KICS 2-page draft |
| `paper/figures/kics_pqc_matrix.png` | KICS figure |
| `scripts/make_journal_figs.py` | Journal figure generator |
| `scripts/make_kics_pqc_matrix_fig.py` | KICS figure generator |
| `gateway/benign_pipeline.py` | Stage 2 re-encrypt + envelope encode/verify |
| `paper/literature/` | Notes and OA extracts (`pdf/` gitignored) |
