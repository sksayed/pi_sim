# Handoff context (journal evaluation + next stage)

This file saves the working context from the Cursor chat that produced the labelled two-Pi evaluation and the IEEE IoT Journal manuscript updates. Use it before implementing a **new stage** or changing Stage 1 / Stage 2.

**Do not treat this as a source of measured numbers for the paper.** Numbers below are a snapshot of what was reported. Canonical figures live in `paper/journal/main.tex` and `results/analysis/`. Project architecture for day-to-day coding is in `CLAUDE.md`.

**User working style in that chat:** go slowly; keep answers short and simple; do not invent data, citations, or performance figures; do not declare the paper submission-ready if scientific, experimental, or security issues remain.

---

## 1. What this repo is

Post-quantum cryptography (PQC) IoT MQTT benchmarking on Raspberry Pi.

**Path today (two stages):**

```
Client Pi  →  MQTT (Mosquitto :1883)  →  Gateway Pi
                 ↑                         │
            Stage 1 NFQUEUE IPS            Stage 2 re-encrypt
            (LightGBM, 32 features)        (ML-KEM-768 + AES-256-GCM + ML-DSA-65)
```

- **Stage 1** intercepts TCP/UDP to and from port 1883, classifies flow *segments*, optionally blocks the client tuple.
- **Stage 2** decrypts device traffic if needed, builds a PQC envelope. In the prototype the envelope is **not** sent to a cloud receiver (cloud is assumed, not implemented).

Hardware in the live testbed: two **Raspberry Pi 4 Model B Rev 1.5**, same phone hotspot. Gateway Pi runs broker + both stages; client Pi runs benign clients and attack generators.

Papers:

| File | Role |
|------|------|
| `paper/journal/main.tex` | IEEE Internet of Things Journal manuscript (the one updated in this chat) |
| `paper/journal/bib/references_journal.bib` | Bibliography |
| `paper/kics_2page_pqc_matrix.tex` | Separate 2-page KICS draft; **not** the target of the latest live-eval edits |

---

## 2. Key design facts (easy to get wrong)

### Keys (`shared/key_manager.py`)

Every key is still derived from **`MASTER_SECRET`** (64-char hex in `.env`, never commit). HKDF-SHA256, domain-separated `info` strings. No real key exchange on MQTT.

Live evaluation (`be82bd2` and later): PQC keygen uses liboqs with a **temporary custom RNG** = SHAKE-256 counter stream keyed by 64-byte HKDF output, then restores system RNG. A process-wide lock serializes keygen / encap / sign because the liboqs RNG is process-global.

**This is still not production security.** Anyone with `MASTER_SECRET` can derive gateway KEM private key, every device signing key, and the stand-in cloud key. Reviewer-grade production path (not implemented):

1. Generate ML-KEM / ML-DSA with liboqs **system RNG**.
2. Provision each party’s own keys; a device must not know the gateway’s private key.
3. Store private keys only on owners.
4. Distribute or authenticate public keys.
5. Remove process-wide deterministic RNG from production keygen.

Earlier bug (fixed for live eval, still used in the **scheme-comparison** benchmark): cyclic repetition of a 64-byte seed (`buf = seed * 64`).

Stage 2 currently **regenerates** KEM + signing key pairs **inside the handler** for every message (`gateway/benign_pipeline.py`). That inflates “full handler” time vs cached keys.

### Stage 1 classification

- Packets are **accepted before** classification (passive path).
- Triggers: FIN/RST with ≥3 packets; every 20 packets; idle reaper after 10 s.
- Flow entry is **reset after each verdict** (segments, not whole connections).
- Attack if argmax ≠ Benign **and** `p_benign < 1 - τ` (`τ = 0.5`).
- **Client-share rule:** keep ATTACK only if client sent ≥ `FW_MIN_CLIENT_SHARE` (0.3) of segment **payload bytes** (`FW_CLIENT_SHARE_BY=bytes`). Else verdict is benign. Raw model decision is logged as `model_verdict`.
- **Block after K:** `FW_BLOCK_AFTER_N=2` consecutive ATTACK verdicts; benign resets the streak.
- Block key: `(client_ip, proto, client_port, 1883)`. Blocks do not expire. Allow-list `FW_ALLOW_IPS` (R4: `127.0.0.1`).
- Broker→client packets of a blocked connection are dropped (`packet_dropped_to_client`) and **not re-classified**.

**Why those rules exist**

| Problem | Failed idea | What was kept |
|---------|-------------|----------------|
| Gateway/monitoring subscriber inherits forwarded attack payloads | Train/infer on client packets only (R1 FP 1.7% → 41.5%) | Byte-share ≥ 30% |
| One false ATTACK blocked long-lived benign MQTT sessions | — | Block after 2 consecutive ATTACKs |
| UDP/publish floods invisible at 1 event/s, UDP frames ~1066 B vs CIC 50 B | — | Publish ~40 msg/s; UDP 500 pkt/s, 8-byte payload |

**Evasion (must stay in Limitations):** an attacker that makes the broker send it most payload bytes (e.g. subscribe to many topics) can drop below 30% client share.

### Labelling (`experiments/analyze.py`)

- Infrastructure: `127.0.0.1` or gateway IP.
- Benign: client IP + port from `benign_conns.csv`.
- Attack: time window + grace (`flow timeout + 5 s`), using **first packet of the segment** (`nfqueue_first_wall_ns`).
- Precision/recall: attack vs **benign-client** verdicts; infrastructure separate.
- Benign MQTT `rc == 0` means **queued**, not broker ACK.
- IPS drop attribution: only drops on **blocked attack** tuples (iptables + callback). Do not add all callback drops to attack totals.
- Timing: exclude reaper verdicts with `t_inspection_ns == 0`.

### Training (do not retrain casually)

- Data: `data/CIC_IoMT_2024_WiFi_MQTT_test_notupdated.csv` (released **test** partition, 1,614,182 rows).
- Row-level 70/30 split, seed 42. **Not** capture-independent.
- 32 live-reproducible features (not all 45 CIC columns).
- C1 calibration: 375 live benign segments × 20 appended **after** the split; enter scaler + early-stopping val; never the test set. Same benign generators as evaluation → live FPR is optimistic.
- Feature drop and calibration were introduced **together**; no ablation. Pilot 45-feature model: 96.4% of C1 benign-client verdicts flagged.
- Offline: 71.5% accuracy, 0.709 macro-F1. Old 45-feature model ~97.85% offline but failed live.

---

## 3. Experiment protocol

**Scripts:** `experiments/plan.py` (single source of truth), `gateway_agent.py` (root, gateway Pi), `client_runner.py` (sudo, client Pi).

**Runs**

| ID | Traffic | Mode |
|----|---------|------|
| R1 | Benign 10 min | IDS |
| R2 | 10 attacks × 60 s + 20 s gaps | IDS |
| R3 | Benign + attacks | IDS |
| R4 | As R3 | IPS, allow-list 127.0.0.1 |
| R5 | As R3 | IPS, no allow-list |

**Paper sessions:** `PAPER_REPS = (6, 7, 8, 9)` in `experiments/plan.py`.  
`python experiments/analyze.py` (and `paper_tables.py`, `timing.py`, `make_journal_figs.py`) **only use those** unless `--all`.

**Session naming:** `R{1-5}_rep{N}`. Client runner: `for rep in range(first_rep, first_rep + reps)` then for each run R1…R5.

**Resume rule:** starting a session **deletes** `results/gateway/<session>` and rewrites client CSVs. Never rerun `--first-rep 6 --reps 5` after a partial success.

**How to start a run**

```bash
# both Pis
cd ~/Desktop/pi_project/pi_sim && git pull origin main

# gateway
sudo .venv/bin/python experiments/gateway_agent.py

# client (example: remaining sessions only)
sudo .venv/bin/python experiments/client_runner.py --gateway <IP> --runs R2,R3,R4,R5 --reps 1 --first-rep 10
```

Push **gateway first**, then client `git pull --rebase origin main && git push`. Remotes: GitHub `origin`, GitLab `gitlab`. Client results have often landed on GitLab first.

---

## 4. What happened in this chat (timeline)

Development method agreed: **tune on rep 1 only, check 2–3, then a fresh Pi run for the paper. Report whatever comes out. Do not tune on reported test runs.**

1. **Old full run (reps 1–3)** with 32-feature calibrated model, no share rule, block-after-1, attacks at 1 Hz. R3 precision 0.867 / recall 0.963; UDP 0%; publish ~14%; R4/R5 delivery 0.886 / ~0.59 because subscriber/false blocks.
2. **Laptop replay** (`experiments/replay_eval.py`) validated against live verdicts. Client-only features rejected. Packet-share 0.3 + K=2 chosen on rep1, checked on 2–3.
3. **Code:** share rule + `FW_BLOCK_AFTER_N`; faster publish/UDP; analyze/timing bugfixes.
4. **Trial rep 4:** packet-share insufficient (QoS1 ACKs). Byte-share + drop broker→blocked-client derived here (tuned on this trial).
5. **Trial rep 5:** first live check of byte-share + K=2; R1–R5 all ≥93% per-verdict accuracy; 100% delivery.
6. **Keygen SHAKE-256 + lock** (`be82bd2`) before the “final” run.
7. **Final run intended as reps 6–8 (or 6–10).** User used `--reps 5 --first-rep 6`. Wi-Fi drop at **R2_rep10**. Gateway push arrived before client; later both sides of **reps 6–9** complete. R2_rep10 discarded.
8. **Paper tables/results** filled from reps 6–9. Conclusion/limitations were still quoting the **old** run until updated.
9. **Reviewer-style edits (no new Pi run):**
   - Present **block rate** as prominently as detection; split unblocked into already-closed (SYN/connect/scans) vs still-open (**all 5 Slowloris sockets**).
   - Add **macro-averaged attack-family recall** (unweighted mean of 10 family flag rates).

**Commits of note (may sit under later paper-only edits):**

| Commit | Content |
|--------|---------|
| `be84af0` | Client-share + block-after-N; flood rates; analyze/timing fixes |
| `f90e7b4` | Earlier manuscript revision (training validity, metrics, key-gen caveats) |
| `355180a` | Share by **bytes**; drop broker-to-blocked-client |
| `be82bd2` | SHAKE-256 key stream + RNG lock |
| `85ca599` / `4325dd6` | Partial/final eval data (gateway then client) |

Local paper edits after that may still be **uncommitted**.

---

## 5. Reported live numbers (reps 6–9 only)

IDS, per-verdict, attack vs benign-client:

| Run | Accuracy | Precision | Recall | Macro-10 family recall | Notes |
|-----|----------|-----------|--------|------------------------|--------|
| R1 | 0.990 ± 0.006 | — | — | — | Benign flagged 1.0% ± 0.5% |
| R2 | 0.994 | 1.000 | 0.994 | 0.991 ± 0.002 | No mixed-traffic FP |
| R3 | 0.994 | 0.999 | 0.994 | 0.991 ± 0.002 | **The mixed-traffic result** |

- Recall **without UDP verdicts:** R2 0.981, R3 0.980. UDP ≈ 2,880 of ≈ 4,120 attack verdicts.
- Weakest family: **malformed MQTT** ~0.919 (R2) / 0.924 (R3).
- Raw model (before share rule) R3 precision **0.930**; subscriber raw flag ~54%, gateway subscriber ~61%; after rule ~0% / 0.3%.
- Stage 1 (50,026 verdicts): median classify 2.41 ms, inspect 2.86 ms (inline only).
- Stage 2 (N = 18,157, R1 and R3–R5): median re-encrypt 2.073 ms, handler 4.42 ms.

IPS:

| Metric | R4 | R5 |
|--------|----|----|
| Benign delivery | 1.000 | 1.000 |
| Block rate | 80.6% ± 1.2% | 80.2% ± 0.8% |
| Detected (any ATTACK verdict) | 100% of attack conns | 100% |
| Detected, not blocked | 82.0 ± 5.0 | 82.8 ± 3.3 |
| of which Slowloris still on broker | 5.0 | 5.0 |
| of which already closed | 77.0 ± 5.0 | 77.8 ± 3.3 |
| Packets before block | ~12.4 | ~12.4 |
| Benign conns blocked | 0.25 ± 0.50 | 0.25 ± 0.50 |

Per-family block (R4): publish / malformed / both UDP **100%**; serial connect **99.2%**; 5-thread connect **95.2%**; SYN **0%**; Slowloris **0% and sockets held**; vul scan **0%**; port scan **25%**.

---

## 6. Files that matter

| Path | Role |
|------|------|
| `firewall/mqtt_firewall.py` | Stage 1 |
| `firewall/lightgbm_model.txt`, `standard_scaler.pkl`, `feature_columns.json` | Deployed 32-feature model |
| `gateway/gateway.py`, `gateway/benign_pipeline.py` | Stage 2 |
| `shared/key_manager.py` | All keys |
| `experiments/plan.py` | Runs, FW env, `PAPER_REPS` |
| `experiments/analyze.py`, `paper_tables.py`, `timing.py`, `replay_eval.py` | Analysis / what-if |
| `scripts/make_journal_figs.py` | Figures under `paper/journal/figures/` |
| `results/gateway/R*_rep{6-9}`, `results/client/R*_rep{6-9}` | Paper data |
| `results/analysis/{summary,paper_tables,timing}.{json,md}` | Aggregates |
| `.env` | Secrets — never commit |

---

## 7. Outstanding issues (paper + system)

Do not hide these if extending the system or claiming production security.

- Shared `MASTER_SECRET`; no independent key provisioning.
- Scheme-comparison matrix: sequential single runs; cyclic RNG era; PQC keys regenerated per message, classical keys cached.
- CIC split is row-level on the released **test** partition.
- No ablation of 32 features vs C1 calibration.
- ICMP and replay not in live eval.
- UDP rate 500 pkt/s vs CIC ~20k (Python NFQUEUE limit).
- CPU governor / thermal state not logged (live Stage 1/2 slower than old one-Pi session).
- Enforcement delay (verdict → first drop) not timed.
- Client-share evasion; adversarial robustness untested.
- One client Pi, one Wi-Fi AP.
- Cloud receiver unimplemented; G2/G3 are envelope properties, not demonstrated.
- Paper may not have been compiled locally (no LaTeX engine on the laptop in that chat).
- Uncommitted `main.tex` / figure / analysis edits may still sit in the working tree.
- `paper/kics_2page_pqc_matrix.tex` may have unrelated local edits.

---

## 8. Starting a new stage (read this first)

The current claim is **two stages**: inline IDS/IPS, then PQC re-encryption of messages that reach the gateway subscriber.

A third stage (for example: actual cloud publish + verify/decap, key provisioning, per-host SYN/Slowloris controls, native NFQUEUE, WAN path) should:

1. **Not silently change Stage 1 policies or `PAPER_REPS`** if the journal numbers must stay reproducible.
2. **Not mix development trials (reps 1–5) into paper tables.**
3. Keep MQTT topic contract: `nodes/{device_id}/data`, JSON with `crypto_type`, etc. (`CLAUDE.md`).
4. Stage 2’s envelope is transmitted only when `GW_CLOUD_FORWARD=1` (HTTPS POST to the PC). Default off, so reps 6–9 stay unchanged.
5. If you change key generation, **both Pis must pull the same commit** or every message fails.
6. If you change the firewall, re-run at least a short R1, then R3/R4, on **new rep numbers** (e.g. start at 11). Do not overwrite 6–9.
7. Prefer new modules/directories (`stage3/`, `cloud/`) over rewriting `mqtt_firewall.py` unless the new stage is really IPS policy.

Suggested first implementation steps when you begin:

- List which existing timers/CSV columns you will reuse vs new files under `results/`.
- Keep `.env` / private keys out of git.

---

## 9. Cloud end-to-end extension (HTTPS, not part of the journal numbers)

Off unless `GW_CLOUD_FORWARD=1`. The path is IoT Pi → MQTT → gateway Pi → HTTPS port 8443 → Windows PC on the same hotspot.

- Stage 2 still builds the ML-KEM-768 + AES-256-GCM + ML-DSA-65 envelope. A background thread POSTs it (`gateway/cloud_uplink.py`). The MQTT callback does not wait. HTTPS time is not added to the Stage 2 CSV.
- The PC runs `python -m cloud.setup_pc` (auto IP/TLS/env/portproxy + server) or `python -m cloud.https_server`. It verifies ML-DSA, decapsulates ML-KEM, decrypts AES-GCM, then applies replay rules. HTTP 200 only after that. A retry of the last accepted seq returns `duplicate=true` and is not stored again. An older seq returns 409 and is not retried.
- Gateway ML-DSA private key and cloud ML-KEM private key are generated with the system RNG (`python -m cloud.provision`). They are not derived from `MASTER_SECRET`. Public keys are pinned by SHA-256 in `keys/trust.json`. TLS verification stays on.
- Logs: `results/cloud/uplink.jsonl`, `results/cloud/replay_state.json`, `results/gateway/cloud_uplink.jsonl`. No database.
- `cloud/cloud_receiver.py` (MQTT) is retired.
- Second client Pi runs `experiments/extra_client.py`: auto-finds the agent, waits for Pi A’s session, registers as a peer, logs CSVs under `results/client/<session>/peers/<tag>/`. Do not run `client_runner.py` on both Pis. `analyze.py` / `paper_tables.py` label both client IPs.
- Run steps: `docs/e2e_cloud.md`. Local wiring check: `python cloud/e2e_selftest.py`.
- Use new rep numbers (11+). Do not overwrite reps 6–9.

## 10. Communication leftover for the next agent

- Raspberry Pi path on devices was `~/Desktop/pi_project/pi_sim`.
- Gateway agent waits on TCP **9100**; UDP beacon **9101**.
- Syn flood needs **sudo** on the client Pi; without it that attack is skipped.
- If the client fails while the agent still runs: **do not restart the agent unless it is in ERROR**; resume with `--runs` listing only remaining IDs and `--first-rep` of the unfinished rep.
- Journal paper title: *Two-Stage MQTT Gateway Security: Live Intrusion Filtering and Post-Quantum Re-Encryption on Raspberry Pi*.
)
