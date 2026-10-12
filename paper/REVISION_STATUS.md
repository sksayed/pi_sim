# Paper revision status (from agent sessions)

Last updated: 2026-10-13.

Working log of what was done across the recent agent conversations, what the evidence supports, and what remains. This is **not** a manuscript section.

**Git:** branch `ids_implementation_gateway` → `origin` (`git@gitlab.com:sayedrahman015/pi_sim.git`). Latest paper work is in commit `50cb0ee` and follow-ups on this note.

---

## Two papers

| Paper | File | Format | Status |
|---|---|---|---|
| KICS 2-page (PQC scheme comparison) | `paper/kics_2page_pqc_matrix.tex` | IEEEtran conference | Draft largely complete; not re-aligned with later journal fairness wording |
| IEEE IoT Journal (two-stage system) | `paper/journal/main.tex` | IEEEtran journal, two-column | Draft in progress; overclaims qualified (Problems 2–4, 6–7) |

**Author decisions recorded in chat**

- Prefer short answers; write from existing data; do not re-run experiments until a later labelled run.
- Remove offline-to-live / benign-delivery ratio finding for now (kept for later).
- Remove KICS citations from the journal (IEEE may still expect citing a conference version later).
- Keep journal title: *Two-Stage MQTT Gateway Security: Live Intrusion Filtering and Post-Quantum Re-Encryption on Raspberry Pi*.
- Gateway→cloud is assumed; focus claims on device→gateway and gateway PQC.
- Live sessions ran on Raspberry Pi; logs were copied to this WSL checkout (keep Pi artifacts for submission).

---

## Conversation timeline (problems / tasks)

### Setup and drafting

1. Split: KICS = scheme comparison; journal = full two-stage system.
2. Journal folder layout: `paper/journal/main.tex`, `figures/`, `bib/references_journal.bib`.
3. Converted journal from elsarticle to IEEEtran (`[journal]{IEEEtran}`): `\thanks`, Index Terms, `\IEEEPARstart`, `table*`/`figure*`, `IEEEtran` bst; removed Elsevier highlights / CRediT / declarations.
4. Figures regenerated at column width (`scripts/make_journal_figs.py`); offline per-class legend moved above plot.

### Task 1 — Stage 2 signature (code)

- Sign encoded envelope (id, seq, kem_ct, nonce, ciphertext), not plaintext (`gateway/benign_pipeline.py`).
- `verify_cloud_envelope()` exists; **nothing calls it**; gateway ignores `handle_benign` return (no publish).
- Paper discloses timings were under older plaintext-signing revision.

### Problem 2 — Key provisioning / cloud assumption (LaTeX)

- New subsection `sec:keys`: MASTER_SECRET, HKDF, liboqs deterministic RNG (custom algorithm + cyclic 64-byte HKDF stream + restore system RNG), trust assumptions, shared-secret limits.
- Cloud receiver assumed; receiver cost = Pi reference, not proven upper bound.
- Production key management overhead distinguished from measured crypto ops.

### Problem 3 — Live IDS/IPS effectiveness (investigation only)

- No per-flow ground truth in logs → no TPR/FPR/confusion matrix/suppression rate.
- Attack-only 893 = predictions; combined 37 verdicts; 144 Stage 2 = received messages.
- Inferred: ≥11 benign publisher blocks, 9 subscriber-like; Stage 2 stalled ~6.3 min.
- Plan for labelled re-run documented (R1–R5, loopback IP roles, send logs, drop counters).

### Problem 4 — Packet admission / IPS enforcement (LaTeX)

- 0.944 ms = classification processing, not detect-and-suppress time.
- Packets accepted before classify; block after verdict; short flows may finish first.
- Title kept (“Filtering” = subsequent packets of flagged connections).

### Problem 5 — Threat model vs attack coverage (**findings only; LaTeX not fully applied**)

- NFQUEUE: TCP/UDP **port 1883 only**.
- ICMP / ARP / ping sweep / non-1883 ports: outside boundary.
- Connect flood / spoofed SYN: little practical block effect.
- Malformed / replay: not Stage 1 content inspection / not Stage 1 replay class.
- Manuscript A1 and attack-client list still need Problem 5 wording pass.

### Problem 6 — Crypto benchmark fairness (LaTeX + Handler column)

- 36–54% → **~36–53% crypto time** at 5 KB for ML-KEM+ML-DSA/Falcon vs ECDH+ECDSA only.
- Sequential runs, liboqs vs OpenSSL, unequal timer boundaries documented.
- Handler column in `tab:matrix` from CSV medians; ECDH+ECDSA faster on handler time (cached keys).
- Key caching = **expected**, not measured.

### Problem 7 — Joint evaluation / e2e claims (LaTeX)

- Simultaneous operation ≠ e2e security/availability.
- 144 = gateway-side envelopes, not cloud delivery; envelope not transmitted.
- Stage 1 + Stage 2 timers not summed into e2e latency.
- G2/G3 = design goals; cloud path not evaluated.

---

## Implemented in code

**Stage 2 envelope signing** (`gateway/benign_pipeline.py`)

- `encode_signed_envelope()` / `verify_cloud_envelope()` / `handle_benign()` returns `cloud_payload`.
- `gateway.py` does **not** publish the envelope.
- No unit tests for field tampering.
- Live Stage 2 timings = older plaintext-signing revision.

Do not treat cloud verification as implemented.

---

## What the journal can claim now (evidence-backed)

### Offline IDS

- Accuracy 97.85%, macro-F1 0.900, weighted F1 0.979 (N_test = 484,255).
- Benign P/R 0.979; weak: Ping_Sweep, VulScan, Malformed, OS_Scan, ARP.
- Feature gain: Variance, Rate, Tot size dominate.

### Stage 1 live (predictions + timing, not detection rates)

- Attack-only: 893 flows all **predicted** attack; conf mean 0.997; infer 0.435 / classify 0.944 / inspect 1.201 ms.
- Combined: 4,253 packets, 37 verdicts; infer 0.906 / classify 2.075 ms.
- Packets accepted before classify; min packets 3 (attack-only) vs 20 (combined); 216 short TCPs never classified in combined session.

### Combined IPS observation (inferred)

- 144 Stage 2 rows = local construction only.
- ≥11 benign publisher + 9 subscriber-like blocks (inferred).
- Stage 2 receipts stopped ~6.3 min / 20 min session.
- No exact delivery ratio; no TPR/FPR/suppression.

### Stage 2 crypto

- N = 144; median re-encrypt 0.156 ms; handler median 0.383 ms; envelope not sent.

### Scheme matrix (18,000 msgs)

- 10 × 3 × 600; crypto advantage ~36–53% at 5 KB (qualified); Handler column in table; AES/ChaCha = symmetric refs only.

---

## What is left to do

### A. Labelled live evaluation (fill `\TODO{}` tables)

1. Per-role loopback IPs; ground-truth sidecar; benign `seq` send logs; drop/unclassified flow logs.
2. Same classify settings every session; one JSONL folder per run.
3. Runs R1–R5; 3× repeats of R3/R4.
4. Fill `tab:live-detect` / `tab:ips-effect`; remove red `\TODO` before submission.

### B. Cloud / HNDL experimental claims

1. Publish Stage 2 envelope + receiver path.
2. Verify/tamper tests; re-measure signing after envelope change.
3. WAN / receiver latency only if claimed.

### C. Manuscript open items

1. **Compile** `paper/journal/main.tex` (no `pdflatex` in this environment; only static checks so far).
2. Apply **Problem 5** attack-coverage wording (A1, attack list, 1883-only interception).
3. Decide whether to cite KICS papers (IEEE extended-paper custom).
4. Soften Fig. 1 solid “PQC” arrow vs dashed Cloud if needed.
5. Author bios/photos at final IEEE submission if required.
6. Bib: `dimatteo2026kem22` end page still TODO.
7. Align KICS 2-page with 36–53% / fairness wording if both submitted.
8. Optional: restore offline-to-live / delivery-ratio analysis after labelled run.

### D. Do not claim until re-run

- Live TPR, FPR, precision, recall, confusion matrix.
- Attack suppression rate; exact benign delivery ratio.
- Continuous availability under attack.
- Cloud confidentiality / authentication / replay as **experimental** results.
- Cached-PQC handler faster than ECDH+ECDSA on **total** handler time.

---

## Platform / artifact note

This checkout’s `Firewall_logs/mqtt_firewall.jsonl` includes `10.255.255.254` DNS packets typical of WSL2. Author states Pi origin + copy. Archive Pi raw logs with the submission artifact. Run the labelled campaign on the Pi into a self-contained session folder.

---

## File map

| Path | Role |
|---|---|
| `paper/journal/main.tex` | Journal manuscript |
| `paper/journal/bib/references_journal.bib` | Journal bibliography |
| `paper/journal/figures/` | Journal figures |
| `paper/kics_2page_pqc_matrix.tex` | KICS 2-page draft |
| `paper/figures/kics_pqc_matrix.png` | KICS figure |
| `paper/REVISION_STATUS.md` | This status note |
| `scripts/make_journal_figs.py` | Journal figure generator |
| `scripts/make_kics_pqc_matrix_fig.py` | KICS figure generator |
| `gateway/benign_pipeline.py` | Stage 2 re-encrypt + envelope encode/verify |
| `paper/literature/` | Notes and OA extracts (`pdf/` gitignored) |
| `benchmarks/` | Reports + CSVs used for paper numbers |
| `Firewall_logs/` | Live firewall JSONL (runtime; check gitignore) |
