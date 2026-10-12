# Consolidated research gap (locked)

## One-sentence gap

Recent Q1 work (2024–2025) advances **either** (i) high-accuracy / lightweight / federated **IoT IDS** (offline Acc/F1/ROC/CM), **or** (ii) **PQC primitives / TLS / ASIC** on constrained hardware (handshake ms, memory, area/energy) — but does **not** deliver a **hardware-validated two-stage MQTT gateway** that (1) filters live attacks before broker admission and (2) upgrades surviving traffic to **NIST Level-3** PQC for cloud transit, with **joint** latency characterization.

## Paper-by-paper → gap map

| ID | They contribute | Evaluation style | Still open (our opening) |
|----|-----------------|------------------|---------------------------|
| A | CICIoMT2024 MQTT/IoMT attack dataset | Dataset stats + offline ML baselines | Live NFQUEUE firewall; PQC transit |
| B | Strong LightGBM+CNN IDS on CICIoMT | Acc/F1/FAR, ROC, confusion matrices (Kaggle) | Online ms verdicts on Pi; PQC |
| C | Lightweight DL IDS (TBCLNN + SKD) | Acc >99%, model size/compute | MQTT gateway path; HNDL protection |
| D | Privacy-preserving federated IIoT IDS | Acc, FL compute/comm overhead | Inline MQTT enforce; PQC re-encrypt |
| E | PQ-TLS (ML-KEM+ML-DSA) on Raspberry Pi 4 | Handshake ms, memory, bytes, cert size | MQTT IDS; app-layer re-encrypt; brownfield devices |
| F | ML-KEM ASIC efficiency | Area, power, energy, ATP | System MQTT pipeline |

## What our findings close

1. **Live Stage 1:** LightGBM MQTT IDS/IPS via NetfilterQueue on Pi; per-attack confidence + classify/verdict latency (~0.94 ms classify in firewall report).
2. **Stage 2:** Transparent gateway re-encryption to ML-KEM-768 + AES-256-GCM + ML-DSA-65 (real liboqs); mean crypto ~**0.189 ms** (N=144 e2e run).
3. **Composition:** Combined run — attacks do not reach PQC path (0 firewall misses); benign messages PQ-upgraded; stages’ latency paths do not couple.

## Comparison axes for Related Work table (draft columns)

| Work | Live MQTT path? | IDS/IPS? | PQC? | Hardware | Primary metrics |
|------|-----------------|----------|------|----------|-----------------|
| A | dataset only | offline | no | testbed capture | dataset / baselines |
| B | no | offline ML | no | Kaggle GPU/CPU | Acc, F1, ROC, CM |
| C | no | offline DL | no | (dataset eval) | Acc, model size |
| D | no (FL) | FL IDS | no (HE for FL) | cloud IIoT demo | Acc, FL overhead |
| E | TLS not MQTT | no | TLS PQC | Raspberry Pi 4 | handshake ms, mem, bytes |
| F | no | no | KEM HW | 22 nm ASIC | ATP, power, energy |
| **Ours** | **yes** | **yes (NFQUEUE)** | **MQTT re-encrypt** | **Raspberry Pi 4** | **verdict ms + crypto ms + e2e** |

## Implications for journal figures (to beat their visual language)

- From **B-style:** offline CM / feature importance (we have `outputs/lgbm_based_on_subroto_vai/`).
- From **E-style:** stage latency bars (KEM / AES / Sign / total) + byte overhead of PQ MQTT message.
- **Unique to us:** architecture of two-stage path; e2e composition table; per-attack live timing.

## Next planning step

**Step 2:** Freeze working title + 2–3 contribution bullets that explicitly close the table above.
