# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

This is a **post-quantum cryptography (PQC) benchmarking framework** for IoT, designed to run on Raspberry Pi networks. It simulates multi-node MQTT communication where clients encrypt sensor data with various classical and PQC schemes, and a gateway decrypts and records nanosecond-precision performance metrics for academic research.

## Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Copy and fill in secrets
cp .env.example .env
# Required: MASTER_SECRET (64-char hex), GATEWAY_IP, GATEWAY_PORT=1883, PUBLISH_INTERVAL=2
```

For real PQC (vs. simulation fallback):
```bash
sudo apt install -y cmake ninja-build libssl-dev
# Build liboqs, then:
pip install git+https://github.com/open-quantum-safe/liboqs-python.git
```

## Common Commands

```bash
# Start gateway (must be running before clients)
python gateway/gateway.py

# Run demo clients (increasing crypto complexity)
python client/client_a.py   # AES-256-GCM only
python client/client_b.py   # Kyber-512 + AES-256-GCM
python client/client_c.py   # Kyber-768 + Dilithium-3 + AES-256-GCM

# Run single research profile
python client/profile_1_baseline.py   # ML-KEM-512 baseline
python client/profile_4_standard.py   # ML-KEM-768 + ML-DSA-65 (NIST standard)

# Run full benchmark matrix (30 scenarios × ~600 messages each)
python scripts/run_client_benchmark_matrix.py
python scripts/run_client_benchmark_matrix.py --profiles pqc --per-scenario 200

# Analyze results
python scripts/analyze_pqc_benchmarks.py \
    --client benchmarks/client/pqc_metrics.csv \
    --gateway benchmarks/gateway/pqc_metrics_gateway.csv \
    -o benchmarks/analysis_report.txt

# Smoke test all client types
python scripts/test_all_features.py
```

## Architecture

The system has three tiers:

**Client → MQTT Broker (Mosquitto, port 1883) → Gateway**

All clients publish to `nodes/{device_id}/data` with JSON payloads containing `crypto_type`, `nonce`, `ciphertext`, and optionally `kem_ciphertext` and `signature`. The gateway subscribes to `nodes/+/data` and dispatches to the appropriate decryption handler.

### Key Derivation (Critical Design Point)

Every key is derived independently on both client and gateway from `MASTER_SECRET` via HKDF-SHA256 — no key exchange occurs over MQTT. The `info` string scopes keys to algorithm and device:
- `aes:client-a` → AES-256 key for demo client A
- `kem:Kyber512:gw` → Gateway's Kyber-512 keypair (same public key derived on all clients)
- `ecdsa-p256:profile-1-01` → Per-device ECDSA signing key

This means `shared/key_manager.py` is the single source of truth for all crypto. Changes there affect both sides.

### Client Hierarchy

```
BaseClient (client/base_client.py)
├── ClientA / ClientB / ClientC  — demo clients, simple crypto
└── ResearchProfileClient (client/research_base_client.py)
    ├── Profile1 through Profile7  — PQC profiles (ML-KEM, ML-DSA, BIKE, FrodoKEM, Falcon, SLH-DSA)
    └── ClassicResearchClientBase (client/classic_research_client.py)
        ├── ProfileClassicAes
        ├── ProfileClassicChaCha
        └── ProfileClassicEcdhEcdsa
```

`BaseClient` handles MQTT connect/loop/publish and generates `session_id` + monotonic `seq`. Subclasses implement `build_message(seq)`.

`ResearchProfileClient` adds the `@benchmark_pqc` decorator, client tagging (CLIENT_TAG env var for multi-Pi runs), and structured KEM+signature+AES pipeline.

### Gateway Dispatch

`gateway/gateway.py` routes on `crypto_type` field in the JSON payload:
- `aes_gcm` → `handle_aes_gcm()`
- `kyber_kem_aes` → `handle_kyber_kem_aes()`
- `pqc_research_profile` → `handle_pqc_research_profile()` (all 7 PQC profiles)
- `classic_aes` / `classic_chacha` / `classic_ecdh_ecdsa` → classical handlers

Replay protection: gateway tracks `(device_id, session_id) → last_seq` and rejects `seq <= last_seq`.

### Benchmarking Infrastructure

`shared/metrics.py` provides the `@benchmark_pqc` decorator. It captures:
- Wall-clock time (nanoseconds) for each sub-operation (KEM encap/decap, sign/verify, AES encrypt/decrypt)
- CPU time delta (user + sys, nanoseconds via `resource` module)
- RSS memory delta (KB via `psutil`)

Results are written to CSV via a thread-safe queue to minimize timing perturbation. Default paths:
- Client: `benchmarks/client/pqc_metrics.csv`
- Gateway: `benchmarks/gateway/pqc_metrics_gateway.csv`

Override with `BENCH_CSV_PATH` / `GATEWAY_BENCH_CSV_PATH` env vars.

### Simulation vs. Real PQC

`shared/key_manager.py` detects `import oqs` at runtime. If liboqs-python is unavailable, all KEM/signature operations fall back to deterministic stubs using HKDF-derived bytes. The MQTT pipeline works end-to-end in simulation mode but provides no real security — used for testing when liboqs is not installed.

### Firewall (Optional, feature/ips_implementation)

`firewall/mqtt_firewall.py` implements a LightGBM-based MQTT intrusion detection/prevention system using NetfilterQueue. Controlled entirely via environment variables (`FW_QUEUE_NUM`, `FW_MODEL_PATH`, `FW_ATTACK_THRESHOLD`, `FW_BLOCK_VERDICT`, etc.). The trained model is at `firewall/lightgbm_model.txt`.

## Research Profiles Summary

| Profile | KEM | Signature | Security Level |
|---------|-----|-----------|----------------|
| 1 (Baseline) | ML-KEM-512 | ML-DSA-44 | NIST L1 (128-bit) |
| 2 (Sig-Min) | ML-KEM-512 | Falcon-512 | NIST L1 |
| 3 (KEM-Div) | BIKE-L1 | ML-DSA-44 | NIST L1 |
| 4 (Standard) | ML-KEM-768 | ML-DSA-65 | NIST L3 (192-bit) |
| 5 (Hybrid) | FrodoKEM-640 | ML-DSA-65 | NIST L3 conservative |
| 6 (High-Sec) | ML-KEM-768 | SLH-DSA-SHAKE-128s | NIST L3 |
| 7 (Extreme) | ML-KEM-1024 | SLH-DSA-SHAKE-256s | NIST L5 (256-bit) |
| Classic-AES | — (AES-256-GCM only) | — | Symmetric baseline |
| Classic-ChaCha | — (ChaCha20-Poly1305) | — | Symmetric baseline |
| Classic-ECDH | ECDH P-256 | ECDSA P-256 | Classical asymmetric |

## Payload Sizes

Three payload sizes are benchmarked: 5KB (default), 10KB, 102400B (100KB). Set via `PAYLOAD_TARGET_BYTES` env var. `shared/payload_pad.py` pads JSON plaintext to the target size before encryption.
