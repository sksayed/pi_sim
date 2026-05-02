# Gateway PQC Re-Encryption Pipeline Report

**Generated:** 2026-05-02 17:39:15  
**Source:** `reencrypt_metrics.csv + firewall_misses.jsonl`  

---

## 1. Executive Summary

The gateway re-encrypted **96 benign messages** using `ML-KEM-512` + `ML-DSA-44` (AES-256-GCM). Mean broker transit was **1.385 ms** and mean PQC re-encryption overhead was **0.168 ms**.

| Metric | Value |
|--------|-------|
| Messages re-encrypted | 96 |
| KEM algorithm | `ML-KEM-512` |
| Signature algorithm | `ML-DSA-44` |
| PQC mode | Real liboqs |
| Observation window | 17:37:04 → 17:38:02 |

## 2. Timing Breakdown

> All values in milliseconds (ms). **Broker transit** = `t_recv_ns − t_publish_ns` (includes broker + network latency). **Total gateway** = full handler wall time from `on_message` entry.

| Stage                           | N  | Mean     | Std      | P95      | Min      | Max      |
| ------------------------------- | -- | -------- | -------- | -------- | -------- | -------- |
| Broker transit (client→gateway) | 96 | 1.385 ms | 0.612 ms | 2.652 ms | 0.905 ms | 3.227 ms |
| KEM encapsulate                 | 96 | 0.050 ms | 0.010 ms | 0.064 ms | 0.038 ms | 0.108 ms |
| AES-256-GCM encrypt             | 96 | 0.028 ms | 0.053 ms | 0.025 ms | 0.018 ms | 0.536 ms |
| Signature sign                  | 96 | 0.089 ms | 0.036 ms | 0.167 ms | 0.049 ms | 0.215 ms |
| Total re-encrypt (KEM+AES+Sign) | 96 | 0.168 ms | 0.072 ms | 0.260 ms | 0.112 ms | 0.739 ms |
| Total gateway (on_message→done) | 96 | 0.450 ms | 0.569 ms | 0.512 ms | 0.318 ms | 5.970 ms |

## 3. Per-Device Timing

| Device ID            | N  | Transit Mean | Transit Std | Reencrypt Mean | Reencrypt Std | Total GW Mean |
| -------------------- | -- | ------------ | ----------- | -------------- | ------------- | ------------- |
| benign-burst-dc2419  | 66 | 1.358 ms     | 0.574 ms    | 0.164 ms       | 0.044 ms      | 0.394 ms      |
| benign-steady-59be62 | 30 | 1.444 ms     | 0.684 ms    | 0.176 ms       | 0.110 ms      | 0.576 ms      |

## 4. Firewall Misses — Attacks That Reached the Gateway

**Total missed attacks:** 50

> These messages had `is_attack=True` in the payload, meaning the attack client injected the label. The LightGBM firewall failed to classify or block the corresponding network flow before it reached the gateway. Use these records to identify model weaknesses.

### By Attack Label

| Attack Label | Count | Share  |
| ------------ | ----- | ------ |
| mqtt-flood   | 50    | 100.0% |

### By crypto_type Used (Spoofing Pattern)

| crypto_type | Count |
| ----------- | ----- |
| aes_gcm     | 50    |

### Last 10 Miss Events

| Time     | Attack Label | Device         | Seq      | crypto_type | Payload Preview                                              |
| -------- | ------------ | -------------- | -------- | ----------- | ------------------------------------------------------------ |
| 17:37:40 | mqtt-flood   | flood-attacker | 14022616 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:37:40 | mqtt-flood   | flood-attacker | 14022617 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:37:41 | mqtt-flood   | flood-attacker | 14022618 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:37:41 | mqtt-flood   | flood-attacker | 14022619 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:37:41 | mqtt-flood   | flood-attacker | 14022620 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:37:41 | mqtt-flood   | flood-attacker | 14022621 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:37:41 | mqtt-flood   | flood-attacker | 14022622 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:37:42 | mqtt-flood   | flood-attacker | 14022623 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:37:42 | mqtt-flood   | flood-attacker | 14022624 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:37:42 | mqtt-flood   | flood-attacker | 14022625 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |

## 5. Last 10 Re-Encrypted Messages

| Device               | Seq | Broker Transit | Re-Encrypt | Total GW |
| -------------------- | --- | -------------- | ---------- | -------- |
| benign-burst-dc2419  | 63  | 0.999 ms       | 0.135 ms   | 0.348 ms |
| benign-burst-dc2419  | 64  | 1.306 ms       | 0.251 ms   | 0.509 ms |
| benign-burst-dc2419  | 65  | 0.939 ms       | 0.221 ms   | 0.442 ms |
| benign-burst-dc2419  | 66  | 1.093 ms       | 0.143 ms   | 0.358 ms |
| benign-steady-59be62 | 25  | 1.443 ms       | 0.190 ms   | 0.438 ms |
| benign-steady-59be62 | 26  | 0.996 ms       | 0.174 ms   | 0.419 ms |
| benign-steady-59be62 | 27  | 2.709 ms       | 0.221 ms   | 0.465 ms |
| benign-steady-59be62 | 28  | 0.981 ms       | 0.151 ms   | 0.403 ms |
| benign-steady-59be62 | 29  | 1.103 ms       | 0.200 ms   | 0.414 ms |
| benign-steady-59be62 | 30  | 3.156 ms       | 0.134 ms   | 0.344 ms |

---

*Report generated by `scripts/parse_gateway_reencrypt.py` — MQTT IDS/IPS + PQC Benchmarking Framework.*
