# Gateway PQC Re-Encryption Pipeline Report

**Generated:** 2026-05-02 17:30:07  
**Source:** `reencrypt_metrics.csv + firewall_misses.jsonl`  

---

## 1. Executive Summary

The gateway re-encrypted **605 benign messages** using `ML-KEM-512` + `ML-DSA-44` (AES-256-GCM). Mean broker transit was **13.202 ms** and mean PQC re-encryption overhead was **1.810 ms**.

| Metric | Value |
|--------|-------|
| Messages re-encrypted | 605 |
| KEM algorithm | `ML-KEM-512` |
| Signature algorithm | `ML-DSA-44` |
| PQC mode | Real liboqs |
| Observation window | 14:37:04 → 17:27:18 |

## 2. Timing Breakdown

> All values in milliseconds (ms). **Broker transit** = `t_recv_ns − t_publish_ns` (includes broker + network latency). **Total gateway** = full handler wall time from `on_message` entry.

| Stage                           | N   | Mean      | Std       | P95       | Min      | Max         |
| ------------------------------- | --- | --------- | --------- | --------- | -------- | ----------- |
| Broker transit (client→gateway) | 597 | 13.202 ms | 71.045 ms | 19.337 ms | 0.173 ms | 1543.454 ms |
| KEM encapsulate                 | 605 | 0.441 ms  | 0.794 ms  | 0.916 ms  | 0.038 ms | 10.912 ms   |
| AES-256-GCM encrypt             | 605 | 0.119 ms  | 0.645 ms  | 0.172 ms  | 0.018 ms | 15.712 ms   |
| Signature sign                  | 605 | 1.250 ms  | 1.847 ms  | 3.384 ms  | 0.049 ms | 22.860 ms   |
| Total re-encrypt (KEM+AES+Sign) | 605 | 1.810 ms  | 2.248 ms  | 5.095 ms  | 0.112 ms | 23.786 ms   |
| Total gateway (on_message→done) | 605 | 3.819 ms  | 11.579 ms | 8.519 ms  | 0.318 ms | 277.583 ms  |

## 3. Per-Device Timing

| Device ID            | N   | Transit Mean | Transit Std | Reencrypt Mean | Reencrypt Std | Total GW Mean |
| -------------------- | --- | ------------ | ----------- | -------------- | ------------- | ------------- |
| benign-burst-dc2419  | 66  | 1.358 ms     | 0.574 ms    | 0.164 ms       | 0.044 ms      | 0.394 ms      |
| benign-burst-f12ca2  | 194 | 14.019 ms    | 37.095 ms   | 2.613 ms       | 2.933 ms      | 4.787 ms      |
| benign-mixed-fdf5f0  | 153 | 20.438 ms    | 126.499 ms  | 1.838 ms       | 1.445 ms      | 3.536 ms      |
| benign-steady-59be62 | 30  | 1.444 ms     | 0.684 ms    | 0.176 ms       | 0.110 ms      | 0.576 ms      |
| benign-steady-884c02 | 162 | 11.728 ms    | 41.394 ms   | 1.794 ms       | 2.054 ms      | 4.924 ms      |

## 4. Firewall Misses — Attacks That Reached the Gateway

**Total missed attacks:** 30

> These messages had `is_attack=True` in the payload, meaning the attack client injected the label. The LightGBM firewall failed to classify or block the corresponding network flow before it reached the gateway. Use these records to identify model weaknesses.

### By Attack Label

| Attack Label | Count | Share  |
| ------------ | ----- | ------ |
| mqtt-flood   | 30    | 100.0% |

### By crypto_type Used (Spoofing Pattern)

| crypto_type | Count |
| ----------- | ----- |
| aes_gcm     | 30    |

### Last 10 Miss Events

| Time     | Attack Label | Device         | Seq     | crypto_type | Payload Preview                                              |
| -------- | ------------ | -------------- | ------- | ----------- | ------------------------------------------------------------ |
| 17:22:19 | mqtt-flood   | flood-attacker | 7112288 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:22:20 | mqtt-flood   | flood-attacker | 7112289 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:22:21 | mqtt-flood   | flood-attacker | 7112290 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:22:22 | mqtt-flood   | flood-attacker | 7112291 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:22:23 | mqtt-flood   | flood-attacker | 7112292 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:22:24 | mqtt-flood   | flood-attacker | 7112293 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:22:25 | mqtt-flood   | flood-attacker | 7112294 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:22:26 | mqtt-flood   | flood-attacker | 7112295 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:22:27 | mqtt-flood   | flood-attacker | 7112296 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |
| 17:22:28 | mqtt-flood   | flood-attacker | 7112297 | aes_gcm     | {"device_id": "flood-attacker", "crypto_type": "aes_gcm", "s |

## 5. Last 10 Re-Encrypted Messages

| Device               | Seq | Broker Transit | Re-Encrypt | Total GW  |
| -------------------- | --- | -------------- | ---------- | --------- |
| benign-burst-f12ca2  | 191 | 9.173 ms       | 2.246 ms   | 4.500 ms  |
| benign-mixed-fdf5f0  | 151 | 8.381 ms       | 10.350 ms  | 11.662 ms |
| benign-burst-f12ca2  | 192 | 15.763 ms      | 2.356 ms   | 3.410 ms  |
| benign-burst-f12ca2  | 193 | 14.828 ms      | 19.162 ms  | 27.323 ms |
| benign-burst-f12ca2  | 194 | 0.688 ms       | 1.337 ms   | 9.516 ms  |
| benign-steady-884c02 | 160 | 5.707 ms       | 1.425 ms   | 2.650 ms  |
| benign-mixed-fdf5f0  | 152 | 6.461 ms       | 0.880 ms   | 2.257 ms  |
| benign-steady-884c02 | 161 | 5.891 ms       | 2.257 ms   | 3.630 ms  |
| benign-mixed-fdf5f0  | 153 | 6.511 ms       | 0.985 ms   | 2.447 ms  |
| benign-steady-884c02 | 162 | 5.999 ms       | 1.057 ms   | 2.282 ms  |

---

*Report generated by `scripts/parse_gateway_reencrypt.py` — MQTT IDS/IPS + PQC Benchmarking Framework.*
