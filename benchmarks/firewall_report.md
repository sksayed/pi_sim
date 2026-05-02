# MQTT Firewall Intrusion Detection Report

**Generated:** 2026-05-02 15:18:40  
**Source file:** `JSONL (52 verdicts) + .log (52 verdicts)`  
**Time range:** 15:06:19 → 15:18:30  

---

## 1. Executive Summary

The LightGBM-based MQTT firewall processed **349 packets** (408 log lines) and issued **53 flow-level verdicts**. Of these, **49 (92.5%) were classified as attacks** and **4 (7.5%) as benign**. Mean model confidence on attack flows was **0.9621**.

| Metric | Value |
|--------|-------|
| Total log lines | 408 |
| Total packets intercepted | 349 |
| Total flow verdicts | 53 |
| Attack verdicts | 49 (92.5%) |
| Benign verdicts | 4 (7.5%) |
| Observation window | 15:06:19 → 15:18:30 |

## 2. Attack Type Breakdown

| Attack Type             | Verdict Count | Share (%) |
| ----------------------- | ------------- | --------- |
| MQTT-DDoS-Connect_Flood | 15            | 28.3%     |
| TCP_IP-DDoS-UDP1        | 12            | 22.6%     |
| Recon-Port_Scan         | 12            | 22.6%     |
| benign                  | 4             | 7.5%      |
| MQTT-DDoS-Publish_Flood | 3             | 5.7%      |
| MQTT-DoS-Connect_Flood  | 3             | 5.7%      |
| ARP_Spoofing            | 3             | 5.7%      |
| TCP_IP-DDoS-SYN         | 1             | 1.9%      |

## 3. Model Confidence Statistics

Statistics computed over **attack-classified flows only**.

| Statistic | Value |
|-----------|-------|
| Sample size | 49 flows |
| Minimum confidence | 0.6199 |
| Maximum confidence | 1.0000 |
| Mean confidence | 0.9621 |
| Flows with confidence ≥ 0.90 | 39 (79.6%) |

## 4. Flow Statistics

| Metric | Min | Max | Mean |
|--------|-----|-----|------|
| Packets per flow | 3 | 10 | 6.2 |
| Bytes per flow | 0 | 2,900 | 737 |
| Flow duration (s) | 0.0005 | 28.1485 | 1.8504 |

## 5. Timing Performance — Per Attack Type

> **infer** = `model.predict()` only &nbsp;|&nbsp; **classify** = feature extraction + inference + decision &nbsp;|&nbsp; **inspect** = packet arrival → verdict (inline classifications only; 0 for background reaper-triggered flows)

| Attack Type             | N  | Infer Mean (ms) | Infer Std (ms) | Classify Mean (ms) | Classify Std (ms) | Inspect Mean (ms) | Inspect Std (ms) |
| ----------------------- | -- | --------------- | -------------- | ------------------ | ----------------- | ----------------- | ---------------- |
| ARP_Spoofing            | 3  | 0.761           | 0.347          | 1.874              | 1.031             | 0.000             | 0.000            |
| MQTT-DDoS-Connect_Flood | 15 | 0.450           | 0.022          | 1.060              | 0.056             | 1.285             | 0.119            |
| MQTT-DDoS-Publish_Flood | 3  | 0.411           | 0.034          | 0.984              | 0.051             | 1.258             | 0.144            |
| MQTT-DoS-Connect_Flood  | 3  | 0.446           | 0.011          | 1.107              | 0.038             | 0.000             | 0.000            |
| Recon-Port_Scan         | 12 | 1.328           | 1.029          | 2.692              | 1.681             | 0.000             | 0.000            |
| TCP_IP-DDoS-SYN         | 1  | 0.526           | 0.000          | 2.154              | 0.000             | 2.328             | 0.000            |
| TCP_IP-DDoS-UDP1        | 12 | 0.635           | 0.225          | 1.515              | 0.344             | 0.000             | 0.000            |
| benign                  | 4  | 0.451           | 0.013          | 1.065              | 0.055             | 1.277             | 0.177            |
| **Overall**             | 53 | 0.708           | 0.616          | 1.598              | 1.072             | 1.325             | 0.251            |

## 6. Top Attacker Flows

**23** distinct `(src_ip:src_port, attack_type)` flows detected.

| Source (ip:port)     | Classified Attack Type  | Verdict Count |
| -------------------- | ----------------------- | ------------- |
| 127.0.0.1:59169      | Recon-Port_Scan         | 11            |
| 127.0.0.1:1883       | MQTT-DDoS-Connect_Flood | 10            |
| 127.0.0.1:59169      | MQTT-DDoS-Connect_Flood | 5             |
| 127.0.0.1:1883       | MQTT-DoS-Connect_Flood  | 2             |
| 10.255.255.254:44717 | TCP_IP-DDoS-UDP1        | 2             |
| 192.168.208.1:137    | ARP_Spoofing            | 2             |
| 127.0.0.1:59169      | TCP_IP-DDoS-SYN         | 1             |
| 10.255.255.254:46222 | TCP_IP-DDoS-UDP1        | 1             |
| 127.0.0.1:39933      | MQTT-DDoS-Publish_Flood | 1             |
| 127.0.0.1:60737      | MQTT-DDoS-Publish_Flood | 1             |
| 10.255.255.254:59019 | TCP_IP-DDoS-UDP1        | 1             |
| 127.0.0.1:46679      | MQTT-DDoS-Publish_Flood | 1             |
| 10.255.255.254:46725 | TCP_IP-DDoS-UDP1        | 1             |
| 127.0.0.1:60737      | MQTT-DoS-Connect_Flood  | 1             |
| 127.0.0.1:1883       | Recon-Port_Scan         | 1             |
| 10.255.255.254:49492 | TCP_IP-DDoS-UDP1        | 1             |
| 10.255.255.254:58290 | TCP_IP-DDoS-UDP1        | 1             |
| 10.255.255.254:55930 | TCP_IP-DDoS-UDP1        | 1             |
| 10.255.255.254:47186 | ARP_Spoofing            | 1             |
| 10.255.255.254:46307 | TCP_IP-DDoS-UDP1        | 1             |

*...and 3 additional flows not shown.*

## 7. Last 10 Verdicts

| Time     | Verdict | Attack Type      | Confidence | Source               | Destination         | Pkts | Bytes |
| -------- | ------- | ---------------- | ---------- | -------------------- | ------------------- | ---- | ----- |
| 15:14:16 | ATTACK  | TCP_IP-DDoS-UDP1 | 0.9559     | 10.255.255.254:46307 | 10.255.255.254:53   | 4    | 252   |
| 15:14:30 | ATTACK  | Recon-Port_Scan  | 1.0000     | 127.0.0.1:59169      | 127.0.0.1:1883      | 3    | 4     |
| 15:14:51 | ATTACK  | TCP_IP-DDoS-UDP1 | 0.8766     | 10.255.255.254:58380 | 10.255.255.254:53   | 4    | 350   |
| 15:14:54 | ATTACK  | TCP_IP-DDoS-UDP1 | 0.8827     | 10.255.255.254:42228 | 10.255.255.254:53   | 4    | 202   |
| 15:15:30 | ATTACK  | Recon-Port_Scan  | 1.0000     | 127.0.0.1:59169      | 127.0.0.1:1883      | 3    | 4     |
| 15:15:54 | ATTACK  | TCP_IP-DDoS-UDP1 | 0.9523     | 10.255.255.254:38981 | 10.255.255.254:53   | 4    | 252   |
| 15:16:30 | ATTACK  | Recon-Port_Scan  | 1.0000     | 127.0.0.1:59169      | 127.0.0.1:1883      | 3    | 4     |
| 15:17:30 | ATTACK  | Recon-Port_Scan  | 1.0000     | 127.0.0.1:59169      | 127.0.0.1:1883      | 3    | 4     |
| 15:17:39 | ATTACK  | ARP_Spoofing     | 0.8956     | 192.168.208.1:137    | 192.168.223.255:137 | 3    | 150   |
| 15:18:30 | ATTACK  | Recon-Port_Scan  | 1.0000     | 127.0.0.1:59169      | 127.0.0.1:1883      | 3    | 4     |

---

*Report generated by `scripts/parse_firewall_logs.py` — MQTT IDS/IPS Benchmarking Framework.*
