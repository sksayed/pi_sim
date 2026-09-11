# MQTT Firewall Intrusion Detection Report

**Generated:** 2026-05-03 10:53:30  
**Source file:** `JSONL (887 verdicts) + .log (887 verdicts)`  
**Time range:** 10:42:43 → 10:53:29  

---

## 1. Executive Summary

The LightGBM-based MQTT firewall processed **4,531 packets** (5,686 log lines) and issued **893 flow-level verdicts**. Of these, **893 (100.0%) were classified as attacks** and **0 (0.0%) as benign**. Mean model confidence on attack flows was **0.9974**.

| Metric | Value |
|--------|-------|
| Total log lines | 5,686 |
| Total packets intercepted | 4,531 |
| Total flow verdicts | 893 |
| Attack verdicts | 893 (100.0%) |
| Benign verdicts | 0 (0.0%) |
| Observation window | 10:42:43 → 10:53:29 |

## 2. Attack Type Breakdown

| Attack Type             | Verdict Count | Share (%) |
| ----------------------- | ------------- | --------- |
| MQTT-DoS-Connect_Flood  | 796           | 89.1%     |
| Recon-OS_Scan           | 28            | 3.1%      |
| MQTT-DDoS-Connect_Flood | 16            | 1.8%      |
| TCP_IP-DDoS-SYN         | 13            | 1.5%      |
| MQTT-DDoS-Publish_Flood | 13            | 1.5%      |
| TCP_IP-DDoS-UDP1        | 12            | 1.3%      |
| MQTT-DoS-Publish_Flood  | 8             | 0.9%      |
| TCP_IP-DDoS-TCP         | 4             | 0.4%      |
| ARP_Spoofing            | 2             | 0.2%      |
| Recon-Port_Scan         | 1             | 0.1%      |

## 3. Model Confidence Statistics

Statistics computed over **attack-classified flows only**.

| Statistic | Value |
|-----------|-------|
| Sample size | 893 flows |
| Minimum confidence | 0.6199 |
| Maximum confidence | 1.0000 |
| Mean confidence | 0.9974 |
| Flows with confidence ≥ 0.90 | 880 (98.5%) |

## 4. Flow Statistics

| Metric | Min | Max | Mean |
|--------|-----|-----|------|
| Packets per flow | 3 | 10 | 4.6 |
| Bytes per flow | 0 | 31,712 | 236 |
| Flow duration (s) | 0.0004 | 95.9162 | 5.5514 |

## 5. Timing Performance — Per Attack Type

> **infer** = `model.predict()` only &nbsp;|&nbsp; **classify** = feature extraction + inference + decision &nbsp;|&nbsp; **inspect** = packet arrival → verdict (inline classifications only; 0 for background reaper-triggered flows)

| Attack Type             | N   | Infer Mean (ms) | Infer Std (ms) | Classify Mean (ms) | Classify Std (ms) | Inspect Mean (ms) | Inspect Std (ms) |
| ----------------------- | --- | --------------- | -------------- | ------------------ | ----------------- | ----------------- | ---------------- |
| ARP_Spoofing            | 2   | 1.391           | 0.891          | 2.157              | 0.886             | 0.000             | 0.000            |
| MQTT-DDoS-Connect_Flood | 16  | 0.968           | 1.022          | 1.958              | 1.565             | 2.521             | 1.609            |
| MQTT-DDoS-Publish_Flood | 13  | 0.699           | 0.806          | 1.467              | 1.362             | 1.850             | 1.378            |
| MQTT-DoS-Connect_Flood  | 796 | 0.396           | 0.232          | 0.871              | 0.444             | 1.151             | 0.613            |
| MQTT-DoS-Publish_Flood  | 8   | 0.474           | 0.050          | 1.189              | 0.209             | 1.379             | 0.222            |
| Recon-OS_Scan           | 28  | 0.762           | 0.897          | 1.439              | 1.336             | 1.571             | 1.324            |
| Recon-Port_Scan         | 1   | 4.391           | 0.000          | 7.977              | 0.000             | 8.207             | 0.000            |
| TCP_IP-DDoS-SYN         | 13  | 0.689           | 0.705          | 1.491              | 1.159             | 1.713             | 1.204            |
| TCP_IP-DDoS-TCP         | 4   | 0.438           | 0.072          | 0.963              | 0.199             | 1.286             | 0.215            |
| TCP_IP-DDoS-UDP1        | 12  | 0.461           | 0.094          | 1.161              | 0.377             | 1.164             | 0.256            |
| **Overall**             | 893 | 0.435           | 0.377          | 0.944              | 0.652             | 1.201             | 0.741            |

## 6. Top Attacker Flows

**265** distinct `(src_ip:src_port, attack_type)` flows detected.

| Source (ip:port)     | Classified Attack Type  | Verdict Count |
| -------------------- | ----------------------- | ------------- |
| 127.0.0.1:1883       | MQTT-DoS-Connect_Flood  | 608           |
| 127.0.0.1:1883       | MQTT-DDoS-Connect_Flood | 16            |
| 127.0.0.1:1883       | TCP_IP-DDoS-TCP         | 4             |
| 127.0.0.1:56319      | MQTT-DoS-Connect_Flood  | 2             |
| 127.0.0.1:46415      | MQTT-DoS-Connect_Flood  | 2             |
| 127.0.0.1:1883       | MQTT-DoS-Publish_Flood  | 2             |
| 127.0.0.1:49864      | MQTT-DoS-Connect_Flood  | 1             |
| 127.0.0.1:56039      | TCP_IP-DDoS-SYN         | 1             |
| 10.255.255.254:34690 | TCP_IP-DDoS-UDP1        | 1             |
| 10.255.255.254:49859 | ARP_Spoofing            | 1             |
| 10.255.255.254:38523 | TCP_IP-DDoS-UDP1        | 1             |
| 127.0.0.1:43109      | TCP_IP-DDoS-SYN         | 1             |
| 127.0.0.1:44089      | TCP_IP-DDoS-SYN         | 1             |
| 127.0.0.1:59273      | MQTT-DDoS-Publish_Flood | 1             |
| 127.0.0.1:54611      | MQTT-DDoS-Publish_Flood | 1             |
| 127.0.0.1:48951      | MQTT-DDoS-Publish_Flood | 1             |
| 127.0.0.1:58563      | MQTT-DDoS-Publish_Flood | 1             |
| 127.0.0.1:42561      | TCP_IP-DDoS-SYN         | 1             |
| 127.0.0.1:56951      | MQTT-DDoS-Publish_Flood | 1             |
| 10.255.255.254:41499 | TCP_IP-DDoS-UDP1        | 1             |

*...and 245 additional flows not shown.*

## 7. Last 10 Verdicts

| Time     | Verdict | Attack Type             | Confidence | Source          | Destination     | Pkts | Bytes  |
| -------- | ------- | ----------------------- | ---------- | --------------- | --------------- | ---- | ------ |
| 10:52:05 | ATTACK  | MQTT-DDoS-Connect_Flood | 1.0000     | 127.0.0.1:1883  | 127.0.0.1:47041 | 8    | 31,712 |
| 10:52:20 | ATTACK  | MQTT-DDoS-Connect_Flood | 1.0000     | 127.0.0.1:1883  | 127.0.0.1:38869 | 8    | 40     |
| 10:53:16 | ATTACK  | MQTT-DoS-Connect_Flood  | 1.0000     | 127.0.0.1:1883  | 127.0.0.1:54395 | 3    | 10     |
| 10:53:16 | ATTACK  | MQTT-DDoS-Connect_Flood | 1.0000     | 127.0.0.1:1883  | 127.0.0.1:47041 | 3    | 9,041  |
| 10:53:22 | ATTACK  | MQTT-DoS-Connect_Flood  | 1.0000     | 127.0.0.1:1883  | 127.0.0.1:56203 | 3    | 0      |
| 10:53:22 | ATTACK  | MQTT-DoS-Connect_Flood  | 1.0000     | 127.0.0.1:1883  | 127.0.0.1:34063 | 3    | 0      |
| 10:53:23 | ATTACK  | MQTT-DoS-Connect_Flood  | 1.0000     | 127.0.0.1:1883  | 127.0.0.1:34063 | 3    | 0      |
| 10:53:23 | ATTACK  | MQTT-DoS-Connect_Flood  | 1.0000     | 127.0.0.1:1883  | 127.0.0.1:56203 | 3    | 0      |
| 10:53:28 | ATTACK  | MQTT-DoS-Connect_Flood  | 1.0000     | 127.0.0.1:1883  | 127.0.0.1:38869 | 3    | 10     |
| 10:53:29 | ATTACK  | TCP_IP-DDoS-SYN         | 0.9954     | 127.0.0.1:53901 | 127.0.0.1:1883  | 10   | 86     |

---

*Report generated by `scripts/parse_firewall_logs.py` — MQTT IDS/IPS Benchmarking Framework.*
