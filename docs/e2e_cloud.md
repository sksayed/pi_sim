# End-to-end test: two client Pis, one gateway, PC as cloud

This does not replace the journal runs (reps 6–9). Cloud forwarding is off unless `GW_CLOUD_FORWARD=1`.

```
Client Pi A  ─┐
              ├─ MQTT :1883 ─ Gateway Pi (Stage 1 + Stage 2) ─ HTTPS :8443 ─ Windows PC
Client Pi B  ─┘                 same Wi-Fi hotspot
```

The PC is a LAN stand-in for a cloud receiver. It does not receive raw IP packets. It receives the existing Stage 2 envelope (ML-KEM-768, AES-256-GCM, ML-DSA-65) as an HTTPS POST. The firewall rules stay on port 1883, so this connection does not need `CLOUD_ALLOW_IP`.

Device-to-gateway keys are unchanged (`MASTER_SECRET`). The gateway signing key and the cloud KEM key are generated separately. Each private key stays on the machine that created it.

## One-time keys and certificate

On the **PC**, from the repo root, with liboqs installed:

```bash
python -m cloud.provision --role cloud --out keys/cloud
python -m cloud.provision --tls --ip <PC_HOTSPOT_IP> --out keys/tls
```

On the **gateway Pi**:

```bash
python -m cloud.provision --role gateway --out keys/gateway
```

Copy `keys/cloud/kem.pk` and `keys/cloud/kem.alg` to the gateway. Copy `keys/gateway/sig.pk` and `keys/gateway/sig.alg` to the PC. Copy `keys/tls/cloud.crt` to the gateway. Leave `kem.sk` on the PC and `sig.sk` on the gateway.

Compare the SHA-256 printed at generation with the file you copied, then pin it. Do this on each machine for the public key it received:

```bash
python -m cloud.provision --pin keys/cloud/kem.pk --label cloud_kem_pk --trust keys/trust.json
python -m cloud.provision --pin keys/gateway/sig.pk --label gateway_sig_pk --trust keys/trust.json
```

The fingerprint must match the one printed where the key was generated. A mismatch refuses to start.

## Gateway `.env`

```
GW_CLOUD_FORWARD=1
CLOUD_URL=https://<PC_HOTSPOT_IP>:8443/v1/envelope
GATEWAY_SIG_SK=keys/gateway/sig.sk
GATEWAY_CLOUD_PK=keys/cloud/kem.pk
GATEWAY_TRUST=keys/trust.json
CLOUD_TLS_CERT=keys/tls/cloud.crt
```

`CLOUD_URL` must use the same IP that is in the certificate. TLS hostname checks stay on.

## PC `.env`

```
CLOUD_KEM_SK=keys/cloud/kem.sk
CLOUD_GATEWAY_PK=keys/gateway/sig.pk
CLOUD_TRUST=keys/trust.json
CLOUD_TLS_CERT=keys/tls/cloud.crt
CLOUD_TLS_KEY=keys/tls/cloud.key
CLOUD_PORT=8443
```

## One-message check on one machine

```bash
python cloud/e2e_selftest.py
```

This uses port 18443 and a temporary directory. It is a wiring check. It does not produce a paper result.

## Run on the hotspot

**1. PC**

```bash
python -m cloud.https_server
```

**2. Gateway Pi** (agent, as before):

```bash
cd ~/Desktop/pi_project/pi_sim
sudo .venv/bin/python experiments/gateway_agent.py
```

The log should contain `Cloud HTTPS ON`. With `GW_CLOUD_FORWARD=0` the gateway behaves as in the journal runs.

**3. Client Pi A** (session controller):

```bash
sudo .venv/bin/python experiments/client_runner.py --runs R1 --reps 1 --first-rep 11
```

Use a new rep number (11 or higher). Do not reuse reps 6–9.

**4. Client Pi B** (traffic only; do not run `client_runner.py` here):

```bash
sudo .venv/bin/python experiments/extra_client.py --gateway <GATEWAY_PI_IP> --tag pi2
```

Add `--attacks` on Pi B if that Pi should send the attack list once.

## What the logs mean

`results/cloud/uplink.jsonl` is written on the PC. `event=accept` is the only new delivery. `event=duplicate` is a retry of the latest accepted `(device_id, seq)` and is not processed again. `event=replay` or `event=reject` is a failure. Periodic `event=resource` lines include `accept_per_s`, `delivery_ratio`, `mean_verify_decrypt_ns`, `rss_kb`, and `cpu_percent`, computed from messages this process has seen.

`results/cloud/replay_state.json` is the last accepted seq per device. It is replaced atomically and reloaded on startup.

`results/gateway/cloud_uplink.jsonl` is written on the gateway. Each `https_result` has:

- `https_rtt_ns` — gateway clock, from the start of the POST to the response
- `t_verify_decrypt_ns` — PC clock, signature check plus KEM decapsulation plus AES-GCM
- `mqtt_to_ack_ns` — gateway clock, from MQTT receipt to the cloud response

The Stage 2 CSV does not include the HTTPS wait. The MQTT callback only queues the envelope.

Pi B’s flows are real MQTT, but the paper labeller only knows the controller Pi’s IP. Do not mix Pi B traffic into the journal tables.
