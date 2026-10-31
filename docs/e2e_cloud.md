# End-to-end test: two client Pis, one gateway, PC as cloud

This does not replace the journal runs (reps 6–9). Cloud forwarding is off unless `GW_CLOUD_FORWARD=1`.

```
Client Pi A  ─┐
              ├─ MQTT :1883 ─ Gateway Pi (Stage 1 + Stage 2) ─ HTTPS :8443 ─ Windows PC
Client Pi B  ─┘                 same Wi-Fi hotspot
```

The PC is a LAN stand-in for a cloud receiver. It does not receive raw IP packets. It receives the existing Stage 2 envelope (ML-KEM-768, AES-256-GCM, ML-DSA-65) as an HTTPS POST. The firewall rules stay on port 1883, so this connection does not need `CLOUD_ALLOW_IP`.

Device-to-gateway keys are unchanged (`MASTER_SECRET`). The gateway signing key and the cloud KEM key are generated separately. Each private key stays on the machine that created it.

## PC + gateway cloud setup (automated)

**PC (Windows/WSL)** — one command:

```bash
python -m cloud.https_server
```

On start it calls `cloud.setup_pc`: detects the Wi-Fi IP, refreshes TLS/`.env.cloud`/portproxy when the IP changes, rebuilds `keys/for_gateway_pi.tar.gz`, then serves on port 8443.

**Gateway Pi** — after the tarball is on the Pi (scp, or set `GATEWAY_SSH=user@gateway-ip` in `.env.cloud` on the PC for auto-push):

```bash
python -m cloud.setup_gateway
sudo .venv/bin/python experiments/gateway_agent.py
```

`gateway_agent` also runs `setup_gateway` automatically if the tarball is present. Pasteable agent instructions: `docs/GATEWAY_PI_SETUP_PROMPT.md`.

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
python -m cloud.setup_pc
# or, if keys/env are already current:
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

**4. Client Pi B** (peer; do not run `client_runner.py` here):

Start this after the agent is up. It finds the gateway by the same UDP beacon as Pi A, waits until Pi A starts a session, then joins:

```bash
sudo .venv/bin/python experiments/extra_client.py --tag pi2
```

Optional: `--gateway <IP>`, `--session R1_rep11`, `--attacks`.

Pi B writes ground truth under `results/client/<session>/peers/pi2/` (`benign_conns.csv`, `benign_sends.csv`, `attack_windows.csv`, `meta.json`). After you pull both Pis’ results onto one machine, `experiments/analyze.py` labels flows from both client IPs.

## What the logs mean

`results/cloud/uplink.jsonl` is written on the PC. `event=accept` is the only new delivery. `event=duplicate` is a retry of the latest accepted `(device_id, seq)` and is not processed again. `event=replay` or `event=reject` is a failure. Periodic `event=resource` lines include `accept_per_s`, `delivery_ratio`, `mean_verify_decrypt_ns`, `rss_kb`, and `cpu_percent`, computed from messages this process has seen.

Each client publish carries `msg_id` (one id for that message), `t_publish_ns`, and `client_clock_offset_ns` (gateway clock minus the client clock, measured at session start). The same `msg_id` is in `benign_sends.csv`, the Stage 2 CSV, and every cloud decision. Set `GATEWAY_IP` on the PC, or leave it unset and the receiver uses the gateway UDP beacon. It pings the gateway agent every 30 s and logs `event=clock_sync` with `clock_offset_ns` (gateway clock minus the PC clock). On an accept, `t_e2e_ns` is cloud-accept time minus client-publish time after both stamps are moved onto the gateway clock. It is not a wide-area round trip, and it is absent until the first successful ping.

`results/cloud/replay_state.json` is the last accepted seq per device. It is replaced atomically while the process runs. Starting `python -m cloud.https_server` deletes that file first, so a new receiver does not keep the last campaign's sequences. Do not restart the receiver in the middle of a session.

`results/gateway/cloud_uplink.jsonl` is written on the gateway. Each `https_result` has:

- `msg_id` — the client publish id
- `t_e2e_ns` — the receiver's client-to-accept figure, when the clock offset was known
- `https_rtt_ns` — gateway clock, from the start of the POST to the response
- `t_verify_decrypt_ns` — PC clock, signature check plus KEM decapsulation plus AES-GCM
- `mqtt_to_ack_ns` — gateway clock, from MQTT receipt to the cloud response

The Stage 2 CSV does not include the HTTPS wait. The MQTT callback only queues the envelope.

Pi B’s flows are real MQTT, but the paper labeller only knows the controller Pi’s IP. Do not mix Pi B traffic into the journal tables.
