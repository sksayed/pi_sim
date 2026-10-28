# Prompt to paste on the gateway Pi (Cursor / Claude / terminal assistant)

Copy everything below the line into an agent chat **on the gateway Raspberry Pi**, from the repo root `~/Desktop/pi_project/pi_sim`.

---

You are on the **gateway Raspberry Pi** for the pi_sim project.

## Goal

Install the HTTPS cloud uplink bundle from the Windows PC so I can run only:

```bash
sudo .venv/bin/python experiments/gateway_agent.py
```

and Stage 2 will POST envelopes to the PC cloud receiver. Do not rewrite IDS/IPS, Stage 2 crypto, or the journal paper.

## What I will put on this Pi

The PC creates `keys/for_gateway_pi.tar.gz`. I will copy it into this repo root (or `keys/`), for example:

```bash
# run on the PC after: python -m cloud.https_server   # or cloud.setup_pc
scp keys/for_gateway_pi.tar.gz <this-pi-user>@<this-pi-ip>:~/Desktop/pi_project/pi_sim/
```

If the tarball is not here yet, tell me exactly what to run on the PC and wait.

## What you must do on this Pi

1. `cd ~/Desktop/pi_project/pi_sim` and `git pull` so `cloud/setup_gateway.py` exists (branch `main`).
2. Ensure `.venv` exists and `pip install -r requirements.txt` if needed. liboqs is required when `GW_CLOUD_FORWARD=1`.
3. Run:

```bash
.venv/bin/python -m cloud.setup_gateway
```

   That script must:
   - find `for_gateway_pi.tar.gz` or `for_gateway_pi/`
   - install `keys/cloud`, `keys/gateway`, `keys/tls/cloud.crt`, `keys/trust.json`
   - merge `CLOUD_*` / `GW_CLOUD_FORWARD=1` into `.env` (replace old CLOUD lines, do not duplicate forever)
   - `chmod 600 keys/gateway/sig.sk`
   - try connecting to the host in `CLOUD_URL`

4. Confirm `.env` contains `GW_CLOUD_FORWARD=1` and `CLOUD_URL=https://<PC_WIFI_IP>:8443/v1/envelope` matching the PC.
5. From this Pi: `ping -c 2 <PC_WIFI_IP>` and say if it fails.
6. Do **not** start a long experiment. Print the one command I should run:

```bash
sudo .venv/bin/python experiments/gateway_agent.py
```

## Rules

- Do not commit `.env`, `keys/*.sk`, or TLS private keys.
- Do not overwrite paper result sessions (reps 6–9).
- If `.env` is root-owned and not writable, fix permissions or merge with sudo, then continue.
- If setup_gateway is missing, create it to match the PC repo behaviour described in `docs/e2e_cloud.md`.

---

## Optional fully automatic push from the PC

On the PC, in `.env.cloud` (after SSH keys work):

```bash
GATEWAY_SSH=sayed@<gateway-pi-ip>
GATEWAY_SSH_DIR=~/Desktop/pi_project/pi_sim
```

Then `python -m cloud.https_server` rebuilds the bundle and scp+installs it on the Pi when the IP changes.
