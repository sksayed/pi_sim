# Phase 4 — Three-Pi + cloud matrix (E1–E5 × 3 reps)

Does **not** touch paper reps 6–9. For a clean campaign use a fresh `--first-rep` (e.g. `30`) so sessions do not collide with archive/`E1_rep20`/`E1_rep25` attempts.

**Pi B is never idle.** It always joins every session (benign on E1, attacks on E2–E5).

IPS allow-list (E1/E3/E5, `allow_list=True`):
- Always: `127.0.0.1` (+ optional `CLOUD_ALLOW_IP`)
- **E1 / E3:** also Pi A (benign controller)
- **E1 only:** also Pi B when it registers (`pi_b=benign`) via `allow_ips_extra.txt`
- **E5:** remote Pis are **not** allow-listed (both may attack; IPS must be able to block)

## Matrix

| Exp | Pi A | Pi B command (after `--tag pi2 --session <id>`) | Gateway |
|---|---|---|---|
| E1 | Benign | *(no extra flags — benign publishers)* | IPS + allow-list + cloud |
| E2 | Benign | `--attacks-only --attack-slice all` | IDS + cloud |
| E3 | Benign | `--attacks-only --attack-slice all` | IPS + allow-list + cloud |
| E4 | Benign + attack slice `a` | `--attacks-only --attack-slice b` | IDS + cloud |
| E5 | Benign + attack slice `a` | `--attacks-only --attack-slice b` | IPS + allow-list + cloud |

E4/E5: `a ∪ b = all`, disjoint → same total attack volume as one full pass (E2/E3).

## Startup order (every session)

### 1. Windows PC
```bash
cd ~/journal_paper_proj/pi_sim && source .venv/bin/activate
python -m cloud.https_server
```

### 2. Gateway Pi
```bash
cd ~/Desktop/pi_project/pi_sim
sudo .venv/bin/python experiments/gateway_agent.py
```
(`GW_CLOUD_FORWARD=1` in `.env`)

### 3. Pi B — start once with `--auto` (recommended for full matrix)
```bash
sudo .venv/bin/python experiments/extra_client.py --tag pi2 --auto
```
Leave this running. For each Pi A session it reads `run` from the gateway agent and
applies the plan role (E1 benign, E2/E3 attacks-all, E4/E5 attacks-b) without restarting.

Manual one-shot (if not using `--auto`):
- E1: `... extra_client.py --tag pi2`
- E2/E3: `... --tag pi2 --attacks-only --attack-slice all`
- E4/E5: `... --tag pi2 --attacks-only --attack-slice b`

### 4. Pi A — full matrix (3 reps) or one experiment at a time
```bash
# Full E1–E5 × 3 (Pi B command changes per experiment — restart Pi B when Pi A prints it)
sudo .venv/bin/python experiments/client_runner.py --runs E1,E2,E3,E4,E5 --reps 3 --first-rep 30
```

One experiment:
```bash
sudo .venv/bin/python experiments/client_runner.py --runs E1 --reps 3 --first-rep 30
```

Pi A prints the exact Pi B command at session start.

## Outputs

- Pi A: `results/client/E*_rep*/`
- Pi B: `results/client/E*_rep*/peers/pi2/`
- Gateway: `results/gateway/E*_rep*/`
- Cloud: `results/cloud/uplink.jsonl`
- Gateway HTTPS: `results/gateway/cloud_uplink.jsonl`
