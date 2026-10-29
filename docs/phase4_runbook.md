# Phase 4 — Three-Pi + cloud matrix (E1–E5 × 3 reps)

Does **not** touch paper reps 6–9. For a clean campaign use `--first-rep 20` (sessions `E1_rep20` …). Older interrupted `E*_rep12/13` can stay in git as archive.

**Pi B is never idle.** It always joins every session (benign on E1, attacks on E2–E5).

IPS cells (E1, E3, E5) use `FIXED_FW_SETTINGS` and **allow_list=True** (controller Pi A IP).

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

### 3. Pi B — always start (waits for session)
**E1**
```bash
sudo .venv/bin/python experiments/extra_client.py --tag pi2
```

**E2 / E3**
```bash
sudo .venv/bin/python experiments/extra_client.py --tag pi2 --attacks-only --attack-slice all
```

**E4 / E5**
```bash
sudo .venv/bin/python experiments/extra_client.py --tag pi2 --attacks-only --attack-slice b
```

Optional: add `--session E1_rep20` to pin the name.

### 4. Pi A — one experiment at a time (recommended)
```bash
sudo .venv/bin/python experiments/client_runner.py --runs E1 --reps 1 --first-rep 20
```

Then E2_rep20, E3_rep20, … after each succeeds. Full matrix later:
```bash
sudo .venv/bin/python experiments/client_runner.py --runs E1,E2,E3,E4,E5 --reps 3 --first-rep 20
```

Pi A prints the exact Pi B command at session start.

## Outputs

- Pi A: `results/client/E*_rep*/`
- Pi B: `results/client/E*_rep*/peers/pi2/`
- Gateway: `results/gateway/E*_rep*/`
- Cloud: `results/cloud/uplink.jsonl`
- Gateway HTTPS: `results/gateway/cloud_uplink.jsonl`
