# Phase 4 — Three-Pi + cloud matrix (E1–E5 × 3 reps)

Does **not** touch paper reps 6–9 or rep 11. Use `--first-rep 12` → sessions `E1_rep12` … `E5_rep14`.

IPS cells (E1, E3, E5) use the same `FIXED_FW_SETTINGS` as R4/R5 and **allow_list=True** (controller Pi A IP), matching validated R4-style allow-list.

## Attack volume

| Experiments | Pi A attacks | Pi B attacks |
|---|---|---|
| E1 | none | off |
| E2, E3 | none | full `ATTACKS` list |
| E4, E5 | slice `a` (even indices) | slice `b` (odd indices) |

`a ∪ b = all`, disjoint → combined E4/E5 attack volume matches one full pass (E2/E3).

## Startup order (each session)

### 1. Windows PC
```bash
cd ~/journal_paper_proj/pi_sim
source .venv/bin/activate
python -m cloud.https_server
```

### 2. Gateway Pi
```bash
cd ~/Desktop/pi_project/pi_sim
# once after pulling / new PC IP:
#   python -m cloud.setup_gateway
# .env must have GW_CLOUD_FORWARD=1
sudo .venv/bin/python experiments/gateway_agent.py
```

### 3. Pi B (before or right after Pi A starts a session)
**E1:** do nothing (leave idle).

**E2 / E3:**
```bash
sudo .venv/bin/python experiments/extra_client.py --tag pi2 --attacks-only --attack-slice all
```

**E4 / E5:**
```bash
sudo .venv/bin/python experiments/extra_client.py --tag pi2 --attacks-only --attack-slice b
```

Optional: `--session E2_rep12` to pin the session name.

### 4. Pi A (controller)
Full matrix (≈ many hours):
```bash
sudo .venv/bin/python experiments/client_runner.py \
  --runs E1,E2,E3,E4,E5 --reps 3 --first-rep 12
```

One experiment / one rep (sanity):
```bash
sudo .venv/bin/python experiments/client_runner.py --runs E1 --reps 1 --first-rep 12
```

Pi A prints the exact Pi B command when `pi_b != off`. Start Pi B while that session is active (extra_client waits for the agent session).

## Outputs

- Pi A: `results/client/E*_rep*/`
- Pi B: `results/client/E*_rep*/peers/pi2/`
- Gateway: `results/gateway/E*_rep*/`
- Cloud PC: `results/cloud/uplink.jsonl` (append-only; archive/copy per campaign if you need isolation)
- Gateway HTTPS timings: `results/gateway/cloud_uplink.jsonl`

Paper analysis (`analyze.py` without `--all`) still uses only R1–R5 reps 6–9. Phase 4 sessions are separate (`plan.is_phase4_session`).

## Safety

- Refuses Phase 4 if `--first-rep` intersects paper reps 6–9.
- Refuses to start a session that already has `meta.json`.
