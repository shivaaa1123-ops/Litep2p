# LiteP2P Global Infra Stress Runbook

This repo already includes a scheduled GitHub Actions workflow to run the stress suite on **self-hosted runners**:
- `.github/workflows/stress_suite.yml`

You can also run the suite across a list of VPS IPs/hosts via SSH using:
- `tools/harness/run_remote_suite.sh`

## Option A (recommended): GitHub Actions + self-hosted runners

### 1) Register a self-hosted runner per VPS

On each VPS, install a GitHub Actions runner and label it (examples used by the repo today):
- `litep2p-sg`
- `litep2p-us`

Then add additional entries to the workflow matrix in `.github/workflows/stress_suite.yml`.

### 2) Ensure the runner user can do passwordless sudo for net chaos

The stress suite uses `sudo -n` for `iptables`/`tc` when not running as root.

Minimum requirement for full chaos coverage:
- `sudo -n true` succeeds for the runner user

If you don’t enable passwordless sudo:
- baseline phases still run
- iptables/tc phases will be skipped (safe default)

### 3) Workflow schedule / manual trigger

- Nightly schedule is in `.github/workflows/stress_suite.yml`
- You can run on-demand via **workflow_dispatch** and tune knobs like `LOSS_PROB`, `ALLOW_CHAOS_FAILURES`, `RESOURCE_CHAOS_ENABLED`, etc.

Artifacts:
- the workflow uploads the entire `OUT_DIR` bundle per runner
- look for `summary.env`, `summary.json`, and `results.csv`

## Option B: Run across VPS hosts via SSH

### 1) Prepare a hosts file

Create `hosts.txt` (one per line):

- `ubuntu@1.2.3.4`
- `root@my-vps-hostname`

### 2) Ensure SSH access

- Prefer an `~/.ssh/config` entry per host (key, user, port)
- Ensure `ssh` is non-interactive (BatchMode)

### 3) Run the remote suite

From your control machine (or a CI runner that has SSH access), run:

```bash
bash tools/harness/run_remote_suite.sh hosts.txt
```

Outputs are pulled to:
- `./remote_artifacts/<host>/<timestamp>/...`

### 4) Regular runs

Pick one:
- Cron/systemd timer on the control machine calling `run_remote_suite.sh`
- GitHub Actions workflow on a self-hosted control runner (with SSH access to all VPS)

## Recommended rollout for “deployment readiness”

1) Start with `ALLOW_CHAOS_FAILURES=1` to gather data without blocking.
2) Fix any baseline failures (baseline phases always gate `FINAL_EXIT`).
3) Turn on strict gating:
   - set `ALLOW_CHAOS_FAILURES=0`
4) Enable resource pressure:
   - set `RESOURCE_CHAOS_ENABLED=1` (requires `stress-ng` on VPS)
5) Add more regions/hosts to the runner matrix (or SSH hosts list) to cover real-world variability.
