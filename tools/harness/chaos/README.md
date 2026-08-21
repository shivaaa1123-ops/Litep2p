# Phase 11 — Android Chaos Lab (`tools/harness/chaos/`)

Automates master doc §46 device chaos scenarios against a real Android device.
**Target invariant:** after every interruption the runtime returns to a known,
internally consistent state — every single time.

## Requirements
- `adb` with exactly one (or more) attached device(s), USB debugging on.
- `CHAOS_APP_ID` (default `com.zeengal.litep2p`).
- A logcat recovery marker: the runtime logs a line containing
  `$CHAOS_RECOVERY_MARKER` (default `restored`) when it has rebuilt durable
  state after a start. Tune via env vars — see `chaos_lib.sh`.
- `corrupt_state.sh` needs a **debuggable build** (`run-as` access); it SKIPs
  honestly on release builds.

## Run

```bash
tools/harness/chaos/run_chaos_suite.sh                 # 3 iterations per scenario
ITER=5 tools/harness/chaos/run_chaos_suite.sh          # override
tools/harness/chaos/run_chaos_suite.sh --iterations 2
```

## Scenarios (§46)
| Script | Interruption | Extra invariant exercised |
|---|---|---|
| `kill_app.sh`      | SIGKILL app process        | inv 2/17 crash-safe state |
| `force_stop.sh`    | `am force-stop` cold start | inv 4 restart convergence |
| `toggle_wifi.sh`   | Wi-Fi off/on               | session re-establish |
| `toggle_data.sh`   | mobile data off/on         | transport failover |
| `network_switch.sh`| wifi→data→wifi             | inv 12 identity stability |
| `reboot.sh`        | full device reboot         | everything persisted |
| `fill_storage.sh`  | storage pressure + relief  | inv 7 honest rejection |
| `change_time.sh`   | clock jump ±2h             | TTL math sanity |
| `sleep_wake.sh`    | Doze sleep/wake            | inv 11 idle ≈ no work |
| `corrupt_state.sh` | flipped byte in store file | fail-safe open path |

Exit codes per scenario: `0` PASS · `1` FAIL · `2` SKIP (missing prerequisite —
never counted as a pass).

## Interpreting results
A FAIL is a release-gate blocker: record it in
`network_os_implementation/11_phase_11_simulator_and_chaos_lab.md` §10 and fix
before shipping. Flaky failures are bugs by definition (fixed scenarios; §11).
