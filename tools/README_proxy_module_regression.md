# Proxy module regression (desktop)

This repo has an optional proxy module that is **enabled by default**.
You can disable it at compile time with `-DENABLE_PROXY_MODULE=OFF`.

`tools/proxy_module_regression.py` automates the following loop:

- Configure/build desktop with proxy **OFF**, then run baseline desktop tests.
- Configure/build desktop with proxy **ON**, then run baseline tests plus `proxy_test`.
- (When proxy is ON) run a Python-driven simulation against `proxy_stdio` to validate client+gateway control/data behavior.

## Quick run (macOS / bash)

```bash
cd /Users/Shiva/StudioProjects/Litep2p
/Users/Shiva/StudioProjects/Litep2p/.venv/bin/python tools/proxy_module_regression.py --iterations 1
```

## Common options

- `--iterations N`: repeat build+test cycle N times
- `--delay SECONDS`: sleep between iterations
- `--timeout SECONDS`: timeout for each C++ test executable
- `--stdio-timeout SECONDS`: per-step timeout for the `proxy_stdio` simulation
- `--skip-stdio-sim`: skip the `proxy_stdio` simulation (still builds ON/OFF and runs C++ tests)

## Notes

- `proxy_stdio` is only built when `ENABLE_PROXY_MODULE=ON` (which is the default).
- The `proxy_stdio` simulation currently validates the starter behavior:
  - HELLO/ACCEPT
  - OPEN_STREAM/ACCEPT
  - STREAM_DATA echo in gateway mode
  - CLOSE_STREAM stops echo
  - gateway-disabled rejects HELLO
