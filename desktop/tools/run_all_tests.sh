#!/usr/bin/env bash
# run_all_tests.sh — run every desktop test suite in one command and report
# exit codes. Phase 0 Step 1.10 deliverable (baseline structured tests).
#
# Usage: desktop/tools/run_all_tests.sh [--loop N]
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/desktop/build_fixcheck/bin"
LOOP="${1:-1}"

SUITES=(c_api_test session_manager_test overlay_test proxy_test file_transfer_test
        crypto_test nat_traversal_test malformed_input_test voice_call_test
        network_runtime_test)

total_fail=0
for ((n = 0; n < LOOP; n++)); do
    echo "=== pass $((n + 1))/$LOOP ==="
    for s in "${SUITES[@]}"; do
        if [ ! -x "$BIN/$s" ]; then
            echo "SKIP  $s (not built)"
            continue
        fi
        if "$BIN/$s" > /tmp/p0_test_$s.log 2>&1; then
            echo "PASS  $s"
        else
            echo "FAIL  $s (see /tmp/p0_test_$s.log)"
            total_fail=$((total_fail + 1))
        fi
    done
done

echo "=== done: $total_fail failure(s) across $LOOP pass(es) ==="
exit $((total_fail > 0 ? 1 : 0))
