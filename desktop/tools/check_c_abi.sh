#!/usr/bin/env bash
# check_c_abi.sh — Network OS Phase 1 C ABI compatibility gate (Step 2.8).
#
# Diffs the `litep2p_*` symbol set + signatures declared in include/litep2p.h
# against a committed snapshot. The diff MUST be empty: the C ABI is the
# public contract (locked decision 6/10) and any change requires bumping the
# major version and updating jni_bridge.cpp, litep2p_c_api.cpp, the Kotlin
# wrapper, and docs/api-spec.md together.
#
# Usage:
#   desktop/tools/check_c_abi.sh            # check (default)
#   desktop/tools/check_c_abi.sh --update   # refresh the snapshot
set -u

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
HEADER="$REPO/litep2p-core/src/main/cpp/include/litep2p.h"
SNAPSHOT_DIR="$REPO/tools/abi"
SNAPSHOT="$SNAPSHOT_DIR/litep2p_abi_snapshot.txt"

[ -f "$HEADER" ] || { echo "ERROR: $HEADER not found"; exit 2; }

# Extract one line per exported function: return type + name + signature,
# normalized (strip whitespace/line breaks). Greps only litep2p_* functions
# (extern "C" block), skipping comments/macros.
extract_abi() {
    awk '
        /^[a-z_].*litep2p_/ && /\(/ && !/^#/ && !/\/\// {
            line = $0
            gsub(/[[:space:]]+/, " ", line)
            print line
        }
    ' "$HEADER" | sed 's/ *$//' | sort
}

mkdir -p "$SNAPSHOT_DIR"

if [ "${1:-}" = "--update" ]; then
    extract_abi > "$SNAPSHOT"
    echo "ABI snapshot updated: $SNAPSHOT ($(wc -l < "$SNAPSHOT") functions)"
    exit 0
fi

if [ ! -f "$SNAPSHOT" ]; then
    echo "No snapshot yet — creating baseline at $SNAPSHOT"
    extract_abi > "$SNAPSHOT"
    echo "Baseline created with $(wc -l < "$SNAPSHOT") functions."
    exit 0
fi

CURRENT="$(mktemp /tmp/litep2p_abi.XXXXXX)"
extract_abi > "$CURRENT"

if diff -u "$SNAPSHOT" "$CURRENT" > /tmp/abi.diff; then
    echo "C ABI OK: symbol set + signatures identical to snapshot ($(wc -l < "$SNAPSHOT") functions)."
    rm -f "$CURRENT"
    exit 0
else
    echo "C ABI DRIFT DETECTED — diff:"
    cat /tmp/abi.diff
    echo ""
    echo "The C ABI is the public contract. If this change is intentional:"
    echo "  1. bump the major version (gradle.properties + litep2p.h),"
    echo "  2. update jni_bridge.cpp, litep2p_c_api.cpp, Kotlin wrapper, docs/api-spec.md,"
    echo "  3. run: desktop/tools/check_c_abi.sh --update"
    rm -f "$CURRENT"
    exit 1
fi
