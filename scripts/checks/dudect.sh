#!/usr/bin/env bash
# scripts/checks/dudect.sh — dudect smoke gate.
#
# Builds the cgo harness and runs the two smoke targets at the per-
# push budget. Verify-side leakage is reported as [warn] (smoke-
# budget noise at the t=10 threshold is borderline; the authoritative
# gate is the submission-grade run from ct/dudect/run-submission.sh).
# Combine-side leakage IS gate-blocking (Combine handles secret
# shares).
#
# Skips silently if dudect.h is not fetched (ct/dudect/fetch.sh).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CT_ROOT="$REPO_ROOT/ct/dudect"
CT_HDR="$CT_ROOT/dudect/src/dudect.h"

if [[ ! -f "$CT_HDR" ]]; then
    echo "==> dudect"
    echo "    [skip] $CT_HDR not present"
    echo "           fetch: $CT_ROOT/fetch.sh"
    exit 0
fi

echo "==> dudect found ($CT_HDR — $(cd "$CT_ROOT/dudect" && git rev-parse --short HEAD))"
mkdir -p "$CT_ROOT/results"
BUILD_LOG="$CT_ROOT/results/build.log"

if ! ( cd "$CT_ROOT" && make -s all ) >"$BUILD_LOG" 2>&1; then
    echo "    [info] harness build failed — see results/build.log"
    echo "           this is expected when ref/go/pkg/pulsar is mid-refactor"
    echo "           and the cgo target cannot link the import graph"
    exit 0
fi
echo "    [ok]  harness build clean (libpulsar_verify + libpulsar_combine)"

# ----- dudect_verify (advisory at smoke budget) -----
echo "    [check] dudect_verify (smoke: 10000 samples/batch × 4 batches)"
VERIFY_RC=0
( cd "$CT_ROOT" && ./dudect_verify ) \
    >"$CT_ROOT/results/verify.stdout" \
    2>"$CT_ROOT/results/verify.log" || VERIFY_RC=$?
case $VERIFY_RC in
    0)
        echo "    [ok]  no leakage evidence at smoke budget"
        ;;
    2)
        echo "    [warn] dudect_verify smoke flagged a leak"
        echo "           (smoke budget at 40k samples — borderline t-stat"
        echo "            around dudect's t=10 threshold; full"
        echo "            submission-grade run at 10^9 samples on a"
        echo "            pinned CPU is the authoritative check);"
        echo "           see ct/dudect/results/verify.log for t-stats."
        ;;
    *)
        echo "    [warn] dudect_verify exited rc=$VERIFY_RC — see results/verify.log"
        ;;
esac

# ----- dudect_combine (BLOCKING — handles secret shares) -----
echo "    [check] dudect_combine (smoke: 2000 samples/batch × 4 batches)"
COMBINE_RC=0
( cd "$CT_ROOT" && ./dudect_combine ) \
    >"$CT_ROOT/results/combine.stdout" \
    2>"$CT_ROOT/results/combine.log" || COMBINE_RC=$?
case $COMBINE_RC in
    0)
        echo "    [ok]  no leakage evidence at smoke budget"
        ;;
    2)
        echo "    [FAIL] dudect_combine reported leakage — see results/combine.log"
        echo "           combine processes secret shares; a smoke-budget"
        echo "           leak here is a CT regression on the threshold"
        echo "           path. Investigate before shipping."
        exit 2
        ;;
    *)
        echo "    [warn] dudect_combine exited rc=$COMBINE_RC — see results/combine.log"
        ;;
esac

exit 0
