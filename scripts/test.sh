#!/usr/bin/env bash
# Pulsar test suite runner.
#
# Runs unit tests, KAT validation (when available), and the no-secret-logs
# linter. Designed to be the CI gate alongside scripts/build.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Module-only build. See note in scripts/build.sh.
export GOWORK=off

echo "==> Go unit tests"
go test -count=1 -race ./ref/go/...

echo "==> No-secret-logs linter"
# DD-007: secret-touching files MUST NOT use stdlib log.* / fmt.Print* /
# panic. This list is the implementation surface that touches secrets.
SECRET_FILES=(
    "ref/go/pkg/pulsar/keygen.go"
    "ref/go/pkg/pulsar/sign.go"
    "ref/go/pkg/pulsar/dkg.go"
    "ref/go/pkg/pulsar/threshold.go"
    "ref/go/pkg/pulsar/reshare.go"
    "ref/go/pkg/pulsar/shamir.go"
)
for f in "${SECRET_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        # Allow comments mentioning these tokens, but forbid actual use:
        # filter out lines starting with // and import-comment blocks.
        if grep -nE '^[^/]*(\<log\.(Print|Fatal|Panic)|fmt\.(Print|Fprint)|panic\()' "$f" \
            | grep -vE '^\s*//' ; then
            echo "FAIL: secret-touching file $f contains forbidden logging or panic" >&2
            exit 1
        fi
    fi
done

echo "==> KAT validation"
if [[ -f vectors/keygen.json ]]; then
    go test -count=1 -run "^TestKAT_" ./ref/go/pkg/pulsar/
else
    echo "    [info] vectors/ not generated — run scripts/gen_vectors.sh"
fi

echo "==> Class N1 interoperability — cross-validate KAT signatures against"
echo "    cloudflare/circl FIPS 204 verifier (independent of reference impl)"
go test -count=1 ./test/interoperability/...

# Layer-6 (fuzzing) smoke. Per-push gate: 5s per parser-surface
# target; deep fuzzing runs nightly via Makefile.fuzz fuzz-nightly.
# Skips silently on Go < 1.18 (no -fuzz support).
#
# Differential fuzz (FuzzN1_ByteEquality_Differential) is HEAVIER —
# 30s per target window because each iteration drives the full
# DKG + threshold-sign + reconstruct + centralized-sign + byte-
# compare pipeline. We run it per-push when PULSAR_DIFF_FUZZ=1
# (default off so the per-push gate stays under ~30s total); the
# nightly job always runs `fuzz-diff-nightly` for 1h coverage.
echo "==> Fuzz smoke (Layer 6)"
GO_VER="$(go env GOVERSION 2>/dev/null || true)"
case "$GO_VER" in
    go1.1[89]*|go1.[2-9][0-9]*|go[2-9].*)
        make -C ref/go/pkg/pulsar -f Makefile.fuzz fuzz-smoke
        if [[ "${PULSAR_DIFF_FUZZ:-0}" == "1" ]]; then
            echo "==> Differential fuzz smoke (PULSAR_DIFF_FUZZ=1)"
            make -C ref/go/pkg/pulsar -f Makefile.fuzz fuzz-diff-smoke
        else
            echo "    [info] differential fuzz skipped (set PULSAR_DIFF_FUZZ=1 to enable);"
            echo "           nightly runs it for 1h via 'make -f Makefile.fuzz fuzz-diff-nightly'"
        fi
        ;;
    *)
        echo "    [info] Go $GO_VER does not support -fuzz; skipping"
        ;;
esac

echo "==> done"
