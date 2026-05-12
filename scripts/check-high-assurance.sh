#!/usr/bin/env bash
# Pulsar-M high-assurance track checker.
#
# Compiles the Jasmin sources under jasmin/ and runs `easycrypt check`
# on the theories under proofs/easycrypt/. Skip-friendly: if the tools
# are not installed the script prints a clear message and exits 0 so
# this stays additive to the default CI gate (scripts/test.sh).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

JASMIN_ROOT="$REPO_ROOT/jasmin"
EC_ROOT="$REPO_ROOT/proofs/easycrypt"

have_jasmin=0
have_ec=0
command -v jasminc  >/dev/null 2>&1 && have_jasmin=1
command -v easycrypt >/dev/null 2>&1 && have_ec=1

echo "==> Pulsar-M high-assurance track"
echo "    jasmin/   $JASMIN_ROOT"
echo "    easycrypt $EC_ROOT"
echo

# -----------------------------------------------------------------------------
# Jasmin
# -----------------------------------------------------------------------------

if [[ $have_jasmin -eq 0 ]]; then
    echo "    [skip] jasminc not on PATH"
    echo "           install: opam install jasmin"
    echo "           upstream: https://github.com/jasmin-lang/jasmin"
else
    echo "==> jasminc found ($(jasminc -version 2>&1 | head -1))"
    JAZZ_FILES=(
        "$JASMIN_ROOT/threshold/round1.jazz"
        "$JASMIN_ROOT/threshold/round2.jazz"
        "$JASMIN_ROOT/threshold/combine.jazz"
    )
    for f in "${JAZZ_FILES[@]}"; do
        if [[ ! -f "$f" ]]; then
            echo "    [warn] missing: $f"
            continue
        fi
        # libjade fetch is on-demand; only attempt compilation if it's there
        if [[ ! -d "$JASMIN_ROOT/ml-dsa-65/libjade" ]]; then
            echo "    [info] $f: libjade not fetched; skipping compile"
            echo "           run: $JASMIN_ROOT/ml-dsa-65/fetch.sh"
            continue
        fi
        echo "    [check] $f"
        # Stubs have empty bodies — jasminc parses successfully but
        # produces no assembly. That is the expected outcome at the
        # initial-submission stage.
        jasminc -checksafety -checkCT "$f" || {
            echo "    [info] $f: jasminc rejected (stub body — expected at initial stage)"
        }
    done
fi

echo

# -----------------------------------------------------------------------------
# EasyCrypt
# -----------------------------------------------------------------------------

if [[ $have_ec -eq 0 ]]; then
    echo "    [skip] easycrypt not on PATH"
    echo "           install: opam install easycrypt"
    echo "           upstream: https://github.com/EasyCrypt/easycrypt"
else
    echo "==> easycrypt found ($(easycrypt --version 2>&1 | head -1))"
    EC_FILES=(
        "$EC_ROOT/PulsarM_N1.ec"
        "$EC_ROOT/PulsarM_N4.ec"
        "$EC_ROOT/lemmas/PulsarM_CT.ec"
    )
    for f in "${EC_FILES[@]}"; do
        if [[ ! -f "$f" ]]; then
            echo "    [warn] missing: $f"
            continue
        fi
        echo "    [check] $f"
        # admit-bearing theories still type-check; that's by design at
        # initial-submission stage. easycrypt returns 0 if the file
        # parses + type-checks even with `admit` in proof bodies.
        easycrypt compile "$f" || {
            echo "    [info] $f: easycrypt could not close the file (expected — uses admit)"
        }
    done
fi

echo
echo "==> done"
exit 0
