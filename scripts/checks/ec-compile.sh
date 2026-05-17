#!/usr/bin/env bash
# scripts/checks/ec-compile.sh — EasyCrypt compile gate for all
# tracked EC files.
#
# Runs `easycrypt compile` on each file in EC_FILES and fails the
# gate if any reports [critical] (which `easycrypt compile` emits
# to stderr even when the exit code is 0). Skips silently if
# easycrypt is not installed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EC_ROOT="$REPO_ROOT/proofs/easycrypt"

EC_FILES=(
    "$EC_ROOT/Pulsar_N1.ec"
    "$EC_ROOT/Pulsar_N4.ec"
    "$EC_ROOT/lemmas/Pulsar_CT.ec"
    "$EC_ROOT/lemmas/MLDSA65_Functional.ec"
    "$EC_ROOT/Pulsar_N1_Memory.ec"
    "$EC_ROOT/Pulsar_N1_Signature_Codec.ec"
    "$EC_ROOT/Pulsar_N1_Combine_Refinement.ec"
    "$EC_ROOT/Pulsar_N1_Sign_Refinement.ec"
    "$EC_ROOT/Pulsar_N1_Wrapper_Bridge.ec"
    "$EC_ROOT/Pulsar_N1_Combine_Layout.ec"
    "$EC_ROOT/Pulsar_N1_Sign_Layout.ec"
)

if ! command -v easycrypt >/dev/null 2>&1; then
    echo "==> EasyCrypt compile gate"
    echo "    [skip] easycrypt not on PATH"
    echo "           install (source build): https://github.com/EasyCrypt/easycrypt"
    exit 0
fi

EC_HASH=$(easycrypt config 2>&1 | grep "git-hash" | head -1)
echo "==> easycrypt found ($EC_HASH)"
EC_FAIL=0
for f in "${EC_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "    [warn] missing: $f"
        continue
    fi
    if easycrypt compile -I "$EC_ROOT" -I "$EC_ROOT/lemmas" "$f" 2>&1 | grep -q '\[critical\]'; then
        echo "    [FAIL] $f — see easycrypt output above"
        EC_FAIL=1
    else
        echo "    [ok]   $f compiles"
    fi
done
if [[ $EC_FAIL -ne 0 ]]; then
    echo
    echo "    EasyCrypt compile gate FAILED."
    exit 2
fi
exit 0
