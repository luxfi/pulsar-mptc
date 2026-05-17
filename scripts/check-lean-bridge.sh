#!/usr/bin/env bash
# Lean ↔ EasyCrypt Shamir bridge guard.
#
# Each of the four EC axioms named in proofs/lean-easycrypt-bridge.md
# must:
#   1. Still exist in the EC source.
#   2. Carry an inline citation comment pointing at the Lean theorem.
#
# If an axiom is renamed or the bridge comment is stripped without a
# corresponding bridge-doc update, this script fails the CI gate.
# This is the operational guard for the cross-prover bridge (see
# proofs/lean-easycrypt-bridge.md § "Future work" item 2).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAIL=0

# (axiom-name, file, lean-theorem-substring-that-must-appear-in-comment)
declare -a BRIDGE=(
    "lagrange_inverse_eval|proofs/easycrypt/Pulsar_N1.ec|shamir_correct_at_target"
    "add_share_zeroR|proofs/easycrypt/Pulsar_N4.ec|AddCommMonoid"
    "reconstruct_linear|proofs/easycrypt/Pulsar_N4.ec|combine_distributes_over_sum"
    "shamir_correct|proofs/easycrypt/Pulsar_N4.ec|shamir_correct_at_target"
)

echo "==> Lean ↔ EC Shamir bridge guard"

for entry in "${BRIDGE[@]}"; do
    IFS='|' read -r axiom file lean_ref <<< "$entry"
    if [[ ! -f "$file" ]]; then
        echo "    [FAIL] $axiom: $file not found"
        FAIL=1
        continue
    fi
    # Find the axiom declaration line.
    line=$(grep -nE "^axiom[[:space:]]+${axiom}[[:space:]]*" "$file" | head -1 | cut -d: -f1)
    if [[ -z "$line" ]]; then
        echo "    [FAIL] $axiom: declaration not found in $file (renamed without bridge update?)"
        FAIL=1
        continue
    fi
    # Look in the 20 lines preceding the axiom for the BRIDGE comment
    # naming the Lean theorem.
    start=$((line > 20 ? line - 20 : 1))
    if ! sed -n "${start},${line}p" "$file" | grep -q "$lean_ref"; then
        echo "    [FAIL] $axiom @ $file:$line — bridge comment missing reference to '$lean_ref'"
        echo "           (see proofs/lean-easycrypt-bridge.md for the required correspondence)"
        FAIL=1
        continue
    fi
    echo "    [ok]   $axiom @ $file:$line → $lean_ref"
done

# Sanity: the bridge doc itself must exist.
if [[ ! -f proofs/lean-easycrypt-bridge.md ]]; then
    echo "    [FAIL] proofs/lean-easycrypt-bridge.md is missing"
    FAIL=1
else
    echo "    [ok]   proofs/lean-easycrypt-bridge.md present"
fi

if [[ $FAIL -ne 0 ]]; then
    echo
    echo "    Lean ↔ EC bridge guard FAILED — fix the citation comments"
    echo "    or update proofs/lean-easycrypt-bridge.md if the axiom"
    echo "    correspondence changed."
    exit 2
fi
echo "    [ok]   all 4 axiom citations present"
exit 0
