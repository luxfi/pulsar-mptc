#!/usr/bin/env bash
# Fetch libjade at the pinned commit used by Pulsar-M's high-assurance track.
#
# We do not vendor libjade into this repository — see ./README.md for
# rationale. This script reproduces the libjade tree on demand.

set -euo pipefail

# Pinned at submission-tag time. Update at the same time as the
# Pulsar-M submission tag so the artifact chain stays reproducible.
LIBJADE_REPO="https://github.com/formosa-crypto/libjade.git"
LIBJADE_COMMIT="main"  # TODO: replace with frozen hash at 2026-11-16 submission tag

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -d libjade/.git ]]; then
    echo "==> libjade already cloned at $SCRIPT_DIR/libjade"
    ( cd libjade && git fetch --quiet origin && git checkout --quiet "$LIBJADE_COMMIT" )
else
    echo "==> cloning libjade at $LIBJADE_COMMIT"
    git clone --quiet "$LIBJADE_REPO" libjade
    ( cd libjade && git checkout --quiet "$LIBJADE_COMMIT" )
fi

echo "==> libjade ready at $SCRIPT_DIR/libjade"
echo "    ML-DSA-65 sources: $SCRIPT_DIR/libjade/src/crypto_sign/dilithium/dilithium3/"
