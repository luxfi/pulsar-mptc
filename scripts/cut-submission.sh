#!/usr/bin/env bash
# scripts/cut-submission.sh — produce the NIST MPTC submission tarball.
#
# The pulsar-mptc repository is the submission FRAMEWORK; the algorithm
# being submitted lives at github.com/luxfi/pulsar @ v1.0.6. During
# day-to-day development go.mod carries a
#
#     replace github.com/luxfi/pulsar => ../pulsar
#
# directive so the framework tracks an in-tree canonical pulsar checkout.
# That directive is stripped at tarball-cut time and replaced with a
# `go mod vendor` snapshot under vendor/github.com/luxfi/pulsar/, so a
# NIST reviewer extracting the tarball gets a self-contained checkout
# with no network or local-overlay dependency.
#
# Usage:
#     scripts/cut-submission.sh [TAG] [--force]
#
#         TAG       e.g. "submission-2026-11-16"
#                   omit for dry-run (no tarball, no tag)
#         --force   re-cut over an existing tag / tarball
#
# Steps (each step echoes a header):
#     1.  verify clean working tree (git status -s empty)
#     2.  verify on branch main
#     3.  verify scripts/check-high-assurance.sh exits 0
#     4.  strip the local-dev `replace` directive from go.mod
#     5.  go mod vendor (snapshot luxfi/pulsar v1.0.6)
#     6.  regenerate KATs (scripts/gen_vectors.sh) against the vendored copy
#     7.  re-run round-trip replay tests against the vendored copy
#     8.  tar czf submission-<TAG>.tar.gz (excluding .git, vendor/modules.txt)
#     9.  sha256 the tarball; print to stdout
#    10.  git tag <TAG>
#    11.  restore the original go.mod (revert the strip-replace edit)
#
# The script is idempotent: re-running with the same TAG without
# --force fails fast (existing tag or existing tarball blocks the cut).
# A `trap` always restores go.mod and removes the temporary vendor/
# directory so the working tree is left exactly as found, even on
# failure or Ctrl-C.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# -----------------------------------------------------------------------------
# Argument parsing.
# -----------------------------------------------------------------------------
TAG=""
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        -h|--help)
            sed -n '4,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        --*)
            echo "cut-submission: unknown flag: $arg" >&2
            exit 2
            ;;
        *)
            if [[ -n "$TAG" ]]; then
                echo "cut-submission: only one TAG allowed (got '$TAG' and '$arg')" >&2
                exit 2
            fi
            TAG="$arg"
            ;;
    esac
done

DRY_RUN=0
if [[ -z "$TAG" ]]; then
    DRY_RUN=1
    echo "==> cut-submission: DRY-RUN (no TAG given; will not write tarball or tag)"
fi

TARBALL=""
if [[ $DRY_RUN -eq 0 ]]; then
    TARBALL="$REPO_ROOT/${TAG}.tar.gz"
    if [[ "$TAG" != submission-* ]]; then
        echo "cut-submission: TAG must start with 'submission-' (got '$TAG')" >&2
        exit 2
    fi
fi

# -----------------------------------------------------------------------------
# Restore handler — always reverts go.mod + go.sum and removes vendor/,
# even on failure or interrupt. Recorded BEFORE step 4 modifies them.
# -----------------------------------------------------------------------------
GO_MOD="$REPO_ROOT/go.mod"
GO_MOD_BACKUP="$REPO_ROOT/.go.mod.cut-submission.bak"
GO_SUM="$REPO_ROOT/go.sum"
GO_SUM_BACKUP="$REPO_ROOT/.go.sum.cut-submission.bak"
RESTORE_NEEDED=0

restore_state() {
    local rc=$?
    if [[ $RESTORE_NEEDED -eq 1 ]]; then
        if [[ -f "$GO_MOD_BACKUP" ]]; then
            mv -f "$GO_MOD_BACKUP" "$GO_MOD"
            echo "==> cut-submission: restored go.mod from backup"
        fi
        if [[ -f "$GO_SUM_BACKUP" ]]; then
            mv -f "$GO_SUM_BACKUP" "$GO_SUM"
            echo "==> cut-submission: restored go.sum from backup"
        fi
        if [[ -d "$REPO_ROOT/vendor" ]]; then
            rm -rf "$REPO_ROOT/vendor"
            echo "==> cut-submission: removed transient vendor/"
        fi
    fi
    exit $rc
}
trap restore_state EXIT INT TERM

# -----------------------------------------------------------------------------
# Step 1: clean working tree.
# -----------------------------------------------------------------------------
echo
echo "==> Step 1: verify clean working tree"
if [[ -n "$(git status --porcelain)" ]]; then
    echo "cut-submission: working tree not clean — commit or stash changes first" >&2
    git status --short >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Step 2: on branch main.
# -----------------------------------------------------------------------------
echo
echo "==> Step 2: verify on branch main"
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo "cut-submission: must run from branch 'main' (currently on '$CURRENT_BRANCH')" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Step 2.5: idempotency guard for tag + tarball.
# -----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    if git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
        if [[ $FORCE -eq 0 ]]; then
            echo "cut-submission: tag '$TAG' already exists — pass --force to re-cut" >&2
            exit 2
        fi
        echo "    [force] tag '$TAG' will be re-cut (existing tag deleted later)"
    fi
    if [[ -e "$TARBALL" ]]; then
        if [[ $FORCE -eq 0 ]]; then
            echo "cut-submission: tarball '$TARBALL' already exists — pass --force to overwrite" >&2
            exit 2
        fi
        echo "    [force] tarball '$TARBALL' will be overwritten"
    fi
fi

# -----------------------------------------------------------------------------
# Step 3: high-assurance gate.
# -----------------------------------------------------------------------------
echo
echo "==> Step 3: high-assurance gate (scripts/check-high-assurance.sh)"
bash "$REPO_ROOT/scripts/check-high-assurance.sh"

# -----------------------------------------------------------------------------
# Step 4: strip the local-dev replace directive from go.mod.
# -----------------------------------------------------------------------------
echo
echo "==> Step 4: strip local-dev replace directive from go.mod"
cp -p "$GO_MOD" "$GO_MOD_BACKUP"
cp -p "$GO_SUM" "$GO_SUM_BACKUP"
RESTORE_NEEDED=1

# Drop any `replace github.com/luxfi/pulsar => ...` line (and the
# preceding `// Local development overlay` comment block if present).
# Use awk to preserve idempotency: re-running on an already-stripped
# go.mod is a no-op.
awk '
    /^\/\/ Local development overlay/ { skip = 1; next }
    skip && /^\/\// { next }
    skip && /^[[:space:]]*$/ { skip = 0; next }
    skip { skip = 0 }
    /^replace github\.com\/luxfi\/pulsar[[:space:]]/ { next }
    { print }
' "$GO_MOD_BACKUP" > "$GO_MOD"

if grep -q '^replace github\.com/luxfi/pulsar' "$GO_MOD"; then
    echo "cut-submission: failed to strip replace directive — go.mod still contains it" >&2
    exit 2
fi
echo "    [ok] replace directive removed; go.mod now points at the published v1.0.6"

# -----------------------------------------------------------------------------
# Step 5: go mod vendor (snapshot luxfi/pulsar v1.0.6).
#
# go.sum must carry the upstream module hash for v1.0.6 before
# `go mod vendor` can resolve it. `go mod download` populates go.sum
# without rewriting go.mod (unlike `go mod tidy`).
# -----------------------------------------------------------------------------
echo
echo "==> Step 5: go mod vendor (snapshot luxfi/pulsar v1.0.6)"
export GOWORK=off
echo "    [step 5a] go mod download (populates go.sum for upstream v1.0.6)"
go mod download
echo "    [step 5b] go mod vendor"
go mod vendor

if [[ ! -d "$REPO_ROOT/vendor/github.com/luxfi/pulsar" ]]; then
    echo "cut-submission: go mod vendor did not produce vendor/github.com/luxfi/pulsar" >&2
    exit 2
fi
echo "    [ok] vendor/github.com/luxfi/pulsar populated"

# -----------------------------------------------------------------------------
# Step 6: regenerate KATs against the vendored copy.
# -----------------------------------------------------------------------------
echo
echo "==> Step 6: regenerate KAT vectors against the vendored copy"
bash "$REPO_ROOT/scripts/gen_vectors.sh"

# -----------------------------------------------------------------------------
# Step 7: round-trip replay tests against the vendored copy.
# -----------------------------------------------------------------------------
echo
echo "==> Step 7: re-run round-trip replay tests against the vendored copy"
go test -count=1 -run "^TestKAT_" github.com/luxfi/pulsar/ref/go/pkg/pulsar

# -----------------------------------------------------------------------------
# Step 8: build the tarball.
# -----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 1 ]]; then
    echo
    echo "==> Step 8: SKIP — dry-run, no tarball will be written"
else
    echo
    echo "==> Step 8: tar czf $(basename "$TARBALL")"
    # We tar from a parent directory so the tarball expands to a
    # 'pulsar-mptc/' top-level directory rather than './' — matches
    # reviewer expectation. --exclude paths are RELATIVE to the
    # transform root (pulsar-mptc/).
    (
        cd "$(dirname "$REPO_ROOT")"
        tar czf "$TARBALL" \
            --exclude='pulsar-mptc/.git' \
            --exclude='pulsar-mptc/vendor/modules.txt' \
            --exclude='pulsar-mptc/.go.mod.cut-submission.bak' \
            pulsar-mptc
    )
    if [[ ! -f "$TARBALL" ]]; then
        echo "cut-submission: tarball not produced at $TARBALL" >&2
        exit 2
    fi
    echo "    [ok] $TARBALL"
fi

# -----------------------------------------------------------------------------
# Step 9: SHA-256 the tarball.
# -----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    echo
    echo "==> Step 9: SHA-256"
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$TARBALL"
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$TARBALL"
    else
        echo "cut-submission: neither shasum nor sha256sum found in PATH" >&2
        exit 2
    fi
fi

# -----------------------------------------------------------------------------
# Step 10: tag the repo.
# -----------------------------------------------------------------------------
if [[ $DRY_RUN -eq 0 ]]; then
    echo
    echo "==> Step 10: git tag $TAG"
    if git rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null; then
        # --force already asserted above.
        git tag -d "$TAG" >/dev/null
    fi
    git tag -a "$TAG" -m "NIST MPTC submission cut $TAG (pulsar v1.0.6 vendored)"
    echo "    [ok] tag '$TAG' created (NOT pushed — push manually when ready)"
fi

# -----------------------------------------------------------------------------
# Step 11: restore go.mod + clean vendor/.
# Done by the EXIT trap. Set RESTORE_NEEDED=1 already above.
# -----------------------------------------------------------------------------
echo
echo "==> Step 11: restore go.mod + remove transient vendor/ (via EXIT trap)"

echo
if [[ $DRY_RUN -eq 1 ]]; then
    echo "==> done — dry-run validated (no tarball / no tag produced)"
else
    echo "==> done — tarball cut, tag created"
    echo "    tarball: $TARBALL"
    echo "    tag:     $TAG (local; not pushed)"
fi
