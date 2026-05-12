# Constant-time analysis (dudect)

dudect (https://github.com/oreparaz/dudect) is a black-box constant-time
checker. It runs a target operation on two classes of inputs (fixed +
random) and applies a Welch's t-test to the timing distributions. If
the test detects a statistically significant timing difference, the
target leaks information through wall-clock time.

This directory holds the Pulsar-M dudect harness. We measure two
operations:

1. **`pulsarm.Verify`** — the load-bearing entry point. Must be
   constant-time in the public key, message, and signature bytes.
2. **`pulsarm.Combine`** — the threshold aggregator. Must be
   constant-time in the per-party signature shares and Lagrange
   coefficients.

`pulsarm.Sign` is intentionally NOT constant-time per FIPS 204 §3.3 —
the rejection-sampling loop has secret-dependent retry count. This
is a property of ML-DSA itself, not Pulsar-M. Production deployments
that need constant-time Sign use the FIPS 204 "ext-ml-dsa-65-cs"
context-supplied variant (open question for MPTC); Pulsar-M inherits
whatever Sign property the underlying FIPS 204 implementation gives.

## Status

Harness layout: scaffolded. The Go-FFI-to-dudect bridge is the
remaining engineering work — current plan is to export Verify +
Combine as cgo entry points and call them from a minimal C harness
linked against `dudect.h`.

| File | Status |
|---|---|
| `verify_ct.go` | TBD — exports `pulsarm.Verify` as cgo entry point |
| `combine_ct.go` | TBD — exports `pulsarm.Combine` as cgo entry point |
| `dudect_verify.c` | TBD — dudect main loop calling the exported Verify |
| `dudect_combine.c` | TBD — dudect main loop calling the exported Combine |
| `Makefile` | TBD — builds both harnesses |
| `results/` | TBD — pinned dudect output at submission time |

## Why this is in the submission package, not yet populated

NIST evaluates constant-time at the submission deadline. The harness
target is to ship populated `results/` on the `submission-2026-11-16`
tag from a quiet machine (no background processes, perf governor
pinned). The harness scaffolding lands in advance so reviewers can
verify the test methodology before the final run.

## How to run (once harness is wired)

```bash
make -C ct/dudect
./ct/dudect/dudect_verify   2> ct/dudect/results/verify.log
./ct/dudect/dudect_combine  2> ct/dudect/results/combine.log
```

Pass criterion: no t-test statistic above 4.5 sigma after 10⁹ samples,
per dudect's standard cutoff.
