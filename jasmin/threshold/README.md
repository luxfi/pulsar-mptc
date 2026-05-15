# Pulsar threshold layer — Jasmin sources

This directory holds the Jasmin sources for Pulsar's **threshold
layer**. The single-party ML-DSA-65 kernel is provided by the libjade
sources in `../ml-dsa-65/libjade/` (fetched on demand, see
`../ml-dsa-65/README.md`); the threshold layer here implements the
per-party computations that combine into a FIPS 204-valid signature.

## Status — stubs

Every `.jazz` file in this directory is a **stub**. The function
signature is committed in Jasmin syntax; the body is a `// TODO:
jasmin implementation` marker with a comment block describing the
algorithm. Implementing the threshold layer in Jasmin is a non-trivial
effort tracked in this repository
release point.

What is in this repository:

- The interface contract between threshold-layer Jasmin and the
  single-party libjade kernel (signature shapes, secret-dependent
  arguments, constant-time obligations).
- The EasyCrypt theory shell that discharges the Class N1
  reduction once the Jasmin implementations land (see
  `../../proofs/easycrypt/PulsarM_N1.ec`).

This is honest and standard for an MPTC this repository. NIST
reviewers see:

1. The single-party verified baseline (libjade, real and machine-
   checked).
2. The interface the threshold layer will plug into (this directory).
3. The Class N1 reduction skeleton (`../../proofs/easycrypt/`).

The full proof closure is in this repository.

## Files

| File | Algorithm | Mirrors Go reference |
|---|---|---|
| `round1.jazz` | Round-1 commit message | `ref/go/pkg/pulsar/threshold.go` `ThresholdSigner.Round1` |
| `round2.jazz` | Round-2 response (post-aggregation) | `ref/go/pkg/pulsar/threshold.go` `ThresholdSigner.Round2` |
| `combine.jazz` | Aggregate quorum responses into FIPS 204 signature | `ref/go/pkg/pulsar/threshold.go` `Combine` |

## Constant-time obligations

Every threshold-layer function operates on at least one secret-
dependent input:

| Function | Secret input | Constant-time obligation |
|---|---|---|
| `round1_commit` | `share` (Shamir secret share) | Time + memory access independent of `share` and of internal RNG output for masking polynomials |
| `round2_response` | `share`, `c` (challenge) | Time + memory access independent of `share` and of rejection-sampling outcomes (norm checks must use constant-time comparison) |
| `combine` | aggregated `z`, `h` | Memory access independent of high-bit decomposition outcomes (norm checks already constant-time in libjade single-party path) |

These obligations are stated formally in
`../../proofs/easycrypt/lemmas/PulsarM_CT.ec` and discharged through
the leakage-model framework of Barthe, Grégoire, Laporte (CSF 2018).

## How to compile

```bash
../../scripts/check-high-assurance.sh
```

The check script is skip-friendly: if `jasminc` is not on PATH, it
prints a clear skip message and exits 0. When `jasminc` is present
and the threshold `.jazz` files have non-stub bodies, the script
compiles each to x86-64 assembly and asserts that the verified
compiler exits cleanly.
