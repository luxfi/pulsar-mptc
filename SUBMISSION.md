# NIST MPTC Submission — Pulsar-M

This document is the cover sheet for the Pulsar-M submission to the
NIST Multi-Party Threshold Cryptography (MPTC) project. It is written
for NIST reviewers and points at every artifact a reviewer needs.

The repository is **active** (not frozen). The submission tarball is
cut from a tag on `main` at NIST's deadline; reviewer feedback and
post-submission patches land in this same repository so the artifact
chain stays auditable.

## At a glance

| Field | Value |
|---|---|
| Submission name | **Pulsar-M** |
| Submitting organisation | Lux Industries, Inc. |
| Algorithm | Threshold ML-DSA-65 (Module-LWE, FIPS 204-aligned) |
| Target NIST MPTC classes | **N1** (single-party-compatible threshold signing) + **N4** (multi-party key generation with public-key preservation across resharing) |
| Underlying primitive | FIPS 204 ML-DSA-65 |
| Round count | 2 rounds per signature |
| Signature output | **Byte-identical** to single-party FIPS 204 ML-DSA-65 |
| Repository | <https://github.com/luxfi/pulsar-mptc> |
| Submission tag | `submission-2026-11-16` (cut from `main` at deadline) |
| Spec PDF | `spec/pulsar-m.pdf` (built via `scripts/build.sh`) |
| License | Apache-2.0 (see `LICENSE`) |
| Patent posture | See `SECURITY.md` — Lux Industries grants a royalty-free patent license on the submitted construction to any MPTC-class N1/N4 implementer |

## Headline claim

> Every signature produced by a Pulsar-M threshold ceremony
> (DKG → Round-1 → Round-2 → Combine) is **bit-identical** to a signature
> produced by single-party FIPS 204 ML-DSA-65 on the same message and
> group public key.

This is the **Class N1** claim. A FIPS-validated ML-DSA verifier
(BoringSSL FIPS, AWS-LC, OpenSSL 3.0 PQ provider) accepts a Pulsar-M
signature without modification.

Cross-validation evidence: every KAT vector in `vectors/kat-v1.json` is
verified by three independent ML-DSA implementations
(`test/interoperability/`):

1. The reference implementation in `ref/go/`
2. The FIPS 204 reference (pq-crystals Dilithium C reference)
3. A third independent implementation (BoringSSL FIPS or OpenSSL 3.0 PQ
   provider, whichever is available at test time)

## What to read first

A reviewer with limited time should read in this order:

1. **`SUBMISSION.md`** (this file) — submission metadata and headline
2. **`spec/pulsar-m.pdf`** — full algorithm specification
   - §1 Introduction + §2 System model
   - §3 Parameters (ML-DSA-44 / 65 / 87)
   - §4 Protocol (DKG, Round-1, Round-2, Combine, Reshare)
   - §5 Security games (EUF-CMA threshold, identifiable abort)
   - §6 Output-interchangeability proof (the Class N1 claim)
   - §7 NIST MPTC category mapping
3. **`README.md`** — repository layout and how to reproduce vectors
4. **`vectors/README.md`** — KAT format + cross-validation gates
5. **`spec/known-limitations.tex`** — what the construction does NOT
   claim (e.g. v0.1 cross-committee reshare without external state
   binding, identifiable-abort attribution under network partitions)

## What to run

The reproducibility gate is `scripts/build.sh` from a fresh clone:

```bash
git clone --branch submission-2026-11-16 https://github.com/luxfi/pulsar-mptc
cd pulsar-mptc
scripts/build.sh          # builds Go ref + spec PDF
scripts/test.sh           # runs unit + KAT + interoperability tests
scripts/bench.sh          # produces signature/verification benchmarks
scripts/gen_vectors.sh    # regenerates KAT vectors (deterministic)
```

`scripts/build.sh` exits non-zero on any failure. CI runs the same
script on every commit; the reproducibility property is the load-
bearing one for the submission.

## What's in this package

```
pulsar-mptc/
├── SUBMISSION.md            # this file
├── README.md                # repository layout + how to use
├── LICENSE                  # Apache-2.0
├── SECURITY.md              # threat model + responsible disclosure
├── CONTRIBUTING.md          # external-contribution policy (post-submission)
├── go.mod                   # module path: github.com/luxfi/pulsar-m
├── spec/                    # LaTeX specification source
│   ├── pulsar-m.tex         # main spec document
│   ├── parameters.tex       # ML-DSA-44/65/87 parameter sets
│   ├── system-model.tex     # threshold network / adversary model
│   ├── security-games.tex   # EUF-CMA + identifiable-abort games
│   ├── references.bib       # bibliography
│   └── pulsar-m.pdf         # built PDF (committed for reviewer convenience)
├── ref/go/                  # reference implementation (Go)
│   ├── cmd/genkat/          # KAT vector generator
│   └── pkg/pulsarm/         # core library
├── vectors/                 # KAT test vectors
│   ├── README.md
│   ├── dkg.json             # DKG transcripts
│   ├── keygen.json          # key-generation vectors
│   ├── sign.json            # single-party signing vectors (for cross-validation)
│   ├── threshold-sign.json  # threshold-signing vectors
│   ├── verify.json          # FIPS 204 verification vectors
│   └── transcripts/         # full-protocol KATs per (n, t) sweep
├── test/
│   ├── negative/            # malformed-input + protocol-deviation tests
│   ├── interoperability/    # cross-validation with FIPS 204 verifiers
│   └── fuzz/                # fuzz harnesses (Go native)
├── ct/dudect/               # constant-time analysis (dudect statistical tests)
├── bench/                   # benchmark configurations
├── estimator/               # security-parameter estimator
├── scripts/                 # build / test / bench / gen_vectors / SBOM
└── docs/                    # design notes + decision-record archive
```

## Class N1 — Output interchangeability

The N1 claim is asserted at four levels of evidence:

| Evidence | Where |
|---|---|
| Algorithmic argument | `spec/pulsar-m.tex` §6, Theorem 6.1 |
| Symbolic / Lean proof | `proofs/lean/Crypto/Pulsar_M/OutputInterchange.lean` (out-of-repo, separate audit artifact) |
| Test harness | `test/interoperability/` runs every KAT through 3 independent verifiers |
| Cross-implementation KATs | `vectors/sign.json` shares vectors with FIPS 204 reference |

## Class N4 — Public-key preservation across resharing

Multi-party proactive resharing preserves the group public key across
committee rotations (epoch boundaries), so a single long-lived public
identity persists while the secret-share custodians rotate.

| Evidence | Where |
|---|---|
| Algorithmic argument | `spec/pulsar-m.tex` §4.5 (Reshare protocol) |
| Symbolic / Lean proof | `proofs/lean/Crypto/Pulsar_M/Shamir.lean` (Shamir + ring extension) |
| Test harness | `vectors/transcripts/n*-t*-reshare.jsonl` carry pre/post-reshare public keys + verify both verify under unmodified ML-DSA |

## What this submission does NOT claim

Read `spec/known-limitations.tex` for the authoritative list. Highlights:

- **No identifiable abort under network partition** — Pulsar-M
  identifies aborting parties under synchronous network assumptions;
  asynchronous identifiable abort requires the Z-Chain Groth16
  accountability layer (separate Lux artifact, not part of this
  submission).
- **No 1-round signing** — the construction is 2-round by design. The
  rejection-sampling step inherent to FIPS 204 ML-DSA precludes a
  1-round threshold variant without a non-NIST-standard preprocessing
  oracle.
- **DKG without external randomness beacon** — Pulsar-M DKG produces
  unbiased coefficients under honest-majority assumptions but does not
  provide bias resistance under collusion. Production deployments
  bind a randomness beacon at the consensus layer (out of scope here).

## Comparison to related submissions

| Submission | Round count | Output interchange | Underlying lattice |
|---|---|---|---|
| **Pulsar-M** (this) | 2 | Byte-equal to FIPS 204 ML-DSA | Module-LWE (M-LWE) |
| Lux Corona (R-LWE sibling) | 2 | Byte-equal to FIPS 204 ML-DSA | Ring-LWE (R-LWE) |
| Raccoon | 3 | Compatible verification | Module-LWE |
| Ringtail (upstream academic) | 2 | Not interchange-tested at submission time | R-LWE |

The R-LWE sibling library lives at <https://github.com/luxfi/corona>
and is not part of this submission. It is included only in the
comparison because the production Lux Quasar consensus uses both
kernels as parallel options selectable per-chain.

## Contact

- Primary: <z@lux.network> (Lux Industries, Inc.)
- Submission coordination: <mptc@lux.network>
- Security disclosure: see `SECURITY.md`
- Public discussion: <https://github.com/luxfi/pulsar-mptc/discussions>

## Reproducibility commitment

The build, test, vector-generation, and benchmark scripts are
deterministic from a 48-byte seed. A reviewer reproducing the
submission tarball from `submission-2026-11-16` should obtain
byte-identical artifacts. Drift is a build bug; please open an issue.
