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
5. **`BLOCKERS.md`** — what the construction does NOT
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
├── jasmin/                  # high-assurance Jasmin sources (initial track)
│   ├── ml-dsa-65/           #   libjade single-party baseline (fetched on demand)
│   └── threshold/           #   Pulsar-M threshold layer (stubs)
├── proofs/easycrypt/        # high-assurance EasyCrypt theories (theory shells)
│   ├── PulsarM_N1.ec        #   Class N1 byte-equality reduction
│   ├── PulsarM_N4.ec        #   Class N4 public-key preservation
│   └── lemmas/PulsarM_CT.ec #   constant-time obligations
├── scripts/                 # build / test / bench / gen_vectors / SBOM / check-high-assurance
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

## High-assurance track (Jasmin + EasyCrypt)

Pulsar-M ships with an **initial** Jasmin + EasyCrypt high-assurance
track. The intent is to land on the same formal-method footing libjade
gives the single-party ML-DSA implementation: Jasmin sources whose
verified compiler produces bit-identical assembly, and EasyCrypt
theories that machine-check both functional correctness and constant-
time against the Barthe-Grégoire-Laporte leakage model.

This is honest scaffolding, not a closed proof. What ships at the
2026-11-16 submission tag:

| Artifact | Status | Location |
|---|---|---|
| libjade ML-DSA-65 single-party baseline (Jasmin + EasyCrypt) | Verified upstream; fetched on demand | `jasmin/ml-dsa-65/fetch.sh` |
| Pulsar-M Round-1 commit (Jasmin) | **Stub** — signature committed, body is `// TODO` | `jasmin/threshold/round1.jazz` |
| Pulsar-M Round-2 response (Jasmin) | **Stub** — signature committed, body is `// TODO` | `jasmin/threshold/round2.jazz` |
| Pulsar-M Combine (Jasmin) | **Stub** — signature committed, body is `// TODO` | `jasmin/threshold/combine.jazz` |
| Class N1 byte-equality (EasyCrypt) | **Theory shell** — lemma stated, proof body `admit` | `proofs/easycrypt/PulsarM_N1.ec` |
| Class N4 public-key preservation (EasyCrypt) | **Theory shell** — lemma stated, proof body `admit` | `proofs/easycrypt/PulsarM_N4.ec` |
| Constant-time obligations (EasyCrypt) | **Theory shell** — lemmas stated, proof bodies `admit` | `proofs/easycrypt/lemmas/PulsarM_CT.ec` |
| Build wiring | Complete (skip-friendly) | `scripts/check-high-assurance.sh` |

Every `admit` in the EasyCrypt tree is paired with a `(* TODO: prove
this once Jasmin extraction is wired *)` comment. Every `.jazz` stub
has its function signature in Jasmin syntax and a body that is a
single `// TODO: jasmin implementation` marker block. No fake proofs;
no fake implementations.

What this gives the NIST reviewer at submission time:

1. The libjade single-party verified baseline as the kernel under
   Pulsar-M's threshold layer — real, machine-checked, citable.
2. The exposed obligation surface for the Pulsar-M-specific work:
   which Jasmin routines need implementing, which CT lemmas need
   proving, and how the Class N1 reduction composes with libjade's
   functional theorem.
3. A skip-friendly check script (`scripts/check-high-assurance.sh`)
   that exits 0 on machines without `jasminc`/`easycrypt` and runs
   the tools when they are present.

Closing the `admit`s + filling the `.jazz` bodies is multi-month work
tracked across MPTC submission rounds. The initial track exists so
the high-assurance posture is reviewable today, not deferred to "the
next submission".

## What this submission does NOT claim

Read `BLOCKERS.md` for the authoritative list. Highlights:

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
