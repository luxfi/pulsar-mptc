# NIST MPTC Submission — Pulsar

This document is the cover sheet for the Pulsar submission to the
NIST Multi-Party Threshold Cryptography (MPTC) project. It is written
for NIST reviewers and points at every artifact a reviewer needs.

The repository is **active** (not frozen). The submission tarball is
cut from a tag on `main` at NIST's deadline; reviewer feedback and
post-submission patches land in this same repository so the artifact
chain stays auditable.

## At a glance

| Field | Value |
|---|---|
| Submission name | **Pulsar** |
| Submitting organisation | Lux Industries, Inc. |
| Algorithm | Threshold ML-DSA-65 (Module-LWE, FIPS 204-aligned) |
| Target NIST MPTC classes | **N1** (single-party-compatible threshold signing) + **N4** (multi-party key generation with public-key preservation across resharing) |
| Underlying primitive | FIPS 204 ML-DSA-65 |
| Round count | 2 rounds per signature |
| Signature output | **Byte-identical** to single-party FIPS 204 ML-DSA-65 |
| Repository | <https://github.com/luxfi/pulsar-mptc> |
| Submission tag | `submission-` (cut from `main` at deadline) |
| Spec PDF | `spec/pulsar.pdf` (built via `scripts/build.sh`) |
| License | Apache-2.0 (see `LICENSE`) |
| Patent posture | See `SECURITY.md` — Lux Industries grants a royalty-free patent license on the submitted construction to any MPTC-class N1/N4 implementer |

## Headline claim

> Every signature produced by a Pulsar threshold ceremony
> (DKG → Round-1 → Round-2 → Combine) is **bit-identical** to a signature
> produced by single-party FIPS 204 ML-DSA-65 on the same message and
> group public key.

This is the **Class N1** claim. A FIPS-validated ML-DSA verifier
(BoringSSL FIPS, AWS-LC, OpenSSL 3.0 PQ provider) accepts a Pulsar
signature without modification.

**Theorem framing — accepted-path correctness.** The Class N1
byte-equality theorem is conditional on acceptance: *if* the threshold
combine (and the single-party comparator) accepts — i.e., passes the
ML-DSA norm and rejection checks and the kappa rejection-sampling loop
converged — *then* the produced byte string equals the centralized
ML-DSA-65 signature on the same protocol-level inputs, under the
stated layout, algebraic, and byte-walk assumptions. Acceptance
probability is tracked separately through the `accept_signing_attempt`
predicate and the `mldsa_accept_lower_bound` operational bound; ML-DSA
rejection sampling remains probabilistic per FIPS 204, and the
deterministic EC model captures the accepted-path conditioning via
the predicate rather than via probabilistic Hoare logic.

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
2. **`spec/pulsar.pdf`** — full algorithm specification
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
git clone --branch submission- https://github.com/luxfi/pulsar-mptc
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
├── go.mod                   # module path: github.com/luxfi/pulsar
├── spec/                    # LaTeX specification source
│   ├── pulsar.tex         # main spec document
│   ├── parameters.tex       # ML-DSA-44/65/87 parameter sets
│   ├── system-model.tex     # threshold network / adversary model
│   ├── security-games.tex   # EUF-CMA + identifiable-abort games
│   ├── references.bib       # bibliography
│   └── pulsar.pdf         # built PDF (committed for reviewer convenience)
├── ref/go/                  # reference implementation (Go)
│   ├── cmd/genkat/          # KAT vector generator
│   └── pkg/pulsar/         # core library
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
│   └── threshold/           #   Pulsar threshold layer (stubs)
├── proofs/easycrypt/        # high-assurance EasyCrypt theories (13 files)
│   ├── Pulsar_N1.ec                       # Class N1 protocol spec + generic theorem
│   ├── Pulsar_N4.ec                       # Class N4 reshare pk-preservation
│   ├── Pulsar_N1_Memory.ec                # byte-memory model (0 axioms)
│   ├── Pulsar_N1_Signature_Codec.ec       # FIPS 204 sig codec
│   ├── Pulsar_N1_{Combine,Sign}_Layout.ec # per-side ABI byte layout
│   ├── Pulsar_N1_{Combine,Sign}_Refinement.ec # per-side byte-walk refinement scaffold
│   ├── Pulsar_N1_{Combine,Sign}_Wrapper.ec    # per-side wrapper module + bridge lemma
│   ├── Pulsar_N1_Extracted.ec             # concrete extracted N1 corollary
│   ├── lemmas/MLDSA65_Functional.ec       # FIPS 204 functional ops
│   └── lemmas/Pulsar_CT.ec                # constant-time obligations
├── proofs/lean-easycrypt-bridge.md        # Lean↔EC algebraic-bridge correspondence
├── scripts/                 # per-push + nightly gate orchestrators
│   ├── check-high-assurance.sh, test.sh   # per-push (REAL — under 60s)
│   ├── nightly.sh                         # cron-scheduled REAL-budget gate
│   ├── checks/                            # per-check independent scripts
│   └── build / bench / gen_vectors / SBOM / extract-jasmin-ec
└── docs/                    # design notes + decision-record archive
```

## Class N1 — Output interchangeability

The N1 claim is asserted at four levels of evidence:

| Evidence | Where |
|---|---|
| Algorithmic argument | `spec/pulsar.tex` §6, Theorem 6.1 |
| Symbolic / Lean proof | `proofs/lean/Crypto/Pulsar/OutputInterchange.lean` (out-of-repo, separate audit artifact) |
| Test harness | `test/interoperability/` runs every KAT through 3 independent verifiers |
| Cross-implementation KATs | `vectors/sign.json` shares vectors with FIPS 204 reference |

## Class N4 — Public-key preservation across resharing

Multi-party proactive resharing preserves the group public key across
committee rotations (epoch boundaries), so a single long-lived public
identity persists while the secret-share custodians rotate.

| Evidence | Where |
|---|---|
| Algorithmic argument | `spec/pulsar.tex` §4.5 (Reshare protocol) |
| Symbolic / Lean proof | `proofs/lean/Crypto/Pulsar/Shamir.lean` (Shamir + ring extension) |
| Test harness | `vectors/transcripts/n*-t*-reshare.jsonl` carry pre/post-reshare public keys + verify both verify under unmodified ML-DSA |

## High-assurance track (Jasmin + EasyCrypt)

Pulsar ships with a Jasmin + EasyCrypt high-assurance track aimed at
the same formal-method footing libjade gives the single-party ML-DSA
implementation: Jasmin sources whose verified compiler produces
bit-identical assembly, and EasyCrypt theories that machine-check
both functional correctness and constant-time against the
Barthe-Grégoire-Laporte leakage model.

The EasyCrypt track is **not theory shells** — every lemma in the
13-file tree is closed (admit budget enforced 0/0; see
`scripts/checks/ec-admits.sh`). What remains in the dependency cone
of the extracted N1 byte-equality theorem is a small, localized
axiom set:

| Artifact | Status | Location |
|---|---|---|
| libjade ML-DSA-65 single-party baseline (Jasmin + EasyCrypt) | Verified upstream; pinned, fetched on demand | `jasmin/ml-dsa-65/fetch.sh` |
| Pulsar Round-1 commit (Jasmin) | Implemented (~400 lines) | `jasmin/threshold/round1.jazz` |
| Pulsar Round-2 response (Jasmin) | Implemented (~600 lines) | `jasmin/threshold/round2.jazz` |
| Pulsar Combine (Jasmin) | Implemented (~400 lines) | `jasmin/threshold/combine.jazz` |
| Jasmin → EC extraction sanity | Per-push gate | `scripts/checks/extraction.sh` |
| jasmin-ct threshold (round1, round2, combine) | **BLOCKING — green** | `scripts/checks/jasmin.sh` |
| jasmin-ct libjade sign | Allowed-failure under #2 (precise write-up: `ct/jasmin-ct-libjade.md`) | same |
| Class N1 byte-equality (concrete extracted corollary) | **Proven as a lemma** (`pulsar_n1_byte_equality_extracted`) — composes the per-side wrapper-bridge equivs | `proofs/easycrypt/Pulsar_N1_Extracted.ec` |
| Class N1 byte-equality (generic, parametric) | **Proven as a theorem** (`pulsar_n1_byte_equality`) inside `section ClassN1` | `proofs/easycrypt/Pulsar_N1.ec` |
| Class N4 public-key preservation | **Proven** (concrete `ReshareHonest` module + `reshare_preserves_secret_honest` lemma) | `proofs/easycrypt/Pulsar_N4.ec` |
| Wrapper bridges (combine + sign) | **Proven as lemmas** (both — neither is an axiom) | `Pulsar_N1_{Combine,Sign}_Wrapper.ec` |
| Body separation (combine + sign) | **Proven as lemmas** | `Pulsar_N1_{Combine,Sign}_Refinement.ec` |
| Memory frame laws | **Proven** (0 axioms) | `Pulsar_N1_Memory.ec` |
| Build wiring | Per-check orchestrator; per-check scripts independently runnable | `scripts/check-high-assurance.sh` |

**Remaining trust footprint of the extracted N1 corollary**:

- **6 implementation-refinement axioms** — per-FIPS-204-stage
  byte-walks on the extracted Jasmin/libjade procedures, three per
  side, one per output component of the ML-DSA §6.2 inner loop:
    combine side (tracked #4):
      `combine_body_c_tilde_spec` — SampleInBall stage (roadmap S4)
      `combine_body_z_spec`       — Lagrange-aggregated z + decompose
                                    (roadmap S3 + S5)
      `combine_body_h_spec`       — MakeHint stage (roadmap S7)
    sign side (tracked #3):
      `sign_body_c_tilde_spec`, `sign_body_z_spec`, `sign_body_h_spec`
  Each axiom constrains a single component value the extracted
  body produces; the pack step (FIPS 204 §3.5.5) and memory-write
  step are structurally discharged. Roadmaps with named sub-claims
  are in `proofs/easycrypt/extraction/`. The `sign_body_*_spec`
  trio's ctx/rho_rnd ghost contract is pinned in
  `Pulsar_N1_Sign_Refinement.ec`.

  Why six axioms (not two): the prior "2 byte-walks over full
  3293-byte packed signatures" framing concealed the per-stage
  structure of the obligation. The per-stage split makes each
  obligation independently attackable against the corresponding
  `MLDSA65_Functional` op (`sample_in_ball`, `decompose_vec_k`,
  `vec_k_make_hint`) and exposes a Lean-bridge opportunity for the
  z-stage axioms (via `Crypto.Threshold.Lagrange.
  threshold_partial_response_identity`). The composite
  `*_compute_components_spec` and `*_compute_sig_spec` are now
  derived lemmas, not axioms.
- **2 accepted-path no-reject axioms** — protocol-correctness
  companions to the byte-walks
  (`combine_no_reject_on_accepted_honest_layout`,
  `sign_no_reject_on_accepted_honest_layout`). Each asserts
  `status = 0` for layout-conforming inputs CONDITIONED on the
  ML-DSA-65 accept event (`accept_signing_attempt`). ML-DSA
  rejection sampling remains probabilistic; the probability bound
  `mldsa_accept_lower_bound` (≈ 1 − 2^-128 after the kappa-bounded
  loop) is tracked operationally rather than via probabilistic
  Hoare logic — the deterministic EC model captures the accept-path
  conditioning via the predicate.
- **1 Lean-bridged algebraic axiom in the N1 cone**
  (`lagrange_inverse_eval` in `Pulsar_N1.ec`) — the
  Lagrange-interpolation identity at X = 0 over share_t. Bridged
  to `Crypto.Pulsar.Shamir.shamir_correct_at_target`.
- **3 additional Lean-bridged algebraic axioms in the N4 cone**
  (`add_share_zeroR`, `reconstruct_linear`, `shamir_correct` in
  `Pulsar_N4.ec`) — additive structure on share_t for reshare-
  preservation. Bridged to Mathlib `AddCommMonoid` +
  `Crypto.Threshold.Lagrange`.
- **Per-type FIPS 204 codec round-trip axioms** (~21 across
  `Pulsar_N1_Sign_Layout`, `Pulsar_N1_Combine_Layout`,
  `Pulsar_N1_Signature_Codec`, and `Pulsar_N1`) — encode/decode
  bidirectional round-trips guarded by `wf_*` well-formedness
  predicates, per-component length identities (sk: rho/K/tr/s1/s2/t0
  per FIPS 204 §3.5.4), share-polynomial-vector view (HIGH-5).
  Each reduces to the corresponding `MLDSA65_Functional` bit-level
  pack/unpack identity when that mechanization lands; for now they
  are small structural axioms over the abstract types.
- **0 section-local module-contract axioms** in the extracted
  corollary's cone (the corollary uses the concrete wrapper modules
  + proved bridge lemmas, not the section's declare-axiom
  hypotheses).

What this gives the NIST reviewer at submission time:

1. The libjade single-party verified baseline as the kernel under
   Pulsar's threshold layer — real, machine-checked, citable.
2. Real Jasmin sources for all three threshold-layer routines that
   call into the pinned libjade kernel.
3. The Class N1 byte-equality theorem **proven** in EasyCrypt as
   `pulsar_n1_byte_equality_extracted`, instantiating the generic
   `pulsar_n1_byte_equality` with concrete wrapper modules. Trust
   reduces to:
   - 6 named per-stage byte-walk obligations (3 components × 2
     sides — c_tilde / z / h on combine and sign);
   - 2 accepted-path no-reject axioms (combine + sign);
   - 1 Lean-bridged algebraic identity in the N1 cone
     (`lagrange_inverse_eval`);
   - per-type FIPS 204 codec round-trips with `wf_*`
     well-formedness guards.

   The N4 cone adds 3 more Lean-bridged algebraic axioms
   (`add_share_zeroR`, `reconstruct_linear`, `shamir_correct`).
4. The Class N4 reshare-preservation theorem **proven** as a
   concrete lemma on `ReshareHonest`.
5. jasmin-ct **blocking** on the threshold layer (round1, round2,
   combine all CT-clean); libjade sign advisory with a documented
   fix path.

What remains in the high-assurance track:

- The six per-stage byte-walk obligations
  (`combine_body_{c_tilde,z,h}_spec`, `sign_body_{c_tilde,z,h}_spec`)
  — multi-week proofs walking the corresponding regions of the
  extracted Jasmin / libjade procedures. Each is independently
  attackable; the z-stage axioms have a Lean-bridge path through
  `Crypto.Threshold.Lagrange.threshold_partial_response_identity`,
  and the c_tilde / h-stage axioms reduce to FIPS 204 hash and
  arithmetic op compositions over the MLDSA65_Functional layer.
  Roadmaps with named sub-claims are committed under
  `proofs/easycrypt/extraction/`.
- The two accepted-path no-reject obligations
  (`combine_no_reject_on_accepted_honest_layout`,
  `sign_no_reject_on_accepted_honest_layout`) — these reduce to the
  byte-walk completing the ML-DSA norm / rejection checks and the
  kappa rejection-sampling loop converging on the honest inputs,
  but are stated separately so the obligation surface is visible.
  The accompanying `mldsa_accept_lower_bound` probability tracking
  is an operational (non-mechanized) FIPS 204 acceptance bound.
- Mechanizing the Lean-bridged algebraic axioms inside EasyCrypt
  directly (1 in N1 cone, 3 in N4 cone) — would require porting a
  minimal polynomial-interpolation theory into EC.
- Concretizing the per-type FIPS 204 codec round-trips by linking
  them to `MLDSA65_Functional.pack_signature` /
  `MLDSA65_Functional.encode_sk` once the bit-level mechanization
  lands. The `wf_*` well-formedness predicates make the discharge
  point explicit.
- Closing the libjade jasmin-ct annotation gap (#2) upstream.

`scripts/check-high-assurance.sh` runs every per-push EC + jasmin-ct
+ extraction-sanity + bridge-guard + admit-budget + regression-guard
check at REAL budget. `scripts/nightly.sh` runs the heavier 1-h
fuzz + 10⁹-sample dudect runs that aren't appropriate for per-push.

## What this submission does NOT claim

Read `BLOCKERS.md` for the authoritative list. Highlights:

- **No identifiable abort under network partition** — Pulsar
  identifies aborting parties under synchronous network assumptions;
  asynchronous identifiable abort requires the Z-Chain Groth16
  accountability layer (separate Lux artifact, not part of this
  submission).
- **No 1-round signing** — the construction is 2-round by design. The
  rejection-sampling step inherent to FIPS 204 ML-DSA precludes a
  1-round threshold variant without a non-NIST-standard preprocessing
  oracle.
- **DKG without external randomness beacon** — Pulsar DKG produces
  unbiased coefficients under honest-majority assumptions but does not
  provide bias resistance under collusion. Production deployments
  bind a randomness beacon at the consensus layer (out of scope here).

## Comparison to related submissions

| Submission | Round count | Output interchange | Underlying lattice |
|---|---|---|---|
| **Pulsar** (this) | 2 | Byte-equal to FIPS 204 ML-DSA | Module-LWE (M-LWE) |
| Lux Corona (R-LWE sibling) | 2 | Byte-equal to FIPS 204 ML-DSA | Ring-LWE (R-LWE) |
| Raccoon | 3 | Compatible verification | Module-LWE |
| Corona (upstream academic) | 2 | Not interchange-tested at submission time | R-LWE |

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
submission tarball from `submission-` should obtain
byte-identical artifacts. Drift is a build bug; please open an issue.
