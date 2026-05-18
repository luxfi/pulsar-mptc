# IETF/CFRG Draft Skeleton — Threshold ML-DSA

> **Working draft** of an IETF Internet-Draft proposing Pulsar for
> CFRG / standardization. NOT yet submitted to IETF. This file is
> the technical substance an editor would convert to the IETF XML
> / Markdown format.

```
Document name: draft-lux-pulsar-threshold-mldsa-00
Title:         Threshold ML-DSA for Distributed Signing and
               Blockchain Applications
Status:        Internet-Draft (Informational, intended Experimental
               then Standards Track)
Author:        Lux Industries, Inc. (z@lux.network)
Date:          2026-05-18 (this draft); intended submission to
               CFRG mailing list 2026-Q4.
```

## Abstract

This document specifies a threshold variant of the FIPS 204 ML-DSA
post-quantum signature algorithm. The construction produces
signatures that are byte-identical to single-party FIPS 204 ML-DSA-65
signatures and verify under any unmodified FIPS 204 conformant
verifier. The threshold protocol consists of a distributed key
generation (DKG) phase and a 2-round signing protocol with
identifiable abort under synchronous network assumptions.

## 1. Introduction

### 1.1 Motivation

Blockchain validator sets, certificate-authority back-ends, and
high-value treasury custody all benefit from threshold signing —
no single party holds the secret, but the deployed verifier sees
only a standard single-party signature. This specification defines
such a threshold construction for the NIST-standardized post-quantum
signature algorithm ML-DSA (FIPS 204).

### 1.2 Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in
this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174].

### 1.3 Relationship to FIPS 204

This document specifies a threshold protocol that PRODUCES a FIPS
204 ML-DSA-65 signature. It does NOT modify the FIPS 204 algorithm
itself. Verifiers conforming to FIPS 204 verify Pulsar signatures
without modification.

### 1.4 Relationship to FIPS 205 (SLH-DSA)

This draft covers Threshold ML-DSA only (Tier 1). Threshold variants
of FIPS 205 SLH-DSA are out of scope; see §11 (Future work) for the
experimental research profile (Tier 3).

## 2. Notation

| Symbol | Meaning |
|---|---|
| `n` | Total parties in the quorum |
| `t` | Threshold (minimum signers) |
| `Q ⊆ {1,...,n}` | Active signing quorum, |Q| ≥ t |
| `sk_i` | Party i's secret key share |
| `pk` | Group public key (shared) |
| `M` | Message to be signed |
| `ctx` | Context string (FIPS 204 §3.7, up to 255 bytes) |
| `σ` | Final signature (byte-identical to FIPS 204 output) |
| `λ_i^Q` | Lagrange coefficient at zero for party i with respect to Q |
| `R_q` | Polynomial ring Z_q[X]/(X^256+1), q = 8380417 |

## 3. Parameter sets

This document specifies three parameter sets, matching FIPS 204 §4
Table 1 exactly:

| Set | NIST Category | pk bytes | sk_i bytes (per party) | sig bytes |
|---|---|---|---|---|
| Pulsar-44 | 2 | 1312 | TBD | 2420 |
| Pulsar-65 | 3 (RECOMMENDED) | 1952 | TBD | 3309 |
| Pulsar-87 | 5 | 2592 | TBD | 4627 |

The per-party `sk_i` size depends on the secret-sharing scheme used
(Shamir over R_q^l + Pedersen blinding); see §5 (DKG).

Implementations MUST support Pulsar-65. Implementations SHOULD
support Pulsar-44 and Pulsar-87.

## 4. Threat model

### 4.1 Adversary model

- **Static corruption**: the adversary chooses up to t−1 parties to
  corrupt before protocol start.
- **Rushing**: the adversary observes honest parties' messages in
  each round before sending its own.
- **Byzantine**: corrupted parties may deviate arbitrarily.
- **Synchronous network**: a known upper bound Δ on message delivery
  is assumed; protocol aborts on Δ-timeout.

Adaptive corruption is out of scope for this draft.

### 4.2 Security goals

- **EUF-CMA-threshold**: no PPT adversary corrupting up to t−1 parties
  can produce a forgery on a non-queried message.
- **Output interchangeability (Class N1)**: every honest-quorum
  signature is bit-identical to a single-party FIPS 204 signature on
  the same message and group public key.
- **Public-key preservation (Class N4)**: proactive resharing
  preserves the group public key.
- **Identifiable abort**: every aborting party is identifiable by
  the remaining quorum AND by any third party with access to the
  abort-evidence record.

## 5. Distributed Key Generation (DKG)

### 5.1 Setup

The DKG produces:
- A group public key `pk` (FIPS 204-format, 1952 bytes for ML-DSA-65)
- Per-party secret shares `sk_1, ..., sk_n` such that any t-subset
  reconstructs the implicit secret `s_1 = f.eval(0)` where `f` is
  the (hidden) sharing polynomial.

### 5.2 Protocol

[TBD — Pedersen-VSS over R_q^l with public-key commitment binding.
See `spec/pulsar.tex` §4.1 for the detailed protocol description.]

### 5.3 Complaint and blame

[TBD — see `spec/pulsar.tex` §5.2 and the abort-evidence TLV in
`ref/go/pkg/pulsar/abort.go`.]

## 6. Threshold signing (2 rounds)

### 6.1 Round 1 — commitment

Each party `i ∈ Q` independently:

1. Derives the per-call randomness `rho_rnd_i` from a session
   identifier + a fresh entropy contribution.
2. Samples a mask polynomial vector `y_i ∈ R_q^l` via FIPS 204 §3.5.4
   ExpandMask on a per-party seed.
3. Computes the high-bits commitment `w1_i = HighBits(A · y_i)`
   where `A = ExpandA(rho)` from the group public key.
4. Broadcasts `w1_i` to the other parties in Q.

### 6.2 Aggregator: challenge derivation

After receiving all `n_Q` commitments:

1. Aggregates `w1_agg = Σᵢ∈Q λ_i^Q · w1_i` (Lagrange-weighted sum at zero,
   coordinate-wise).
2. Computes `c_tilde = SHAKE256(mu_ext || w1Encode(w1_agg), 32)`
   where `mu_ext = SHAKE256(0x00 || |ctx| || ctx || M, 64)` is the
   FIPS 204 §5.4.1 ExternalMu.
3. Broadcasts `c_tilde` to all parties in Q.

### 6.3 Round 2 — response

Each party `i ∈ Q`:

1. Computes `c = SampleInBall(c_tilde)` (FIPS 204 §3.5.1).
2. Computes `z_i = y_i + c · s_1,i` where `s_1,i` is party i's share
   of the FIPS 204 `s_1` secret.
3. Broadcasts `z_i` to the aggregator.

### 6.4 Aggregator: combine

After receiving all `n_Q` partial responses:

1. Aggregates `z = Σᵢ∈Q λ_i^Q · z_i` (Lagrange-weighted sum, coordinate-wise).
2. Verifies the FIPS 204 §6.2 R1-R4 rejection conditions on the
   aggregated values:
   - R1: `‖z‖∞ < γ1 − β`
   - R2: `‖r0‖∞ < γ2 − β` where `r0 = LowBits(A·z − c·t1·2^d)`
   - R3: `‖c·t0_agg‖∞ < γ2`
   - R4: `weight(h) ≤ ω` where `h = MakeHint(...)`
3. If any condition fails: increment kappa, restart the protocol
   from Round 1 with kappa-incremented seeds.
4. If all conditions pass: pack `σ = sigEncode(c_tilde, z, h)` per
   FIPS 204 §3.5.5 and broadcast `σ`.

### 6.5 Output interchangeability claim

The output `σ` is bit-identical to:
```
FIPS204.Sign_internal(sk_centralized, M', rho_rnd)
```
where:
- `sk_centralized = Lagrange-interpolate-at-zero(Q, [sk_i])`
- `M' = 0x00 || |ctx| || ctx || M`
- `rho_rnd` is the same per-call randomness derivation as the centralized version.

Verifiers MUST accept `σ` under any FIPS 204 conformant Verify
implementation without modification.

## 7. Verification

The verification algorithm is the unmodified FIPS 204 §6.3 Verify.
This document does NOT specify a Pulsar-specific verifier.

## 8. Proactive resharing (Class N4)

[TBD — see `spec/pulsar.tex` §4.5. Key property: the group public
key is preserved across reshare boundaries.]

## 9. Abort-evidence format

[TBD — TLV-encoded per-kind evidence with one-byte kind tag + per-kind
structured fields. See `ref/go/pkg/pulsar/abort.go` for the wire
format.]

## 10. Test vectors

Conformance test vectors are published at:
- `https://github.com/luxfi/pulsar-mptc/tree/main/vectors/`

Covering:
- DKG transcripts for n=3..21, t=2..14
- Sign vectors at (n, t) parameter sweeps
- Verify vectors matching FIPS 204 single-party reference
- Reshare transcripts preserving pk

## 11. Security considerations

### 11.1 Post-quantum hardness

Pulsar inherits the M-LWE / M-SIS hardness of FIPS 204 ML-DSA. This
draft does NOT establish PQ hardness independently. See NIST FIPS
204 Appendix B for the hardness analysis.

### 11.2 Threshold-specific security

The DKG soundness and signing unforgeability reductions are stated
in `spec/pulsar.tex` §5 + `pulsar-m/unforgeability.tex`. Machine-
checked proof artifacts in EasyCrypt + Lean 4 are at:
- `https://github.com/luxfi/pulsar-mptc/tree/main/proofs/`

### 11.3 Constant-time

Implementations MUST be constant-time on:
- Per-party share material
- Per-call randomness `rho_rnd` and derived mask `y_i`
- Any code path branching on rejection-condition outcomes when the
  rejection has not yet been decided

Implementations MAY be variable-time on:
- Final accept/reject decision (per FIPS 204 §3.3 — the kappa
  counter is not secret-dependent on long-term keys)
- Pure-public verification

### 11.4 Replay and session binding

Implementations MUST bind the signing session to a unique session
identifier and reject duplicate or stale sessions. Suitable session
identifiers include:
- A randomly-sampled 32-byte nonce contributed by all participants
- A blockchain block hash + height + transaction index
- A monotonic counter with cryptographic commitment

### 11.5 Identifiable abort under network partition

Identifiable abort is guaranteed ONLY under synchronous network
assumptions. Under network partition, deviating parties may be
indistinguishable from delayed parties. Production deployments
SHOULD bind the synchronous-network timer to consensus-layer
finality.

## 12. IANA considerations

This document requests no IANA actions.

## 13. References

### 13.1 Normative references

- [FIPS204] National Institute of Standards and Technology, "Module-
  Lattice-based Digital Signature Standard", NIST FIPS 204,
  August 2024.
- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in
  RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.

### 13.2 Informative references

- [RFC9882] (et al.) — ML-DSA usage in CMS / X.509 contexts.
- [PULSAR-SPEC] Lux Industries, "Pulsar Threshold ML-DSA
  Specification v0.1", spec/pulsar.tex in the Pulsar repository.
- [PULSAR-PROOFS] Lux Industries, "Pulsar EasyCrypt + Lean Refinement
  Proofs", proofs/ in the Pulsar repository.
- [FROST] Komlo, C. and Goldberg, I., "FROST: Flexible Round-Optimized
  Schnorr Threshold Signatures", SAC 2020.

### 13.3 URIs

- Spec PDF: <https://github.com/luxfi/pulsar-mptc/blob/main/spec/pulsar.pdf>
- Reference impl: <https://github.com/luxfi/pulsar-mptc/tree/main/ref/go>
- Test vectors: <https://github.com/luxfi/pulsar-mptc/tree/main/vectors>
- EasyCrypt proofs: <https://github.com/luxfi/pulsar-mptc/tree/main/proofs/easycrypt>

## 14. Future work

- **Threshold SLH-DSA (FIPS 205) — Tier 3 experimental profile.**
  Not in this draft.
- **Asynchronous identifiable abort.** Requires a separate
  accountability protocol (e.g., the Lux Z-Chain Groth16 layer).
- **Adaptive corruption security.** Currently static-corruption only.
- **Batch signing optimisations.** Multiple messages with shared
  Round-1 commitments.

## Authors' addresses

```
Lux Industries, Inc.
z@lux.network
mptc@lux.network
```

---

**Document metadata**

- File: `docs/ietf-draft-skeleton.md`
- Version: v0.1 (skeleton, pre-IETF submission)
- Date: 2026-05-18
- Intended IETF document name: `draft-lux-pulsar-threshold-mldsa-00`
- Conversion path: this Markdown skeleton converts to xml2rfc XML
  via `mmark` or `kramdown-rfc` before submission to the IETF
  datatracker.
