# Pulsar-M — NIST MPTC submission package

> **Threshold ML-DSA** — a 2-round threshold signing and DKG system whose
> generated signatures are verifiable by **unmodified FIPS 204 ML-DSA
> verification**. Targeting NIST MPTC Class N1 (signing) + N4 (ML keygen / DKG).

This repository is the **active NIST MPTC submission package** for Pulsar-M
and the canonical home for the submission artifacts (spec, KAT vectors,
reference implementation, interop harness, ct analysis, scripts). The
submission tarball for NIST is cut from a tag on `main` at deadline —
the repository itself stays active so reviewer feedback and post-
submission patches land here, not in a fork.

The production Go library has split into its own stable module identity
(`github.com/luxfi/pulsar` / `github.com/luxfi/corona`); this repository
keeps the original `github.com/luxfi/pulsar-m` module path because that
is the identifier NIST receives and reviews against.

## Library identities (post-2026 split)

`Pulsar-M` is the Module-LWE threshold ML-DSA construction. The 2-round
threshold protocol structure operates on ML-DSA-65's polynomial-vector-
over-`R_q` algebra so the per-party-aggregated signature is bit-identical
to a single-party FIPS 204 signature on the same message + public key.

| Repository | Module path | Role |
|---|---|---|
| **luxfi/pulsar-mptc** (this repo) | `github.com/luxfi/pulsar-m` | Active NIST MPTC submission package |
| [luxfi/pulsar](https://github.com/luxfi/pulsar) | `github.com/luxfi/pulsar` | Production Module-LWE Go library |
| [luxfi/corona](https://github.com/luxfi/corona) | `github.com/luxfi/corona` | Production Ring-LWE Go library (sibling kernel) |

The module path inside this submission package remains
`github.com/luxfi/pulsar-m` because that is the identifier NIST receives
and reviews against the submitted KAT vectors and spec. Downstream
consumers who want the live production library should pin
`github.com/luxfi/pulsar@v1.0.x` (Module-LWE) or
`github.com/luxfi/corona@v0.2.x` (Ring-LWE) instead.

> **Status: Research / Reference (not production hardened, not FIPS validated).**
> NIST-profile vectors use SHAKE / cSHAKE / KMAC. Any BLAKE3 deltas are
> experimental and out-of-scope for the MPTC submission.

## Why

NIST FIPS 204 (ML-DSA) is the only NIST-approved post-quantum digital
signature in 2026. Threshold variants of ML-DSA are not yet standardized —
NIST's [Multi-Party Threshold Cryptography](https://csrc.nist.gov/projects/threshold-cryptography)
project is collecting them now (IR 8214C, January 2026; first call package
deadline expected 2026-Nov-16).

Pulsar-M aims to enter that process with a credible, output-interchangeable
threshold ML-DSA candidate — built from the production-tested protocol
machinery already shipping in `luxfi/pulsar` (R-LWE), retargeted to the
M-LWE primitives ML-DSA itself uses.

The win, if Pulsar-M's Sign output is byte-equal to FIPS 204 Sign:
- Threshold-produced signatures verify under unmodified FIPS 204 verifiers.
- Existing FIPS-validated ML-DSA modules (BoringSSL FIPS, AWS-LC, OpenSSL
  3.0 PQ provider) consume Pulsar-M certs without code changes.
- The threshold layer can be Class-N-claimed at NIST without a parallel
  algorithm standardization track.

## Repository layout

```
pulsar-m/
├── BLOCKERS.md               PRODUCTION-GO-LIVE BLOCKER LIST (13 critical findings from red-team audit, 5 weak claims from scientist)
├── docs/                     human-readable design notes
│   ├── threat-model.md
│   ├── nist-mptc-category.md
│   ├── design-decisions.md
│   └── patent-notes-draft.md
├── spec/                     LaTeX technical specification (MPTC package)
│   ├── pulsar-m.tex          main spec
│   ├── security-games.tex    EUF-CMA / TS-UF / robustness / adaptive corr.
│   ├── system-model.tex      network / setup / abort / preprocessing
│   ├── parameters.tex        concrete parameter sets, lattice-estimator
│   └── references.bib
├── ref/
│   ├── go/                   reference implementation (Go, no assembly)
│   │   ├── cmd/              CLI entry points
│   │   ├── internal/         private helpers
│   │   └── pkg/              public API (sign/, dkg/, primitives/, hash/, fmt/)
│   └── c/                    conformance implementation (post-encoding-freeze)
├── vectors/                  Known Answer Tests (KATs)
│   ├── kat-v1.json           input/output vectors per MPTC §IO-Testing
│   ├── kat-v1.rsp            CAVS-style response file (compatibility)
│   └── transcripts/          full-protocol KATs (n,t sweeps)
├── bench/                    reproducible benchmark harness
├── test/                     fuzz / negative / interoperability tests
├── ct/dudect/                constant-time analysis harness
├── estimator/                lattice-estimator parameter scripts
├── jasmin/                   high-assurance Jasmin sources (initial track)
│   ├── ml-dsa-65/             libjade single-party baseline (fetched on demand)
│   └── threshold/             Pulsar-M threshold layer (stubs)
├── proofs/easycrypt/         high-assurance EasyCrypt theories (theory shells)
│   ├── PulsarM_N1.ec          Class N1 byte-equality reduction
│   ├── PulsarM_N4.ec          Class N4 public-key preservation
│   └── lemmas/PulsarM_CT.ec   constant-time obligations
├── scripts/                  build / test / bench / gen_vectors / sbom / check-high-assurance
└── go.mod
```

## Quickstart

The repository is **live and self-validating**. A fresh clone runs the
full submission gate (build + test + KAT replay + Class N1 interop)
end-to-end in under 30 seconds:

```bash
git clone https://github.com/luxfi/pulsar-mptc
cd pulsar-mptc
./scripts/build.sh                  # Go ref + spec PDF (MacTeX / TeX Live)
./scripts/test.sh                   # unit + no-secret-logs + KAT replay + N1 interop
./scripts/gen_vectors.sh            # deterministic KAT regen
./scripts/check-high-assurance.sh   # Jasmin + EasyCrypt (skips if tools missing)
./scripts/bench.sh                  # signing / verification benchmarks
```

`scripts/build.sh` and `scripts/test.sh` exit non-zero on any failure.
The reproducibility property is the load-bearing CI invariant.

## NIST MPTC submission

| package element | location | status |
|---|---|---|
| Technical Specification | `spec/pulsar-m.pdf` (1,536-line LaTeX → 28 pages, 491 KB) | drafted; encoding freeze 2026-Aug |
| Reference Implementation | `ref/go/pkg/pulsarm/` (89.7% coverage) | shipped |
| KAT vectors | `vectors/{dkg,keygen,sign,threshold-sign,verify}.json` | deterministic from seed |
| Class N1 E2E interop | `test/interoperability/` (19/19 subtests vs cloudflare/circl) | passing |
| Symbolic / Lean proofs | `~/work/lux/proofs/lean/Crypto/Pulsar_M/` (3 files, **zero `sorry`**) | mechanized |
| Constant-time analysis | `ct/dudect/` | harness present; results TBD |
| Jasmin high-assurance | `jasmin/{ml-dsa-65,threshold}/` | initial track (libjade fetch + stubs) |
| EasyCrypt theories | `proofs/easycrypt/PulsarM_{N1,N4}.ec` + `lemmas/PulsarM_CT.ec` | theory shells |
| Report on Experimental Evaluation | `bench/results/REPORT.md` | TBD |
| Patent posture | `docs/patent-notes-draft.md` | drafted |
| License | `LICENSE` (Apache-2.0) | ✓ |
| Build/test/bench scripts | `scripts/` | shipped |
| SUBMISSION cover sheet | `SUBMISSION.md` | shipped |

Target dates:
- **2026-Jul-20** preview writeup (NIST third preview deadline)
- **2026-Nov-16** package submission (NIST first call deadline; submission tag `submission-2026-11-16` cut from `main`)

## Relationship to upstream

| repo | what | hash family |
|---|---|---|
| [luxfi/ringtail](https://github.com/luxfi/ringtail) | academic R-LWE 2-round threshold sig (Boschini–Kaviani–Lai–Malavolta–Takahashi–Tibouchi, ePrint 2024/1113) | BLAKE3 |
| [luxfi/pulsar](https://github.com/luxfi/pulsar) | production fork of Ringtail with Pedersen DKG + proactive resharing | SHA-3 / cSHAKE256 (canonical), BLAKE3 (legacy) |
| **luxfi/pulsar-m** (this repo) | **Module-LWE sibling: threshold ML-DSA** | **SHA-3 / SHAKE256** (NIST profile) only |

## Security

`SECURITY.md` describes how to disclose vulnerabilities and what's in-scope for
bug bounty.

## License

Apache-2.0 — same as `luxfi/pulsar` and `luxfi/ringtail`. See `LICENSE`.
