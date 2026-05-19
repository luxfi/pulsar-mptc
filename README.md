# pulsar-mptc — consolidated into `luxfi/pulsar`

> **This repository is archived.** All content was consolidated into
> [`github.com/luxfi/pulsar`](https://github.com/luxfi/pulsar) on
> 2026-05-18 in tag **`v1.0.8`** to honor the project's "one and only
> one way to do everything" invariant.

## Where everything went

| Was here | Is now |
|---|---|
| `pulsar-mptc/SUBMISSION.md` | `pulsar/SUBMISSION.md` |
| `pulsar-mptc/NIST-SUBMISSION.md` | `pulsar/NIST-SUBMISSION.md` |
| `pulsar-mptc/SPEC.md`, `SUITE.md`, `HANZO-CRYPTO-SUITE.md`, `INFORMATION-ARCHITECTURE.md`, `ROADMAP.md`, `CHANGELOG.md`, `SYNC-STATUS.md`, `STATUS-SUBMISSION-READINESS.md`, `SINGLE-IMPL-PLAN.md` | `pulsar/<same>` |
| `pulsar-mptc/PATENTS.md`, `AXIOM-INVENTORY.md`, `PROOF-CLAIMS.md`, `FIPS-TRACEABILITY.md`, `TRUSTED-COMPUTING-BASE.md` | `pulsar/<same>` |
| `pulsar-mptc/docs/{ietf-draft-skeleton,magnetar,evaluation,patent-claims,x-wing-sig}.md` | `pulsar/docs/<same>` |
| `pulsar-mptc/proofs/easycrypt/` (13 EC theories, 0/0 admits) | `pulsar/proofs/easycrypt/` |
| `pulsar-mptc/proofs/lean-easycrypt-bridge.md` | `pulsar/proofs/lean-easycrypt-bridge.md` |
| `pulsar-mptc/jasmin/` (`lib/`, `ml-dsa-65/`, `threshold/`) | `pulsar/jasmin/` |
| `pulsar-mptc/vectors/` | `pulsar/vectors/` |
| `pulsar-mptc/test/interoperability/n1_class_test.go` | `pulsar/test/interoperability/n1_class_test.go` |
| `pulsar-mptc/ct/dudect/` | `pulsar/ct/dudect/` |
| `pulsar-mptc/scripts/{cut-submission,check-high-assurance,check-lean-bridge,gen_vectors,nightly,sbom,extract-jasmin-ec}.sh` | `pulsar/scripts/<same>` |

## Why consolidated

- One canonical home — code + spec + proofs + KAT vectors + cut tool
  in a single repo, single Go module, single git history.
- No backwards compatibility: a single source of truth for the NIST
  MPTC submission package.
- The Go module path `github.com/luxfi/pulsar-mptc` is no longer
  active; depend on `github.com/luxfi/pulsar` at `v1.0.8` or later.

## How to cut the NIST submission tarball

Use `scripts/cut-submission.sh` in `luxfi/pulsar`:

```sh
git clone https://github.com/luxfi/pulsar.git
cd pulsar
bash scripts/cut-submission.sh submission-2026-11-16
```

The cut produces `submission-2026-11-16.tar.gz` containing the full
spec + reference implementation + EC proofs + Jasmin sources + KAT
vectors + reproducibility scripts.

## Final state

- `luxfi/pulsar` v1.0.8 (consolidated; tag `v1.0.8`)
- All proof gates green: EC admit budget 0/0, Lean ↔ EC bridge 5/5,
  jasmin-ct 3/3, N1 interop 19/19 vs cloudflare/circl FIPS 204
- Cryptographer sign-off: `pulsar/CRYPTOGRAPHER-SIGN-OFF.md`
  (APPROVED WITH GATES — all gates disclosure-only, no code change)

---

**Archived 2026-05-18.** This repository is read-only. File issues
and PRs at <https://github.com/luxfi/pulsar>.
