# Pulsar-M — EasyCrypt theories

This directory holds the **EasyCrypt** theories for Pulsar-M's high-
assurance track. EasyCrypt (https://github.com/EasyCrypt/easycrypt) is
the machine-checked proof assistant for cryptographic protocols paired
with Jasmin (`../../jasmin/`). The libjade single-party ML-DSA-65
EasyCrypt theories are imported from `../../jasmin/ml-dsa-65/libjade/`
(fetched on demand); the Pulsar-M-specific theories live here.

## Status — theory shells

Every `.ec` file in this directory is a **theory shell**:

- The theory header (`require import ...`) is committed.
- Module types and the top-level signature for each statement are committed.
- Every `lemma` and `equiv` body is `admit` with a `TODO` comment.

This is honest and standard for an MPTC initial submission. NIST
reviewers see:

1. The shape of the high-assurance reduction.
2. The libjade ML-DSA-65 functional + constant-time theorems we plan
   to compose against.
3. The Pulsar-M-specific obligation surface (Class N1 byte-equality;
   Class N4 public-key preservation; constant-time of secret-dependent
   threshold-layer routines).

Closing the `admit`s is a non-trivial effort tracked across the MPTC
submission process. The shell exists so the proof surface is exposed
and reviewable today.

## Files

| File | Theorem |
|---|---|
| `PulsarM_N1.ec` | **Class N1**: byte-equality of Pulsar-M threshold output to single-party FIPS 204 ML-DSA-65 output under honest quorum |
| `PulsarM_N4.ec` | **Class N4**: public-key preservation across Pulsar-M proactive resharing (committee rotation) |
| `lemmas/PulsarM_CT.ec` | **Constant-time**: every Jasmin threshold-layer routine that touches secret share material is CT under the Barthe-Grégoire-Laporte leakage model |

## Conventions

- `admit` markers are paired with `(* TODO: prove this once Jasmin
  extraction is wired *)` comments. Every `admit` in this tree is one
  of these — none are silent.
- Theory names match libjade's naming convention (`PulsarM_<Class>`
  for top-level reductions, `lemmas/PulsarM_<Topic>` for supporting
  lemmas).
- The libjade ML-DSA-65 import path is `MLDSA65_Functional` and
  `MLDSA65_CT`, matching the libjade theory names in
  `proof/crypto_sign/dilithium/dilithium3/`.

## How to check

```bash
../../scripts/check-high-assurance.sh
```

The script is skip-friendly: if `easycrypt` is not on PATH, it prints
a clear skip message and exits 0. When `easycrypt` is present it runs
`easycrypt check` on each `.ec` file in this tree. `admit`-bearing
theories still type-check; they just don't close the proof obligation
— that's by design at the initial-submission stage.

## Citations

- Barthe, Grégoire, Laporte. *Secure compilation of side-channel
  countermeasures: The case of cryptographic constant-time.* CSF 2018.
- Barbosa, Barthe, Doczkal, Don, Fehr, Grégoire, Huang, Hülsing, Lee,
  Wu. *Fixing and Mechanizing the Security Proof of Fiat–Shamir with
  Aborts and Dilithium.* CRYPTO 2023.
- Almeida et al. *Formally verifying Kyber.* CRYPTO 2024.
- libjade ML-DSA EasyCrypt theories — https://github.com/formosa-crypto/libjade/tree/main/proof
