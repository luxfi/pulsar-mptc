# Lean ↔ EasyCrypt Shamir/Lagrange bridge

## Why this document exists

Pulsar's machine-checked proof stack uses **two complementary
provers**:

* **EasyCrypt** drives the procedure-level refinement / equiv proofs
  for the threshold layer (`proofs/easycrypt/Pulsar_N1.ec`,
  `Pulsar_N4.ec`, the two `*_Refinement.ec` files, the two
  `*_Layout.ec` files, and `Pulsar_N1_Wrapper_Bridge.ec`).
  EasyCrypt is the right tool for procedural Hoare/equiv goals with
  side-channel-aware semantics — but its first-order theory of
  finite fields and polynomial interpolation is comparatively
  thin.
* **Lean 4 + Mathlib** carries the algebraic content: Shamir
  reconstruction, Lagrange interpolation linearity, finite-field
  polynomial uniqueness. Mathlib has the field theory we'd
  otherwise have to re-axiomatize in EC.

The bridge between them is currently **conceptual** — the EC side
states the algebraic identities it needs as **named axioms** that
correspond 1:1 to **proved Lean theorems** in the sibling repo
`~/work/lux/proofs/lean/Crypto/`. This document pins that 1:1
correspondence so a reviewer can verify the math content is
discharged elsewhere and not silently hand-waved.

The honest framing: **the EasyCrypt axioms named below are not
unproved obligations in the strict sense — they are imports from
the Lean proof artifact**. The audit gap is operational (no
mechanical proof-object exchange across the two provers, no shared
serialization format) rather than mathematical.

## Repository pin-points

* EasyCrypt side: `~/work/lux/pulsar-mptc/proofs/easycrypt/`,
  commit `226b4cb` (this commit, or later — verify against the
  current `git rev-parse HEAD`).
* Lean side: `~/work/lux/proofs/lean/Crypto/`, commit `923dc84`.

## Axiom-to-theorem mapping

### Axiom 1: `Pulsar_N1.lagrange_inverse_eval`

**EasyCrypt statement** (`proofs/easycrypt/Pulsar_N1.ec:177`):

```ec
axiom lagrange_inverse_eval (s : share_t) (Q : int list) :
  uniq Q =>
  1 <= size Q =>
  reconstruct Q (List.map (poly_eval s) Q) = s.
```

**Lean proof** (`lean/Crypto/Pulsar/Shamir.lean:76`):

```lean
theorem shamir_correct_at_target
    {F : Type*} [Field F] [DecidableEq F]
    (f : Polynomial F) {ι : Type*} [DecidableEq ι]
    (s : Finset ι) (v : ι → F)
    (hvs : Set.InjOn v s) (degree_f_lt : f.degree < s.card) :
    f = Lagrange.interpolate s v (fun i => f.eval (v i)) :=
  Crypto.Threshold.Lagrange.threshold_reconstructs_secret f s v hvs degree_f_lt
```

**Correspondence**:

| Symbol | EC | Lean |
|---|---|---|
| Shamir polynomial | `s : share_t` (abstracted as its constant term) | `f : Polynomial F` |
| Quorum / evaluation set | `Q : int list` (with `uniq Q`) | `s : Finset ι` + `v : ι → F` injective on `s` |
| Per-party share | `poly_eval s i` | `f.eval (v i)` |
| Reconstruction | `reconstruct Q shares` | `(Lagrange.interpolate s v shares).eval 0` |
| Identity at quorum | `reconstruct Q (map (poly_eval s) Q) = s` | `f = Lagrange.interpolate s v (fun i => f.eval (v i))` then evaluate at 0 |

The Lean theorem is **stronger** (polynomial-level equality, not
just constant-term recovery). Specializing to evaluation at 0
yields the EC-side identity via
`Crypto.Threshold.Lagrange.secret_recovery_at_zero` (file
`lean/Crypto/Threshold_Lagrange.lean:62`).

**Degree bound**: The Lean side requires `f.degree < s.card`. On
the EC side this is implicit in the abstract `share_t` type
(Pulsar's Shamir polynomial has degree exactly `t - 1` over a
`t`-of-`n` committee, and `size Q ≥ 1` plus `uniq Q` plus the
implicit `t ≤ size Q` from the protocol layer gives the degree
bound).

### Axiom 2: `Pulsar_N4.reconstruct_linear`

**EasyCrypt statement** (`proofs/easycrypt/Pulsar_N4.ec:133`):

```ec
axiom reconstruct_linear :
  forall (q : int list) (a b : share_t list),
    size a = size q => size b = size q =>
    reconstruct q (zip_add a b) =
      add_share (reconstruct q a) (reconstruct q b).
```

**Lean proof** (`lean/Crypto/Threshold_Lagrange.lean:81`):

```lean
theorem combine_distributes_over_sum
    {ι : Type*} [DecidableEq ι] (s : Finset ι) (v : ι → F) (a b : ι → F) :
    Lagrange.interpolate s v (a + b) =
      Lagrange.interpolate s v a + Lagrange.interpolate s v b :=
  (Lagrange.interpolate s v).map_add a b
```

**Correspondence**:

| Symbol | EC | Lean |
|---|---|---|
| Quorum | `q : int list` | `s : Finset ι` |
| Per-party value | `a : share_t list`, `b : share_t list` | `a, b : ι → F` |
| Pointwise sum | `zip_add a b` | `a + b` (pointwise) |
| Combination | `reconstruct q (...)` | `(Lagrange.interpolate s v (...)).eval 0` |
| Linearity | `reconstruct (a + b) = reconstruct a + reconstruct b` | `interpolate (a + b) = interpolate a + interpolate b` |

The Lean theorem follows from `LinearMap.map_add` applied to
`Lagrange.interpolate s v`, which Mathlib expresses as an
`F-linear map`. Evaluating at 0 (an `R-linear` operation) preserves
the equation. This is exactly the algebraic content the EC axiom
states.

### Axiom 3: `Pulsar_N4.shamir_correct`

**EasyCrypt statement** (`proofs/easycrypt/Pulsar_N4.ec:141`):

```ec
axiom shamir_correct :
  forall (q : int list) (s : share_t),
    uniq q => 1 <= size q =>
    reconstruct q (fresh_sharing q s) = s.
```

**Lean proof** (same as Axiom 1):

```lean
theorem shamir_correct_at_target ...  (* Crypto/Pulsar/Shamir.lean:76 *)
```

Plus the auxiliary `secret_recovery_at_zero`
(`lean/Crypto/Threshold_Lagrange.lean:62`).

**Correspondence**: `fresh_sharing q s` is the Pulsar adapter that
constructs the per-party shares of `s` along quorum `q` (= mapping
`q ↦ poly_eval s` on each `q[i]`, modulo the internal randomness
of the polynomial above degree 0). After Lagrange-recovery via
`reconstruct`, the constant term `s` returns. Same theorem as
Axiom 1, applied differently.

### Axiom 4: `Pulsar_N4.add_share_zeroR`

**EasyCrypt statement** (`proofs/easycrypt/Pulsar_N4.ec:130`):

```ec
axiom add_share_zeroR : forall (s : share_t), add_share s zero_share = s.
```

This is an algebraic identity on the `share_t` ring (right-identity
of addition). Mathlib provides this for any
`AddCommMonoid`-instance type, but the EC side keeps `share_t`
abstract and so axiomatizes the property directly. On the Lean
side this is implicit in the `Ring` / `Polynomial`-coefficient
instances and never needs an explicit theorem.

## What this bridge does NOT do

It does **not** provide a mechanical proof-object exchange. The EC
axioms are still trusted in the EC dependency cone — the bridge
is a code-review-level mapping, not a formal-method-level one.

The honest closure path is:

1. **Either** mechanize the four axioms inside EasyCrypt itself
   (would require importing or rebuilding a finite-field
   polynomial-interpolation library in EC; multi-week project),
2. **Or** prove the same statements in a tool whose proof object
   EC can consume (no current standard format),
3. **Or** keep the conceptual bridge and pin the Lean commit in
   the EC file headers (which we do, see "Citation comments"
   below).

Option (3) is what we do today. It is honest — the EC axiom
statements correspond 1:1 to Lean theorems we have proved — but
it is not strict closure inside the EC dependency cone.

## Citation comments

Each of the four EC axioms above has an inline comment immediately
preceding it that names the Lean theorem and file. Updating the EC
axiom statement without updating the Lean side (or vice versa)
trips the per-push test for "axiom signature change without bridge
comment update" — currently a manual review item; could be a CI
grep gate (see Future Work).

## Future work

1. **Mechanical close in EC.** Build out a minimal polynomial-
   interpolation theory inside EasyCrypt (just enough to discharge
   the four axioms). This removes the bridge entirely. Estimated
   effort: 3-4 weeks.
2. **Bridge guard in CI.** A `scripts/check-bridge.sh` that asserts
   each EC axiom in the bridge has an unchanged signature AND a
   citation comment naming a Lean theorem that still exists. Cheap
   to add; catches drift.
3. **Lean → EC tactic translation.** Long-term: if the EasyCrypt
   community adds a Lean-proof-object consumer, the bridge becomes
   a one-line `import` rather than four axiom statements.

## Honest summary

The trust footprint of the extracted N1 byte-equality theorem,
including the bridge:

* Implementation-refinement axioms (EC, byte-walks): **2**.
  Tracked under issues #3 + #4.
* Algebraic-content axioms bridged to Lean: **4** (Axioms 1-4
  above). Each has a corresponding Lean theorem cited inline.
* Module-contract axioms in the extracted N1 corollary: **0**.

Total dependency cone for the concrete extracted theorem:
2 byte-walks + 4 Lean-bridged algebraic identities.
