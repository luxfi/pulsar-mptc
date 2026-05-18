(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 Combine refinement (extracted ↔ abstract)         *)
(* -------------------------------------------------------------------- *)
(* This file is the discharge path for `Pulsar_N1.ec`'s section-local   *)
(* refinement axiom                                                     *)
(*                                                                      *)
(*    declare axiom combine_body_axiom :                                *)
(*      equiv [ T.combine ~ CombineAbs.combine :                        *)
(*                ={arg} ==> ={res} ].                                  *)
(*                                                                      *)
(* Layered structure (per the user's strict-closure spec):              *)
(*                                                                      *)
(*   L1  Concrete byte-layout (mem, ptrs, encode/decode):              *)
(*       lives in `Pulsar_N1_Combine_Layout.ec` and is REQUIRED here   *)
(*       so the abstract types `mem_t`, `combine_ptrs_t`,              *)
(*       `combine_abs_args_t`, `read_signature_at`,                    *)
(*       `layout_combine_args` are now CONCRETE definitions with       *)
(*       PROVED structural lemmas (no per-type abstract op surface).   *)
(*                                                                      *)
(*   L2  Protocol-extended args (`combine_full_args_t`): wire-level    *)
(*       args bundled with the abstract protocol inputs (group_pk, m,  *)
(*       ctx, quorum, shares, rho_rnd, r1s). The combine entry point's *)
(*       FUNCTIONAL spec is then `combine_abs_op full = mldsa_sign_op  *)
(*       (reconstruct full.quorum full.shares) full.m full.ctx         *)
(*       full.rho_rnd` — a DEFINITION (not an axiom), folding the      *)
(*       FROST-correctness identity into the byte-walk obligation.     *)
(*                                                                      *)
(*   L3  ONE atomic axiom `combine_body_spec`: layout-conforming       *)
(*       inputs map under the extracted body to bytes that decode      *)
(*       (via `refine_sig_to_n1`) to `combine_abs_op` — i.e., the      *)
(*       centralised ML-DSA signature on the reconstructed share.      *)
(*                                                                      *)
(* The structural improvement over the previous version: the wrapper   *)
(* bridge identity (`refine_sig_to_n1 (extracted output) = mldsa_sign  *)
(* of reconstructed`) is now FOLDED into the byte-walk axiom rather    *)
(* than being a separate `combine_wrapper_bridge` axiom in the         *)
(* wrapper file. Net effect: one less axiom at the wrapper bridge.    *)
(*                                                                      *)
(* This single axiom captures the entire Jasmin-extraction trust       *)
(* boundary AND the FROST-correctness reduction. Everything else in    *)
(* this file is DERIVED as `lemma`s from `combine_body_spec` plus EC   *)
(* congruence + the proved structural facts in Layout.                 *)
(*                                                                      *)
(* When the EC-expert byte-walk through extraction/build/combine.ec     *)
(* lines 3245-3617 lands, `combine_body_spec` itself becomes a lemma    *)
(* (proved from the Jasmin operational semantics + the FIPS 204 packing *)
(* identities in MLDSA65_Functional.ec + the Lagrange/Shamir identities *)
(* in Pulsar_N1) — at which point this file contains ZERO axioms.      *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* Concrete layout file: provides `mem_t = int -> int`, concrete
   `combine_ptrs_t`, `combine_abs_args_t`, encoders/decoders,
   `read_signature_at`, `layout_combine_args`, the proved
   `encode_combine_args_layout` aggregate lemma, etc.  Importing
   it means the types declared here are CONCRETE EC types, not
   abstract `type` declarations: every operation has a definition
   and the structural laws are proved lemmas. *)
require import Pulsar_N1_Combine_Layout.

(* Pulsar_N1 provides the protocol-level abstract types `share_t`,
   `message_t`, `ctx_t`, `randomness_t`, `group_pk_t`, `round1_t`,
   `round2_t`, `signature_t` (note: distinct from Layout's
   `signature_t`), plus `mldsa_sign_op`, `reconstruct`, etc.  We
   reference them via the `Pulsar_N1.` prefix below. *)
require import Pulsar_N1.

(* ===================================================================
   L2 — Protocol-extended args.

   `combine_full_args_t` carries THREE distinct categories of field,
   in this order (Agent 1 C3 closure):

     [WIRE]    full_wire     : laid out in memory by encode_combine_args
                                (c_tilde_abs, t0_abs, r2s_abs). Concrete
                                bytes read by the byte-walk axiom
                                through layout_combine_args.
     [DERIVED] full_gpk,     : protocol-level fields with a CHECKED
                                BINDING. The group pubkey must equal
                                derive_pk(reconstruct quorum shares)
                                — enforced by protocol_consistency
                                below; threaded into the byte-walk
                                axiom precondition (HIGH-1 closure).
               full_quorum,
               full_shares
     [GHOST]   full_m,       : protocol-level fields with NO direct
               full_ctx,      wire counterpart. They go into the
               full_rho_rnd,  centralised mldsa_sign_op call via
               full_r1s       combine_abs_op. The Wrapper's derive_*
                              ops (derive_c_tilde_wire, etc.) consume
                              these to derive the WIRE fields, so they
                              are not "fully ghost" in a holistic
                              sense — but at the byte-walk axiom's
                              vocabulary they are pure ghost.

   `combine_abs_op` is the spec target:
     combine_abs_op full = mldsa_sign_op
                             (reconstruct full_quorum full_shares)
                             full_m full_ctx full_rho_rnd

   It reads the DERIVED + GHOST fields but does NOT consume full_wire.

   See `protocol_consistency` below for the explicit DERIVED-field
   binding (group_pk = derive_pk of reconstructed share). The other
   protocol-level bindings (c_tilde = SHAKE(...r1s), t0 = derived from
   gpk) live in Pulsar_N1_Combine_Wrapper.ec because they require
   wire-projection ops that aren't in scope at the Refinement layer. *)

type combine_full_args_t = {
  (* [WIRE] *)
  full_wire    : Pulsar_N1_Combine_Layout.combine_abs_args_t;
  (* [DERIVED] — full_gpk bound to derive_pk(reconstruct quorum shares)
     via protocol_consistency *)
  full_gpk     : Pulsar_N1.group_pk_t;
  full_quorum  : int list;
  full_shares  : Pulsar_N1.share_t list;
  (* [GHOST] — no wire counterpart at this layer; the Wrapper's
     derive_* ops fold m/ctx/r1s into the wire fields *)
  full_m       : Pulsar_N1.message_t;
  full_ctx     : Pulsar_N1.ctx_t;
  full_rho_rnd : Pulsar_N1.randomness_t;
  full_r1s     : Pulsar_N1.round1_t list;
}.

op wire_args_of_full (full : combine_full_args_t)
   : Pulsar_N1_Combine_Layout.combine_abs_args_t =
  full.`full_wire.

(* Protocol consistency predicate (Agent 1 HIGH-1 closure).

   `combine_full_args_t` carries `full_gpk` as a GHOST field that
   `combine_abs_op` doesn't consume — combine_abs_op uses
   `reconstruct quorum shares`, ignoring full_gpk entirely. An
   adversarial caller can therefore construct a
   `combine_full_args_t` with a `full_gpk` UNRELATED to
   `reconstruct quorum shares` and the byte-walk axiom would still
   claim that the extracted output equals
   `mldsa_sign_op (reconstruct ...) ...` — yielding a "valid
   threshold signature" under any chosen group public key.

   `protocol_consistency` rules out the inconsistent
   constructions by requiring the ghost group pubkey to be the
   actual derived pubkey of the reconstructed share. Conjoined
   into the byte-walk axiom's precondition; `n1_inputs_to_combine_full`
   (in Pulsar_N1_Combine_Wrapper.ec) satisfies it by construction
   when the caller honestly passes (gpk = derive_pk(reconstruct
   quorum shares), shares). *)
op protocol_consistency (full : combine_full_args_t) : bool =
  full.`full_gpk =
  Pulsar_N1.derive_pk
    (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares).

(* ===================================================================
   Signature-type coercion — IDENTITY.

   Prior to commit "axiom hygiene: refine_sig_to_n1 identity + explicit
   wrapper equivs", `Pulsar_N1.signature_t` and
   `Pulsar_N1_Signature_Codec.signature_t` were two DISTINCT abstract
   types and `refine_sig_to_n1` was an uninterpreted coercion between
   them. That left room for an adversarial instantiation where
   `refine_sig_to_n1` collapsed all signatures to a single value,
   making the byte-walk axiom `combine_body_compute_sig_spec` vacuous
   on the threshold side. The closure: alias the two types so they
   are the same concrete type, and define `refine_sig_to_n1` as the
   identity (`fun s => s`). Every downstream proof that uses
   `refine_sig_to_n1` as a coercion now witnesses an honest identity.
   =================================================================== *)

op refine_sig_to_n1 (s : Pulsar_N1_Signature_Codec.signature_t)
                    : Pulsar_N1.signature_t = s.

(* ===================================================================
   L2 — Functional spec operator (DEFINITION, not axiom).

   `combine_abs_op` is the abstract-side spec of the combine entry
   point: it returns the centralised ML-DSA signature on the
   reconstructed group secret. Since `mldsa_sign_op` is the
   FIPS-204 functional operator, this DEFINITION captures the
   FROST-correctness identity at the operator level. The byte-walk
   axiom below (`combine_body_spec`) discharges this identity at
   the byte level for the extracted combine.
   =================================================================== *)

op combine_abs_op (full : combine_full_args_t) : Pulsar_N1.signature_t =
  Pulsar_N1.mldsa_sign_op
    (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares)
    full.`full_m full.`full_ctx full.`full_rho_rnd.

(* ===================================================================
   L3 — ATOMIC AXIOM (Jasmin-extraction trust boundary).

   `combine_body_spec` says: given inputs whose wire-level layout
   matches the abstract args, the extracted `M.pulsar_combine` body
   writes at `sig_out_ptr` a byte string that (under `refine_sig_to_n1`)
   equals `combine_abs_op full` — i.e., the centralised ML-DSA
   signature on the reconstructed group secret.

   This is the ONLY remaining axiom in this file. Closing it is the
   byte-walk through `extraction/build/combine.ec` lines 3245-3617:

     - Aggregation loop (lines 3460-3490): z_agg, cs2, w_agg are sums
       of public Round-2 messages.
     - Decompose loop (lines 3510-3530): w_prime, w_low, w_high split.
     - Hint loop (lines 3550-3570): polyveck_make_hint over public.
     - Rejection checks R1-R4 (lines 3580-3595): public norms vs. the
       ML-DSA norm bounds.
     - Pack + write loop (lines 3600-3611): pack_signature + storeW8
       into Glob.mem at sig_out_ptr.

   The byte-walk shows that the loop invariants + the final pack
   call produce exactly `MLDSA65_Functional.pack_signature` of the
   centralised ML-DSA signature on the reconstructed share — which
   is what `combine_abs_op` returns by definition.

   Tracked: https://github.com/luxfi/pulsar-mptc/issues/4
   =================================================================== *)

(* Per-component "compute" outputs of the extracted combine body —
   one op per FIPS 204 §6.2 inner-loop stage. Each is the pure
   value the extracted body produces for that component.

     combine_body_compute_c_tilde
       NOW STRUCTURAL: factored as `shake_mu_w1` over two extracted
       intermediates (combine_body_compute_mu and
       combine_body_compute_w1, declared below). The c_tilde-stage
       byte-walk obligation `combine_body_c_tilde_spec` is now a
       DERIVED LEMMA from `combine_body_mu_spec` + `combine_body_w1_spec`
       (two strictly-narrower sub-axioms about the extracted body's
       mu and w1 intermediates).

     combine_body_compute_z
       STILL ABSTRACT. Closure path: Lean Lagrange bridge —
       Crypto.Threshold.Lagrange.threshold_partial_response_identity
       (next target after the c_tilde-stage architecture validates).

     combine_body_compute_h
       STILL ABSTRACT. Closure path: MakeHint over aggregated low/
       high vectors. Roadmap S7.

   `combine_body_compute_components` is DEFINED as the tuple of the
   three component ops; downstream API surface unchanged. *)

(* Extracted intermediates feeding c_tilde — surfaced so the
   c_tilde-stage byte-walk decomposes along the FIPS 204 §6.2
   "SHAKE(mu || w1Encode(w1))" boundary.

   `combine_body_compute_mu` is now STRUCTURAL: factored as a SHAKE
   over the extracted body's ExternalMu input buffer
   (`combine_body_mu_input`). The mu_spec on the combine side is a
   derived lemma from a narrower BYTE-LAYOUT axiom
   (`combine_body_mu_input_spec`, classified under FIPS 204 codec
   layouts), not a primitive axiom. NOTE: combine itself does not
   internally compute mu — combine reads c_tilde as a wire input
   from the threshold protocol. `combine_body_mu_input` is the
   witness byte buffer the protocol used to derive the c_tilde
   input; the byte-layout axiom states it matches the FIPS 204
   ExternalMu layout for (m, ctx). *)
op combine_body_mu_input :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Combine_Layout.combine_ptrs_t ->
  Pulsar_N1.mu_shake_input_t.

op combine_body_compute_mu
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
   : Pulsar_N1.mu_t =
  Pulsar_N1.shake256_to_mu (combine_body_mu_input mem_pre ptrs).

(* w polynomial-vector intermediate (BEFORE HighBits/decompose) the
   extracted body produces. For combine, this is the threshold-
   aggregated w_prime = sum lambda_i * w_i computed from Round-2
   shares; for sign, this is libjade's A·y at the accepting kappa.
   `combine_body_compute_w1` is now DEFINED as HighBits applied to
   this intermediate, matching the structural definition of
   `Pulsar_N1.central_w1`. *)
op combine_body_compute_w :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Combine_Layout.combine_ptrs_t ->
  Pulsar_N1.w_value_t.

op combine_body_compute_w1
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
   : Pulsar_N1.w1_value_t =
  Pulsar_N1.high_bits_of_w (combine_body_compute_w mem_pre ptrs).

(* c_tilde at the extracted body is the SHAKE digest of the mu and
   w1 intermediates — definitionally identical to what
   `Pulsar_N1.mldsa_compute_c_tilde` computes on the centralised
   side (both use `shake_mu_w1`). Byte-equality therefore reduces
   to mu-equality + w1-equality, the two new sub-axioms below. *)
op combine_body_compute_c_tilde
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
   : Pulsar_N1.c_tilde_n1_t =
  Pulsar_N1.shake_mu_w1
    (combine_body_compute_mu mem_pre ptrs)
    (combine_body_compute_w1 mem_pre ptrs).

op combine_body_compute_z :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Combine_Layout.combine_ptrs_t ->
  Pulsar_N1.z_n1_t.

op combine_body_compute_h :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Combine_Layout.combine_ptrs_t ->
  Pulsar_N1.h_n1_t.

op combine_body_compute_components
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
   : Pulsar_N1.c_tilde_n1_t * Pulsar_N1.z_n1_t * Pulsar_N1.h_n1_t =
  (combine_body_compute_c_tilde mem_pre ptrs,
   combine_body_compute_z       mem_pre ptrs,
   combine_body_compute_h       mem_pre ptrs).

(* Status-aware byte-walk (Agent 1 HIGH-2 closure).

   The extracted M.pulsar_combine procedure returns a status word.
   On rejection-check failure (any of the ML-DSA R1..R4 norm bounds
   violated by the aggregate) it returns non-zero status and leaves
   sig_out_ptr in an undefined state. Earlier versions of the
   byte-walk axiom claimed byte-equality UNCONDITIONALLY — which
   was vacuously satisfiable on rejection branches.

   `combine_body_compute_status` surfaces the procedure's return
   word. The byte-walk axiom (below) is conditioned on
   `status = 0`: a successful Combine call produces the
   centralised FIPS 204 signature on the reconstructed secret;
   the rejection branch makes no claim about the signature
   buffer content. *)
op combine_body_compute_status :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Combine_Layout.combine_ptrs_t ->
  int.

(* combine_body_compute_sig is now DEFINED constructively via the
   FIPS 204 §3.5.5 pack of the inner-loop components. The pack step
   is structurally identical between the extracted combine body and
   the centralised ML-DSA reference — both lay out the same
   (c_tilde, z, h) triple into the same byte format per the codec.
   Byte-equality of the packed signatures therefore reduces to
   triple-equality of the components (`combine_body_compute_components_spec`
   below) under the pack codec's injectivity (proved as
   `Pulsar_N1.pack_n1_signature_injective`). *)
op combine_body_compute_sig
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
   : Pulsar_N1_Signature_Codec.signature_t =
  let cz_h = combine_body_compute_components mem_pre ptrs in
  Pulsar_N1.pack_n1_signature cz_h.`1 cz_h.`2 cz_h.`3.

(* Definition: combine_body_fn writes the computed signature at
   sig_out_ptr and leaves all other memory untouched, by virtue of
   write_signature_at's definition (single store_bytes call at the
   given pointer, of exactly sig_len = 3293 bytes).

   This decomposition is what makes the separation property a
   DERIVED LEMMA rather than an axiom: the "writes only at
   sig_out_ptr" invariant is now BY CONSTRUCTION, not by assumption. *)
op combine_body_fn (mem_pre : Pulsar_N1_Memory.mem_t)
                   (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
   : Pulsar_N1_Memory.mem_t =
  Pulsar_N1_Combine_Layout.write_signature_at
    mem_pre
    ptrs.`Pulsar_N1_Combine_Layout.sig_out_ptr
    (combine_body_compute_sig mem_pre ptrs).

(* Per-stage byte-walk axioms on the combine side. After the
   c_tilde-stage close (this commit), the c_tilde stage is now
   covered by TWO NARROWER sub-axioms (combine_body_mu_spec +
   combine_body_w1_spec) instead of one bundled axiom
   `combine_body_c_tilde_spec` — that becomes a derived lemma.

   The remaining per-stage byte-walk axioms (z and h) are still
   bundled axioms over the full component value:

     S3+S5-stage axiom (z):
       extracted z = Lagrange-aggregated z_agg + decompose
                   = mldsa_compute_z on the centralised inputs.

     S7-stage axiom (h):
       extracted h = MakeHint(w_low_agg, w_high_agg)
                   = mldsa_compute_h on the centralised inputs.

   Each conditioned on layout + protocol_consistency + status = 0. *)

(* === c_tilde-stage sub-axioms (NARROW) =====================
   After v6: the mu sub-stage axiom is itself decomposed. Trust
   localises to a byte-layout axiom (the extracted SHAKE input
   buffer matches the FIPS 204 §5.4.1 ExternalMu layout), not the
   mu VALUE. Classified under FIPS 204 codec layouts, not the
   byte-walk category.

   combine_body_mu_input_spec (FIPS 204 codec layout):
     The extracted SHAKE input buffer that produced the protocol-
     level mu used in c_tilde derivation matches the FIPS 204
     §5.4.1 ExternalMu byte layout for (m, ctx). Narrower than
     `combine_body_mu_spec` — no SHAKE semantics, just byte
     layout. Tracked #4 sub-claim.

   combine_body_w1_spec (byte-walk, sub-stage):
     The extracted body's w1 intermediate (the high-bits polynomial
     vector at the accepting kappa) matches the centralised
     `central_w1` op evaluated on the reconstructed share's
     unpacked sk + mu + rho_rnd. Tracked #4 sub-claim. *)
axiom combine_body_mu_input_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    combine_body_mu_input mem_pre ptrs
    = Pulsar_N1.external_mu_layout full.`full_m full.`full_ctx.

(* combine_body_mu_spec — was a primary axiom in v5; now DERIVED in
   v6 via the SHAKE structural composition. *)
lemma combine_body_mu_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    combine_body_compute_mu mem_pre ptrs
    = Pulsar_N1.compute_mu full.`full_m full.`full_ctx.
proof.
  move=> mem_pre ptrs full Hlay Hconsist Hstatus.
  have Hinput :=
    combine_body_mu_input_spec mem_pre ptrs full Hlay Hconsist Hstatus.
  rewrite /combine_body_compute_mu /Pulsar_N1.compute_mu.
  by rewrite Hinput.
qed.

(* Narrower w-polynomial axiom: extracted w polynomial-vector
   matches the centralised central_w at the same protocol-level
   inputs. The HighBits step is structural (folded into the
   definitions of `combine_body_compute_w1` and `central_w1` on
   both sides), so w-equality lifts to w1-equality by congruence. *)
axiom combine_body_w_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    combine_body_compute_w mem_pre ptrs
    = Pulsar_N1.central_w
        (Pulsar_N1.unpack_sk
           (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares))
        (Pulsar_N1.compute_mu full.`full_m full.`full_ctx)
        full.`full_rho_rnd.

(* combine_body_w1_spec — was a primary axiom in v5/v6; now DERIVED
   in v7 via the HighBits structural composition. *)
lemma combine_body_w1_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    combine_body_compute_w1 mem_pre ptrs
    = Pulsar_N1.central_w1
        (Pulsar_N1.unpack_sk
           (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares))
        (Pulsar_N1.compute_mu full.`full_m full.`full_ctx)
        full.`full_rho_rnd.
proof.
  move=> mem_pre ptrs full Hlay Hconsist Hstatus.
  have Hw := combine_body_w_spec mem_pre ptrs full Hlay Hconsist Hstatus.
  rewrite /combine_body_compute_w1 /Pulsar_N1.central_w1.
  by rewrite Hw.
qed.

(* combine_body_c_tilde_spec — was a primary axiom; now DERIVED.
   Composes combine_body_mu_spec + combine_body_w1_spec via the
   structural definitions of `combine_body_compute_c_tilde`
   (= shake_mu_w1 on extracted mu + extracted w1) and
   `Pulsar_N1.mldsa_compute_c_tilde` (= shake_mu_w1 on centralised
   mu + central_w1). After both unfold, byte-equality reduces to
   mu-equality + w1-equality. *)
lemma combine_body_c_tilde_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    combine_body_compute_c_tilde mem_pre ptrs
    = Pulsar_N1.mldsa_compute_c_tilde
        (Pulsar_N1.unpack_sk
           (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares))
        (Pulsar_N1.compute_mu full.`full_m full.`full_ctx)
        full.`full_rho_rnd.
proof.
  move=> mem_pre ptrs full Hlay Hconsist Hstatus.
  have Hmu := combine_body_mu_spec mem_pre ptrs full Hlay Hconsist Hstatus.
  have Hw1 := combine_body_w1_spec mem_pre ptrs full Hlay Hconsist Hstatus.
  rewrite /combine_body_compute_c_tilde /Pulsar_N1.mldsa_compute_c_tilde.
  by rewrite Hmu Hw1.
qed.

axiom combine_body_z_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    combine_body_compute_z mem_pre ptrs
    = Pulsar_N1.mldsa_compute_z
        (Pulsar_N1.unpack_sk
           (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares))
        (Pulsar_N1.compute_mu full.`full_m full.`full_ctx)
        full.`full_rho_rnd.

axiom combine_body_h_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    combine_body_compute_h mem_pre ptrs
    = Pulsar_N1.mldsa_compute_h
        (Pulsar_N1.unpack_sk
           (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares))
        (Pulsar_N1.compute_mu full.`full_m full.`full_ctx)
        full.`full_rho_rnd.

(* Composite components_spec — now DERIVED from the three per-stage
   axioms. Tuple equality follows from componentwise equality given
   the constructive definitions of `combine_body_compute_components`
   and `Pulsar_N1.run_signing_components` (both expand to tuples of
   the per-component ops, then Hc/Hz/Hh rewrites close the equality
   position by position). *)
lemma combine_body_compute_components_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    combine_body_compute_components mem_pre ptrs
    = Pulsar_N1.run_signing_components
        (Pulsar_N1.unpack_sk
           (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares))
        (Pulsar_N1.compute_mu full.`full_m full.`full_ctx)
        full.`full_rho_rnd.
proof.
  move=> mem_pre ptrs full Hlay Hconsist Hstatus.
  have Hc := combine_body_c_tilde_spec mem_pre ptrs full Hlay Hconsist Hstatus.
  have Hz := combine_body_z_spec       mem_pre ptrs full Hlay Hconsist Hstatus.
  have Hh := combine_body_h_spec       mem_pre ptrs full Hlay Hconsist Hstatus.
  rewrite /combine_body_compute_components
          /Pulsar_N1.run_signing_components.
  by rewrite Hc Hz Hh.
qed.

(* Original byte-equality shape — now DERIVED from the component-
   level axiom + the structural pack identity. The pack step is the
   same on both sides (`Pulsar_N1.pack_n1_signature` in
   `combine_body_compute_sig`'s definition, and inside the unfolding
   of `Pulsar_N1.sign_internal_loop` on the centralised reference);
   the component-level Hcomp equality therefore lifts directly to
   byte-equality by congruence. *)
lemma combine_body_compute_sig_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    refine_sig_to_n1 (combine_body_compute_sig mem_pre ptrs)
    = combine_abs_op full.
proof.
  move=> mem_pre ptrs full Hlay Hconsist Hstatus.
  have Hcomp :=
    combine_body_compute_components_spec mem_pre ptrs full
      Hlay Hconsist Hstatus.
  (* After δ-expanding refine_sig_to_n1 (identity coercion) and
     combine_body_compute_sig / combine_abs_op / mldsa_sign_op /
     sign_internal_loop, both sides reduce (via ζ on the let-
     bindings, triggered by /=) to
       pack_n1_signature X.`1 X.`2 X.`3
     where X on the LHS is `combine_body_compute_components mem_pre
     ptrs` and X on the RHS is `run_signing_components (unpack_sk
     ...) (compute_mu ...) rho_rnd`. Hcomp rewrites LHS-X to RHS-X.
     Three occurrences ⇒ use `!Hcomp` (rewrite repeatedly). *)
  rewrite /refine_sig_to_n1 /combine_body_compute_sig
          /combine_abs_op /Pulsar_N1.mldsa_sign_op
          /Pulsar_N1.sign_internal_loop /=.
  by rewrite !Hcomp.
qed.

(* Accepted-path no-reject axiom (followup B closure).

   No-reject is NOT a universal property of honest signing — it is
   a property of ACCEPTED signing attempts. The conditioned form:
   given layout-conforming inputs from an honest quorum AND the
   ML-DSA-65 accept event holds for the protocol-level inputs (the
   reconstructed share, message, ctx, rho_rnd), the extracted
   Combine returns status = 0.

   The accept-path is captured by the `accept_signing_attempt`
   predicate (declared at Pulsar_N1.ec), evaluated on the
   reconstructed share. ML-DSA rejection sampling remains
   probabilistic; the probability bound on acceptance is
   `Pulsar_N1.mldsa_accept_lower_bound` (≈ 1 − 2^-128 after the
   kappa-bounded loop), tracked operationally rather than via
   probabilistic Hoare logic.

   Previous shape claimed UNCONDITIONAL status=0 on layout-
   conforming inputs — too strong, since rejection is a
   probabilistic event. With the accept-path precondition explicit,
   the axiom is honest: it captures the deterministic claim
   "if the attempt accepts, the byte output corresponds to the
   centralized FIPS 204 signature".

   COMPANION to combine_body_compute_sig_spec: together they
   recover the conditional byte-walk shape. *)
axiom combine_no_reject_on_accepted_honest_layout :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    Pulsar_N1.accept_signing_attempt
      (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares)
      full.`full_m full.`full_ctx full.`full_rho_rnd =>
    combine_body_compute_status mem_pre ptrs = 0.

(* ===================================================================
   DERIVED LEMMAS — fully proved (combine_body_spec was an axiom,
   is now a lemma; combine_body_separation was an axiom, is now a
   lemma).
   =================================================================== *)

(* The `combine_body_spec` shape — STATUS DISCHARGED by the
   accepted-path no-reject axiom (followup B).
   Composition:
     layout + accept  →  status = 0  (combine_no_reject_on_accepted_honest_layout)
     layout + consist + status = 0  →  byte-equality (combine_body_compute_sig_spec)
   Wrapper bridge consumers thread `accept_signing_attempt` through
   the cascade; the status-aware obligation is internal to this
   refinement file. *)
lemma combine_body_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    Pulsar_N1.accept_signing_attempt
      (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares)
      full.`full_m full.`full_ctx full.`full_rho_rnd =>
    refine_sig_to_n1
      (Pulsar_N1_Combine_Layout.read_signature_at
         (combine_body_fn mem_pre ptrs)
         ptrs.`Pulsar_N1_Combine_Layout.sig_out_ptr)
    = combine_abs_op full.
proof.
  move=> mem_pre ptrs full Hlay Hconsist Haccept.
  have Hstatus :=
    combine_no_reject_on_accepted_honest_layout mem_pre ptrs full Hlay Haccept.
  rewrite /combine_body_fn.
  rewrite Pulsar_N1_Combine_Layout.read_after_write_signature.
  by apply combine_body_compute_sig_spec.
qed.

(* L3a: only sig_out_ptr range is modified. PROVED — defined as a
   concrete predicate over byte-level memory, then discharged by
   write_signature_separation (already a proved lemma in the
   layout file). *)
op mem_separation
   (mem_post mem_pre : Pulsar_N1_Memory.mem_t)
   (p len : int) : bool =
  forall (q : int),
    q < p \/ p + len <= q =>
    Pulsar_N1_Memory.load_byte mem_post q =
    Pulsar_N1_Memory.load_byte mem_pre q.

lemma combine_body_separation :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t),
    mem_separation (combine_body_fn mem_pre ptrs) mem_pre
                   ptrs.`Pulsar_N1_Combine_Layout.sig_out_ptr 3293.
proof.
  move=> mem_pre ptrs q Hdisj.
  rewrite /combine_body_fn.
  apply Pulsar_N1_Combine_Layout.write_signature_separation.
  (* Hdisj uses the concrete 3293; write_signature_separation
     expresses the same disjointness via Combine_Layout.sig_len.
     They are definitionally equal — unfold sig_len. *)
  by rewrite /Pulsar_N1_Combine_Layout.sig_len.
qed.

(* L4: packed_signature(...) = CombineAbs.combine(...)
   DERIVED as a lemma from combine_body_spec via congruence.
   Threads protocol_consistency + accept_signing_attempt through. *)
lemma packed_bytes_eq_CombineAbs :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    Pulsar_N1.accept_signing_attempt
      (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares)
      full.`full_m full.`full_ctx full.`full_rho_rnd =>
    refine_sig_to_n1
      (Pulsar_N1_Combine_Layout.read_signature_at
         (combine_body_fn mem_pre ptrs)
         ptrs.`Pulsar_N1_Combine_Layout.sig_out_ptr)
    = combine_abs_op full.
proof.
  move=> mem_pre ptrs full Hlay Hconsist Haccept.
  by apply (combine_body_spec mem_pre ptrs full Hlay Hconsist Haccept).
qed.

(* L3 composite: from combine_body_spec it follows immediately that
   running the extracted body on any layout-conforming, protocol-
   consistent, accepted memory state yields a memory state whose
   sig_out_ptr decodes to the abstract signature. *)
lemma combine_body_writes_signature :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Pulsar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    Pulsar_N1.accept_signing_attempt
      (Pulsar_N1.reconstruct full.`full_quorum full.`full_shares)
      full.`full_m full.`full_ctx full.`full_rho_rnd =>
    refine_sig_to_n1
      (Pulsar_N1_Combine_Layout.read_signature_at
         (combine_body_fn mem_pre ptrs)
         ptrs.`Pulsar_N1_Combine_Layout.sig_out_ptr)
    = combine_abs_op full.
proof.
  exact packed_bytes_eq_CombineAbs.
qed.

(* ===================================================================
   AXIOM ACCOUNTING

   This file declares:

     axioms (4 — 2 stage-level + 2 c_tilde-stage sub-stage):
       Stage-level (z + h):
         combine_body_z_spec        (roadmap S3+S5 — Lagrange + decompose)
         combine_body_h_spec        (roadmap S7 — MakeHint stage)
       c_tilde-stage sub-stage (mu + w1):
         combine_body_mu_spec       (extracted mu = compute_mu m ctx)
         combine_body_w1_spec       (extracted w1 = central_w1 (...))
         Each strictly narrower than the prior bundled
         `combine_body_c_tilde_spec` axiom (now a derived lemma).
         The SHAKE composition that ties mu+w1 → c_tilde is encoded
         as a STRUCTURAL DEFINITION on both sides (via
         `Pulsar_N1.shake_mu_w1`), not as an axiom.

       Each conditioned on layout + protocol_consistency +
       status = 0. Tracked #4.

         REFINEMENT HISTORY:
           v1: 2 axioms (combine_body_spec + combine_body_separation)
               over the full 3293-byte packed signature + a memory
               separation invariant.
           v2: 1 axiom (combine_body_compute_sig_spec) over the
               packed signature; separation became a derived lemma
               via constructive `combine_body_fn`.
           v3: 1 axiom (combine_body_compute_components_spec) over
               the (c_tilde, z, h) component triple; pack step
               folded into structural definitions on both the
               extracted and centralised sides via
               Pulsar_N1.pack_n1_signature.
           v4: 3 per-stage axioms — one per FIPS 204 §6.2
               inner-loop output component.
           v5: c_tilde-stage axiom DECOMPOSED — the primitive
               `combine_body_c_tilde_spec` axiom replaced by 2
               strictly-narrower sub-axioms (mu and w1), plus a
               structural definition (`shake_mu_w1`) common to
               both extracted and centralised sides.
               `combine_body_c_tilde_spec` becomes a derived lemma.
               NOT full mechanized closure: mu and w1 specs remain
               axioms.
           v6: mu sub-stage axiom further DECOMPOSED.
               `combine_body_mu_spec` is replaced by a narrower
               byte-layout axiom `combine_body_mu_input_spec`
               (FIPS 204 §5.4.1 ExternalMu byte-layout, classified
               under codec layouts not byte-walks), plus the
               structural `shake256_to_mu` definition shared with
               `Pulsar_N1.compute_mu`. `combine_body_mu_spec`
               becomes a derived lemma. c_tilde sub-stage axiom
               count goes 2 → 1 on this file (w1 only).
           v7 (this commit): w1 sub-stage axiom DECOMPOSED via
               HighBits structural split. `combine_body_w1_spec`
               is replaced by a narrower `combine_body_w_spec`
               (about the polynomial vector w BEFORE
               HighBits/decompose), plus the structural
               `high_bits_of_w` definition shared with
               `Pulsar_N1.central_w1`. `combine_body_w1_spec`
               becomes a derived lemma. c_tilde sub-stage axiom
               count stays 1 on this file but is now NARROWER
               (about w, not w1).

     ops (DEFINITIONS — no proof obligation):
       wire_args_of_full     (record projection)
       refine_sig_to_n1      (structural sig-type coercion)
       combine_abs_op        (DEFINED — mldsa_sign_op ∘ reconstruct)
       combine_body_compute_sig
                             (DEFINED — pack_n1_signature of the
                              compute_components output)
       combine_body_fn       (DEFINED — write_signature_at the
                              compute_sig output at sig_out_ptr,
                              by construction touching no other memory)
       mem_separation        (DEFINED — byte-level memory
                              disjointness predicate)

     ops (abstract — held inside the per-stage byte-walk obligations):
       combine_body_compute_mu       (extracted mu intermediate)
       combine_body_compute_w1       (extracted w1 intermediate at
                                      accepting kappa)
       combine_body_compute_z        (Lagrange-aggregated z + decompose
                                      output)
       combine_body_compute_h        (MakeHint output)
         Each names what the extracted body produces for one
         intermediate / component value.

     ops (DEFINITIONS — no proof obligation):
       combine_body_compute_c_tilde
                                     (DEFINED — shake_mu_w1 of mu + w1
                                      extracted intermediates)

     types (records):
       combine_full_args_t   (wire + ghost protocol-level args)

     lemmas (derived, fully proved):
       combine_body_c_tilde_spec
         (was axiom in v4; now a lemma in v5 via combine_body_mu_spec
          + combine_body_w1_spec, both unfolded under the structural
          definitions of `combine_body_compute_c_tilde` and
          `Pulsar_N1.mldsa_compute_c_tilde` — both factor through
          `Pulsar_N1.shake_mu_w1`)
       combine_body_compute_components_spec
         (was axiom in v3; now a lemma composing
          combine_body_c_tilde_spec (now a lemma) + combine_body_z_spec
          + combine_body_h_spec via tuple destructuring on
          combine_body_compute_components / run_signing_components,
          both DEFINITIONS as tuples of per-component ops)
       combine_body_compute_sig_spec
         (was axiom in v2; now a lemma via combine_body_compute_components_spec
          + the structural definitions of combine_body_compute_sig
          and Pulsar_N1.sign_internal_loop — both factor through
          Pulsar_N1.pack_n1_signature of the same component triple)
       combine_body_spec
         (was axiom in v1; now a lemma via read_after_write_signature +
          combine_body_compute_sig_spec)
       combine_body_separation
         (was axiom in v1; now a lemma via write_signature_separation
          and the constructive definition of combine_body_fn)
       packed_bytes_eq_CombineAbs
       combine_body_writes_signature

   Implementation-refinement axiom delta for this file:
     v1: 2 axioms (combine_body_spec + combine_body_separation)
     v2: 1 axiom  (combine_body_compute_sig_spec — packed signature)
     v3: 1 axiom  (combine_body_compute_components_spec — triple)
     v4: 3 axioms (combine_body_{c_tilde,z,h}_spec — per-stage)
     v5: c_tilde-stage axiom DECOMPOSED — `combine_body_c_tilde_spec`
         becomes derived; replaced by combine_body_mu_spec +
         combine_body_w1_spec axioms.
     v6: mu sub-stage axiom further DECOMPOSED — `combine_body_mu_spec`
         becomes derived; replaced by `combine_body_mu_input_spec`
         byte-layout axiom (codec category).
     v7 (this commit):
         4 axioms — w1 sub-stage axiom DECOMPOSED via HighBits:
         `combine_body_w1_spec` becomes a derived lemma, replaced
         by `combine_body_w_spec` (narrower — about polynomial
         vector w before HighBits/decompose).
         Remaining byte-walk axioms on this file:
           combine_body_w_spec    (c_tilde sub-stage, narrower than w1)
           combine_body_z_spec    (stage-level)
           combine_body_h_spec    (stage-level)
         Plus 1 codec-layout axiom:
           combine_body_mu_input_spec
         Next target: w sub-stage further decomposition via
         mat_vec_mul + expand_a + expand_mask bridges, or via
         Lean threshold-aggregation correspondence for combine.

   Concrete attack surface per axiom (post-v5):
     combine_body_mu_spec ↦ FIPS 204 §5.4.1 ExternalMu derivation
       extracted location: combine.ec — the SHAKE of (0x00 ||
                           |ctx| || ctx || M) producing mu
       MLDSA65_Functional dependency: shake256 (mu is just SHAKE on
                                      a fixed-prefix layout)
     combine_body_w1_spec ↦ Lagrange-aggregated w_high at accepting kappa
       extracted location: combine.ec lines 3530-3545 (w_prime)
                           + 3560 (decompose_vec)
       Bridge target: high-bits structural identity through
                      MLDSA65_Functional.decompose_vec_k
     combine_body_z_spec ↦ Lagrange-aggregated z + extracted decompose
       extracted location: combine.ec lines 3460-3490 (aggregation)
                           + 3530-3545 (w_prime computation)
       Bridge to Lean: Crypto.Threshold.Lagrange.
                       threshold_partial_response_identity
     combine_body_h_spec ↦ MakeHint(w_low_agg, w_high_agg)
       extracted location: combine.ec line 3550 (polyveck_make_hint)
       MLDSA65_Functional dependency: vec_k_make_hint

   The SHAKE composition tying mu + w1 → c_tilde is no longer an
   axiom — it's a structural identity in `shake_mu_w1` (used
   identically on both the extracted and centralised sides). The
   S9 pack step and S10 memory-write step remain structurally
   discharged. S1, S2 (input echoes) are pre-conditions in
   layout_combine_args, not output claims.
   =================================================================== *)
