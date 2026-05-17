(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 wrapper bridge                                    *)
(* -------------------------------------------------------------------- *)
(* This file bridges the byte-level atomic axiom in                     *)
(* `Pulsar_N1_Combine_Refinement.ec` (and the sign counterpart) to the  *)
(* procedure-level `equiv` shape that `Pulsar_N1.ec`'s section          *)
(* consumes.                                                            *)
(*                                                                      *)
(* The wrapper modules:                                                 *)
(*   CombineExtractedWrapper : Pulsar_Threshold                        *)
(*     - round1, round2: placeholder procs that satisfy the interface  *)
(*       (not used by combine_body_axiom).                              *)
(*     - combine: adapts abstract args → memory layout → calls the     *)
(*       extracted body's byte-level effect (`combine_body_fn`) →       *)
(*       decodes the signature → returns it.                            *)
(*                                                                      *)
(*   SignExtractedWrapper : MLDSA65_Sign                               *)
(*     - sign: adapts abstract args → memory layout → calls the        *)
(*       extracted body's byte-level effect (`sign_body_fn`) →          *)
(*       decodes the signature → returns it.                            *)
(*                                                                      *)
(* The wrapper bridge lemmas:                                           *)
(*   combine_wrapper_equiv_CombineAbs                                  *)
(*     equiv [ CombineExtractedWrapper.combine ~ CombineAbs.combine    *)
(*             : ={arg} ==> ={res} ]                                    *)
(*   sign_wrapper_equiv_FIPS204Sign                                    *)
(*     equiv [ SignExtractedWrapper.sign ~ FIPS204Sign.sign            *)
(*             : ={arg} ==> ={res} ]                                    *)
(*                                                                      *)
(* These lemmas are real EC `lemma`s reducing to:                       *)
(*   - the concrete Layout encoder + the PROVED                         *)
(*     `encode_combine_args_layout` aggregate lemma                     *)
(*   - the refinement file's atomic byte-walk axiom                     *)
(*     (`combine_body_spec`, now folded with the FROST-correctness      *)
(*     identity by construction of `combine_abs_op`)                    *)
(*                                                                      *)
(* When the byte-walk axiom closes in #4, the combine wrapper lemma    *)
(* becomes a fully derived theorem with no axiom in its proof chain.   *)
(* The sign wrapper still needs `sign_wrapper_bridge` (the sign        *)
(* analogue of the wire-vs-protocol bridge that this file folded for   *)
(* combine via the Refinement restructure) — a separate refactor.      *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* The two refinement files provide the byte-level atomic axioms +
   their associated types, ops, and derived lemmas. *)
require import Pulsar_N1_Combine_Refinement.
require import Pulsar_N1_Sign_Refinement.

(* The concrete combine layout: re-imported so we can call its
   `encode_combine_args` concretely (the Refinement file requires it
   transitively, but we name it explicitly here for the proof). *)
require import Pulsar_N1_Combine_Layout.

(* Pulsar_N1.ec provides the abstract types, the module types
   (Pulsar_Threshold, MLDSA65_Sign), the FIPS204Sign and CombineAbs
   modules, plus the reconstruct/lagrange operators. *)
require import Pulsar_N1.

(* ===================================================================
   ABI encode operators.

   `encode_combine_args` packs the abstract `(group_pk, m, ctx,
   quorum, shares, rho_rnd, r1s, r2s)` tuple into a memory state +
   pointer bundle matching the Jasmin entry-point's ABI.

   In the previous version this was a top-level abstract op of type
       (gpk, m, ctx, quorum, shares, rho_rnd, r1s, r2s)
         -> (mem * combine_ptrs * combine_abs_args)
   independent from `Pulsar_N1_Combine_Layout.encode_combine_args`.
   The wrapper-bridge axiom then had to assert byte-walk + FROST-
   correctness in one shot.

   In the new version this op is DEFINED in two steps:

     1. `n1_inputs_to_combine_full` constructs a
        `combine_full_args_t` from the protocol-level inputs. The
        wire fields (c_tilde_abs, t0_abs, r2s_abs) are derived
        abstractly from the protocol inputs by `derive_c_tilde`,
        `derive_t0`, `derive_r2s_from_round2`. The ghost fields
        (gpk, m, ctx, quorum, shares, rho_rnd, r1s) are copied in
        directly.

     2. `encode_combine_args` then composes `wire_args_of_full`
        with `Pulsar_N1_Combine_Layout.encode_combine_args` (the
        CONCRETE encoder proved correct by
        `encode_combine_args_layout`).

   The byte-walk axiom (`combine_body_spec`) now folds in the
   FROST-correctness identity by virtue of `combine_abs_op` being
   DEFINED as `mldsa_sign_op ∘ reconstruct`. So the wrapper bridge
   reduces to a real lemma composing `encode_combine_args_layout`
   with `combine_body_spec`.

   `encode_sign_args` is unchanged.
   =================================================================== *)

(* Derive the wire-level fields the C-side combine sees from the
   protocol inputs. These are ABSTRACT ops: their concrete bodies
   live in the FIPS 204 / Pulsar protocol spec (`derive_c_tilde`
   is the SHAKE digest of the Round-1 commit transcript; `derive_t0`
   reads from the group public key; `derive_r2s` is the projection
   from Pulsar_N1.round2_t onto the wire-level r2_msg_t record). *)
op derive_c_tilde_wire :
  Pulsar_N1.group_pk_t -> Pulsar_N1.message_t -> Pulsar_N1.ctx_t ->
  Pulsar_N1.round1_t list -> Pulsar_N1_Combine_Layout.c_tilde_t.

op derive_t0_wire :
  Pulsar_N1.group_pk_t -> Pulsar_N1_Combine_Layout.t0_vec_t.

op derive_r2_msgs_wire :
  Pulsar_N1.round2_t list -> Pulsar_N1_Combine_Layout.r2_msg_t list.

op n1_inputs_to_combine_full
   (gpk : Pulsar_N1.group_pk_t) (m : Pulsar_N1.message_t)
   (ctx : Pulsar_N1.ctx_t) (quorum : int list)
   (shares : Pulsar_N1.share_t list) (rho_rnd : Pulsar_N1.randomness_t)
   (r1s : Pulsar_N1.round1_t list) (r2s : Pulsar_N1.round2_t list)
   : combine_full_args_t =
  {| full_wire =
        {| c_tilde_abs = derive_c_tilde_wire gpk m ctx r1s;
           t0_abs      = derive_t0_wire gpk;
           r2s_abs     = derive_r2_msgs_wire r2s; |};
     full_gpk     = gpk;
     full_m       = m;
     full_ctx     = ctx;
     full_quorum  = quorum;
     full_shares  = shares;
     full_rho_rnd = rho_rnd;
     full_r1s     = r1s; |}.

op encode_combine_args
   (gpk : Pulsar_N1.group_pk_t) (m : Pulsar_N1.message_t)
   (ctx : Pulsar_N1.ctx_t) (quorum : int list)
   (shares : Pulsar_N1.share_t list) (rho_rnd : Pulsar_N1.randomness_t)
   (r1s : Pulsar_N1.round1_t list) (r2s : Pulsar_N1.round2_t list)
   : Pulsar_N1_Combine_Layout.mem_t *
     Pulsar_N1_Combine_Layout.combine_ptrs_t *
     combine_full_args_t =
  let full = n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s in
  let (mem, ptrs) =
    Pulsar_N1_Combine_Layout.encode_combine_args (wire_args_of_full full) in
  (mem, ptrs, full).

op encode_sign_args :
  Pulsar_N1.share_t -> Pulsar_N1.message_t -> Pulsar_N1.ctx_t ->
  Pulsar_N1.randomness_t ->
  Pulsar_N1_Sign_Refinement.mem_t *
  Pulsar_N1_Sign_Refinement.sign_ptrs_t.

(* Type-conversion ops between Pulsar_N1's abstract types and the
   sign-refinement file's abstract types. *)
op n1_rnd_to_refine    :
  Pulsar_N1.randomness_t -> Pulsar_N1_Sign_Refinement.randomness_t.
op n1_share_to_refine  :
  Pulsar_N1.share_t -> Pulsar_N1_Sign_Refinement.share_t.
op n1_msg_to_refine    :
  Pulsar_N1.message_t -> Pulsar_N1_Sign_Refinement.message_t.
op n1_ctx_to_refine    :
  Pulsar_N1.ctx_t -> Pulsar_N1_Sign_Refinement.ctx_t.

(* The sign-side decode-from-extracted-signature coercion. The
   combine-side coercion `refine_sig_to_n1` now lives in
   `Pulsar_N1_Combine_Refinement.ec` (alongside the byte-walk
   axiom that consumes it). *)
op refine_sig_to_n1_sign :
  Pulsar_N1_Sign_Refinement.signature_t -> Pulsar_N1.signature_t.

(* ===================================================================
   COMBINE wrapper bridge — now a LEMMA (no axiom).

   Proof composes:
     - `Pulsar_N1_Combine_Layout.encode_combine_args_layout`
       (PROVED lemma: the concrete encoder produces layout-
       conforming memory).
     - `combine_body_spec` (axiom in Refinement file; folds the
       byte-walk AND the FROST-correctness identity).
     - The DEFINITION of `combine_abs_op` (which expands to the
       centralised ML-DSA signature on the reconstructed share).

   No `combine_wrapper_bridge` axiom is needed. The wire-vs-protocol
   bridging identity that previously sat as a separate axiom is now
   absorbed into `combine_body_spec` via `combine_abs_op`'s
   definition.
   =================================================================== *)

lemma combine_wrapper_bridge :
  forall (gpk : Pulsar_N1.group_pk_t)
         (m : Pulsar_N1.message_t)
         (ctx : Pulsar_N1.ctx_t)
         (quorum : int list)
         (shares : Pulsar_N1.share_t list)
         (rho_rnd : Pulsar_N1.randomness_t)
         (r1s : Pulsar_N1.round1_t list)
         (r2s : Pulsar_N1.round2_t list),
    let (mem, ptrs, full) =
      encode_combine_args gpk m ctx quorum shares rho_rnd r1s r2s in
    refine_sig_to_n1
      (Pulsar_N1_Combine_Layout.read_signature_at
         (combine_body_fn mem ptrs)
         ptrs.`Pulsar_N1_Combine_Layout.sig_out_ptr)
    = Pulsar_N1.mldsa_sign_op
        (Pulsar_N1.reconstruct quorum shares) m ctx rho_rnd.
proof.
  move=> gpk m ctx quorum shares rho_rnd r1s r2s /=.
  (* Unfold the let-binding. *)
  rewrite /encode_combine_args /=.
  (* Apply combine_body_spec; the layout-conformance hypothesis is
     discharged by encode_combine_args_layout (PROVED). *)
  have Hlay :
    Pulsar_N1_Combine_Layout.layout_combine_args
      (Pulsar_N1_Combine_Layout.encode_combine_args
         (wire_args_of_full
            (n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s))).`1
      (Pulsar_N1_Combine_Layout.encode_combine_args
         (wire_args_of_full
            (n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s))).`2
      (wire_args_of_full
         (n1_inputs_to_combine_full gpk m ctx quorum shares
                                    rho_rnd r1s r2s)).
  - by apply Pulsar_N1_Combine_Layout.encode_combine_args_layout.
  have Hspec :=
    combine_body_spec
      (Pulsar_N1_Combine_Layout.encode_combine_args
         (wire_args_of_full
            (n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s))).`1
      (Pulsar_N1_Combine_Layout.encode_combine_args
         (wire_args_of_full
            (n1_inputs_to_combine_full gpk m ctx quorum shares
                                       rho_rnd r1s r2s))).`2
      (n1_inputs_to_combine_full gpk m ctx quorum shares
                                 rho_rnd r1s r2s)
      Hlay.
  rewrite Hspec /combine_abs_op /n1_inputs_to_combine_full /=.
  done.
qed.

(* ===================================================================
   SIGN wrapper bridge — REMAINS AN AXIOM.

   The sign refinement file has NOT yet been restructured to fold the
   wire-vs-protocol bridge into `sign_body_spec`. Doing the analogue
   refactor (carry the abstract ML-DSA inputs as ghost fields in a
   `sign_full_args_t`, define the sign-side `combine_abs_op` analogue
   definitionally, fold the identity into `sign_body_spec`) is the
   next narrow target after this commit lands.
   =================================================================== *)
axiom sign_wrapper_bridge :
  forall (sk : Pulsar_N1.share_t)
         (m : Pulsar_N1.message_t)
         (ctx : Pulsar_N1.ctx_t)
         (rho_rnd : Pulsar_N1.randomness_t),
    let (mem, ptrs) = encode_sign_args sk m ctx rho_rnd in
    refine_sig_to_n1_sign
      (Pulsar_N1_Sign_Refinement.read_sig_at
         (Pulsar_N1_Sign_Refinement.sign_body_fn mem ptrs
            (n1_rnd_to_refine rho_rnd))
         ptrs.`ptr_signature)
    = Pulsar_N1.mldsa_sign_op sk m ctx rho_rnd.

(* ===================================================================
   Wrapper modules.

   CombineExtractedWrapper : Pulsar_Threshold
     - combine: encodes args → applies byte-walk effect → decodes.
     - round1, round2: placeholders returning witness (not used by
       combine_body_axiom; the section's main theorem only consumes
       combine).

   SignExtractedWrapper : MLDSA65_Sign
     - sign: encodes args → applies byte-walk effect → decodes.
   =================================================================== *)

module CombineExtractedWrapper : Pulsar_N1.Pulsar_Threshold = {
  proc round1(sess : Pulsar_N1.session_t,
              share : Pulsar_N1.share_t,
              rho_rnd : Pulsar_N1.randomness_t)
       : Pulsar_N1.round1_t = {
    return witness;
  }

  proc round2(sess : Pulsar_N1.session_t,
              share : Pulsar_N1.share_t,
              round1_aggregate : Pulsar_N1.round1_t list,
              c_tilde : Pulsar_N1.message_t)
       : Pulsar_N1.round2_t = {
    return witness;
  }

  proc combine(group_pk : Pulsar_N1.group_pk_t,
               m : Pulsar_N1.message_t,
               ctx : Pulsar_N1.ctx_t,
               quorum : int list,
               shares : Pulsar_N1.share_t list,
               rho_rnd : Pulsar_N1.randomness_t,
               r1s : Pulsar_N1.round1_t list,
               r2s : Pulsar_N1.round2_t list)
       : Pulsar_N1.signature_t = {
    var enc : Pulsar_N1_Combine_Layout.mem_t *
              Pulsar_N1_Combine_Layout.combine_ptrs_t *
              combine_full_args_t;
    var mem_post : Pulsar_N1_Combine_Layout.mem_t;
    var sig : Pulsar_N1.signature_t;
    enc <- encode_combine_args group_pk m ctx quorum shares
                               rho_rnd r1s r2s;
    mem_post <- combine_body_fn enc.`1 enc.`2;
    sig <- refine_sig_to_n1
             (Pulsar_N1_Combine_Layout.read_signature_at
                mem_post enc.`2.`Pulsar_N1_Combine_Layout.sig_out_ptr);
    return sig;
  }
}.

module SignExtractedWrapper : Pulsar_N1.MLDSA65_Sign = {
  proc sign(sk : Pulsar_N1.share_t,
            m : Pulsar_N1.message_t,
            ctx : Pulsar_N1.ctx_t,
            rho_rnd : Pulsar_N1.randomness_t)
       : Pulsar_N1.signature_t = {
    var enc : Pulsar_N1_Sign_Refinement.mem_t *
              Pulsar_N1_Sign_Refinement.sign_ptrs_t;
    var mem_post : Pulsar_N1_Sign_Refinement.mem_t;
    var sig : Pulsar_N1.signature_t;
    enc <- encode_sign_args sk m ctx rho_rnd;
    mem_post <- Pulsar_N1_Sign_Refinement.sign_body_fn
                  enc.`1 enc.`2 (n1_rnd_to_refine rho_rnd);
    sig <- refine_sig_to_n1_sign
             (Pulsar_N1_Sign_Refinement.read_sig_at
                mem_post enc.`2.`ptr_signature);
    return sig;
  }
}.

(* ===================================================================
   Wrapper bridge lemmas — these are REAL EC lemmas with bodies.

   They reduce the procedure-level `equiv` against the abstract
   modules (CombineAbs / FIPS204Sign) to:
     (a) the wrapper modules' deterministic proc bodies, and
     (b) the bridge identities (combine_wrapper_bridge — now a
         lemma; sign_wrapper_bridge — still an axiom pending the
         sign-side refactor).
   =================================================================== *)

lemma combine_wrapper_equiv_CombineAbs :
  equiv [ CombineExtractedWrapper.combine ~ Pulsar_N1.CombineAbs.combine :
            ={arg} ==> ={res} ].
proof.
  proc.
  inline Pulsar_N1.CombineAbs.combine Pulsar_N1.FIPS204Sign.sign.
  wp; skip => />.
  smt(combine_wrapper_bridge).
qed.

lemma sign_wrapper_equiv_FIPS204Sign :
  equiv [ SignExtractedWrapper.sign ~ Pulsar_N1.FIPS204Sign.sign :
            ={arg} ==> ={res} ].
proof.
  proc.
  inline Pulsar_N1.FIPS204Sign.sign.
  wp; skip => />.
  smt(sign_wrapper_bridge).
qed.

(* ===================================================================
   Concrete extracted N1 corollary.

   Pulsar_N1.pulsar_n1_byte_equality is the GENERIC theorem (proved
   inside `section ClassN1`, parametric on abstract `T : Pulsar_Threshold`
   + `S : MLDSA65_Sign` + the two `declare axiom`s combine_body_axiom
   / S_functional_spec). After section closure, it is exported as a
   universally-quantified lemma over (S, T, equiv-on-T.combine,
   equiv-on-S.sign).

   This corollary instantiates the section parameters with the
   concrete wrapper modules and supplies the equivalence hypotheses
   from the wrapper bridge lemmas above.

   Trust boundary of this corollary:
     - 2 byte-walk + separation axioms in
       Pulsar_N1_Combine_Refinement.ec
     - 2 byte-walk + separation axioms in
       Pulsar_N1_Sign_Refinement.ec
     - 1 ABI bridge identity axiom in this file (sign_wrapper_bridge)
       — combine_wrapper_bridge is NOW A LEMMA, no axiom shape
     - 0 module-contract axioms (NO declare axiom combine_body_axiom
       / S_functional_spec in scope here)
     - All Lagrange / Shamir / FIPS-204 algebraic axioms shared with
       the generic theorem.
   =================================================================== *)

lemma pulsar_n1_byte_equality_extracted :
  equiv [
    Pulsar_N1.ThresholdRun(CombineExtractedWrapper).run
    ~ Pulsar_N1.SinglePartyRun(SignExtractedWrapper).run :
        ={group_pk, shares, quorum, m, ctx, rho_rnd}
      /\ uniq quorum{1}
      /\ size shares{1} = size quorum{1}
    ==> ={res}
  ].
proof.
  apply (Pulsar_N1.pulsar_n1_byte_equality
           SignExtractedWrapper CombineExtractedWrapper
           combine_wrapper_equiv_CombineAbs
           sign_wrapper_equiv_FIPS204Sign).
qed.

(* ===================================================================
   AXIOM ACCOUNTING (this file)

   This file declares:

     axioms (1 — ABI-layout bridge identity for SIGN):
       sign_wrapper_bridge

     ops (definitions):
       derive_c_tilde_wire, derive_t0_wire, derive_r2_msgs_wire
         (per-protocol wire-field derivers from the abstract inputs)
       n1_inputs_to_combine_full
         (record-construction adapter, composing the derivers)
       encode_combine_args
         (DEFINED — composes adapter + Layout's concrete encoder)
       encode_sign_args
       refine_sig_to_n1_sign
       n1_rnd_to_refine, n1_share_to_refine, n1_msg_to_refine,
         n1_ctx_to_refine

     modules (concrete):
       CombineExtractedWrapper : Pulsar_Threshold
       SignExtractedWrapper    : MLDSA65_Sign

     lemmas (derived, fully proved):
       combine_wrapper_bridge
         (was axiom, now lemma — proof composes
          `Pulsar_N1_Combine_Layout.encode_combine_args_layout`
          and `Pulsar_N1_Combine_Refinement.combine_body_spec`,
          using `combine_abs_op`'s definition as
          `mldsa_sign_op ∘ reconstruct`)
       combine_wrapper_equiv_CombineAbs
       sign_wrapper_equiv_FIPS204Sign
       pulsar_n1_byte_equality_extracted

   Combined with the two refinement files, the total Pulsar-side
   axiom count for the N1 byte-equality theorem is:

     - 2 in Pulsar_N1_Combine_Refinement.ec (byte-walk + separation)
     - 2 in Pulsar_N1_Sign_Refinement.ec    (byte-walk + separation)
     - 1 in this file                       (sign ABI bridge)
     - 2 in Pulsar_N1.ec                    (declare axiom
       combine_body_axiom, declare axiom S_functional_spec — to be
       replaced after this file is wired in)

   Strict-closure delta from this commit:
     IMPLEMENTATION-REFINEMENT axiom count drops 6 → 5
     (the combine wrapper-bridge axiom is now a lemma; its content
      was folded into combine_body_spec via the Refinement
      restructure that defines `combine_abs_op` as the centralised
      ML-DSA signature on the reconstructed share).

   Sign-side analogue (sign_wrapper_bridge → lemma) is the next
   narrow target; it requires extending sign_body_spec analogously
   to carry the abstract ML-DSA inputs as ghost fields.
   =================================================================== *)
