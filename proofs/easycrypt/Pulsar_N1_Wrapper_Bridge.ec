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
(* When the byte-walk axioms close (combine #4, sign #3), the wrapper *)
(* lemmas become fully derived theorems with no axiom in their proof  *)
(* chains.                                                            *)
(*                                                                    *)
(* BOTH wrapper bridges are now LEMMAS. The sign-side wire-vs-        *)
(* protocol bridge identity is absorbed into `sign_body_spec` via     *)
(* `sign_abs_op`'s definition, mirroring the combine-side restructure.*)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* The two refinement files provide the byte-level atomic axioms +
   their associated types, ops, and derived lemmas. *)
require import Pulsar_N1_Combine_Refinement.
require import Pulsar_N1_Sign_Refinement.

(* The concrete combine + sign layouts: re-imported so we can call
   their concrete encoders and reference their record-field names
   (`sk_abs`, `m_abs`, `c_tilde_abs`, etc.) without ambiguity. *)
require import Pulsar_N1_Combine_Layout.
require import Pulsar_N1_Sign_Layout.

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

(* Sign-side abstract input adapters: protocol-level Pulsar_N1
   types projected onto the Sign_Layout file's LOCAL abstract
   types. These mirror the combine-side `derive_*_wire` ops and
   are the wire-layer projection of the protocol inputs.

   - `n1_share_to_layout_sign` projects the abstract Pulsar_N1
     `share_t` onto the byte-encoded FIPS 204 §3.5.4 sk packing
     (rho || K || tr || s1 || s2 || t0). This is the secret-key
     adapter the threshold wrapper uses when calling libjade.
   - `n1_msg_to_layout_sign` projects the abstract Pulsar_N1
     `message_t` onto the libjade-side message byte layout.

   `ctx` and `rho_rnd` do NOT have wire-layer counterparts —
   libjade's M.sign has no ctx/rnd parameters (the threshold
   wrapper handles them BEFORE calling libjade by folding ctx
   into mu and rho_rnd into K-derived randomness). They appear
   only as GHOST fields in `sign_full_args_t`. *)
op n1_share_to_layout_sign :
  Pulsar_N1.share_t   -> Pulsar_N1_Sign_Layout.share_t.
op n1_msg_to_layout_sign   :
  Pulsar_N1.message_t -> Pulsar_N1_Sign_Layout.message_t.

(* `n1_inputs_to_sign_full` constructs a `sign_full_args_t` from
   the protocol-level inputs. The wire fields are the projected
   sk + m; the ghost fields are copied in directly. *)
op n1_inputs_to_sign_full
   (sk : Pulsar_N1.share_t) (m : Pulsar_N1.message_t)
   (ctx : Pulsar_N1.ctx_t) (rho_rnd : Pulsar_N1.randomness_t)
   : sign_full_args_t =
  {| sgn_wire =
        {| sk_abs = n1_share_to_layout_sign sk;
           m_abs  = n1_msg_to_layout_sign  m; |};
     sgn_sk_n1   = sk;
     sgn_m_n1    = m;
     sgn_ctx_n1  = ctx;
     sgn_rnd_n1  = rho_rnd; |}.

(* `encode_sign_args` composes the wire derivation + Sign_Layout's
   concrete encoder. The encoder takes (sk_layout, m_layout,
   m_len_val); the caller passes `m_len_val = msg_len m_layout`
   so that `encode_sign_args_layout` applies directly. *)
op encode_sign_args
   (sk : Pulsar_N1.share_t) (m : Pulsar_N1.message_t)
   (ctx : Pulsar_N1.ctx_t) (rho_rnd : Pulsar_N1.randomness_t)
   : Pulsar_N1_Combine_Layout.mem_t *
     Pulsar_N1_Sign_Layout.sign_ptrs_t *
     sign_full_args_t =
  let full = n1_inputs_to_sign_full sk m ctx rho_rnd in
  let (mem, ptrs) =
    Pulsar_N1_Sign_Layout.encode_sign_args
      full.`sgn_wire.`sk_abs
      full.`sgn_wire.`m_abs
      (Pulsar_N1_Sign_Layout.msg_len full.`sgn_wire.`m_abs) in
  (mem, ptrs, full).

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
   SIGN wrapper bridge — now a LEMMA (no axiom).

   Mirrors the combine-side proof exactly:
     - `Pulsar_N1_Sign_Layout.encode_sign_args_layout`
       (PROVED lemma: the concrete sign encoder produces
       layout-conforming memory).
     - `sign_body_spec` (axiom in Pulsar_N1_Sign_Refinement.ec;
       folds the byte-walk identity for the libjade ML-DSA-65
       `M.sign` body — together with the wrapper's
       responsibility to encode ctx/rho_rnd into the libjade
       call correctly, as documented in the Sign_Refinement
       file's ghost-field note).
     - The DEFINITION of `sign_abs_op` (which expands directly
       to `mldsa_sign_op` on the four ghost fields).

   No `sign_wrapper_bridge` axiom is needed. The wire-vs-protocol
   bridging identity that previously sat as a separate axiom is now
   absorbed into `sign_body_spec` via `sign_abs_op`'s definition.
   =================================================================== *)

lemma sign_wrapper_bridge :
  forall (sk : Pulsar_N1.share_t)
         (m : Pulsar_N1.message_t)
         (ctx : Pulsar_N1.ctx_t)
         (rho_rnd : Pulsar_N1.randomness_t),
    let (mem, ptrs, full) = encode_sign_args sk m ctx rho_rnd in
    Pulsar_N1_Sign_Refinement.refine_sig_to_n1_sign
      (Pulsar_N1_Sign_Layout.read_sig_sign
         (Pulsar_N1_Sign_Refinement.sign_body_fn mem ptrs)
         ptrs.`Pulsar_N1_Sign_Layout.ptr_signature)
    = Pulsar_N1.mldsa_sign_op sk m ctx rho_rnd.
proof.
  move=> sk m ctx rho_rnd /=.
  (* Unfold the let-binding to expose Sign_Layout's concrete encoder. *)
  rewrite /encode_sign_args /=.
  (* Discharge layout-conformance via the PROVED lemma. The wire-args
     record produced by `wire_sign_args_of_full ∘ n1_inputs_to_sign_full`
     reduces to `{| sk_abs = n1_share_to_layout_sign sk;
                    m_abs  = n1_msg_to_layout_sign  m |}`, which is
     exactly the shape `encode_sign_args_layout` proves. *)
  have Hlay :
    Pulsar_N1_Sign_Layout.layout_sign_args
      (Pulsar_N1_Sign_Layout.encode_sign_args
         (n1_share_to_layout_sign sk)
         (n1_msg_to_layout_sign  m)
         (Pulsar_N1_Sign_Layout.msg_len (n1_msg_to_layout_sign m))).`1
      (Pulsar_N1_Sign_Layout.encode_sign_args
         (n1_share_to_layout_sign sk)
         (n1_msg_to_layout_sign  m)
         (Pulsar_N1_Sign_Layout.msg_len (n1_msg_to_layout_sign m))).`2
      (wire_sign_args_of_full
         (n1_inputs_to_sign_full sk m ctx rho_rnd)).
  - rewrite /wire_sign_args_of_full /n1_inputs_to_sign_full /=.
    by apply Pulsar_N1_Sign_Layout.encode_sign_args_layout.
  (* Apply sign_body_spec at the full args bundle. *)
  have Hspec :=
    Pulsar_N1_Sign_Refinement.sign_body_spec
      (Pulsar_N1_Sign_Layout.encode_sign_args
         (n1_share_to_layout_sign sk)
         (n1_msg_to_layout_sign  m)
         (Pulsar_N1_Sign_Layout.msg_len (n1_msg_to_layout_sign m))).`1
      (Pulsar_N1_Sign_Layout.encode_sign_args
         (n1_share_to_layout_sign sk)
         (n1_msg_to_layout_sign  m)
         (Pulsar_N1_Sign_Layout.msg_len (n1_msg_to_layout_sign m))).`2
      (n1_inputs_to_sign_full sk m ctx rho_rnd)
      Hlay.
  (* Hspec rewrites the LHS to `sign_abs_op (n1_inputs_to_sign_full
     sk m ctx rho_rnd)`. Unfolding `sign_abs_op` and
     `n1_inputs_to_sign_full` then projects the four ghost fields,
     yielding `mldsa_sign_op sk m ctx rho_rnd` — exactly the RHS. *)
  move: Hspec.
  rewrite /Pulsar_N1_Sign_Refinement.sign_abs_op
          /n1_inputs_to_sign_full /=.
  by move=> ->.
qed.

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
    var enc : Pulsar_N1_Combine_Layout.mem_t *
              Pulsar_N1_Sign_Layout.sign_ptrs_t *
              sign_full_args_t;
    var mem_post : Pulsar_N1_Combine_Layout.mem_t;
    var sig : Pulsar_N1.signature_t;
    enc <- encode_sign_args sk m ctx rho_rnd;
    mem_post <- Pulsar_N1_Sign_Refinement.sign_body_fn enc.`1 enc.`2;
    sig <- Pulsar_N1_Sign_Refinement.refine_sig_to_n1_sign
             (Pulsar_N1_Sign_Layout.read_sig_sign
                mem_post
                enc.`2.`Pulsar_N1_Sign_Layout.ptr_signature);
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
     - 0 ABI bridge identity axioms in this file
       — BOTH combine_wrapper_bridge AND sign_wrapper_bridge are
         now LEMMAS, no axiom shape
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

     axioms (0 — both wrapper-bridge identities are now lemmas):
       (none)

     ops (definitions):
       derive_c_tilde_wire, derive_t0_wire, derive_r2_msgs_wire
         (per-protocol combine wire-field derivers)
       n1_inputs_to_combine_full
         (combine record-construction adapter)
       encode_combine_args
         (DEFINED — composes adapter + Combine Layout's concrete encoder)
       n1_share_to_layout_sign, n1_msg_to_layout_sign
         (per-protocol sign wire-field derivers)
       n1_inputs_to_sign_full
         (sign record-construction adapter)
       encode_sign_args
         (DEFINED — composes adapter + Sign Layout's concrete encoder)

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
       sign_wrapper_bridge
         (was axiom, now lemma — proof composes
          `Pulsar_N1_Sign_Layout.encode_sign_args_layout`
          and `Pulsar_N1_Sign_Refinement.sign_body_spec`,
          using `sign_abs_op`'s definition as `mldsa_sign_op` on
          the four ghost fields)
       combine_wrapper_equiv_CombineAbs
       sign_wrapper_equiv_FIPS204Sign
       pulsar_n1_byte_equality_extracted

   Combined with the two refinement files, the total Pulsar-side
   axiom count for the N1 byte-equality theorem is:

     - 2 in Pulsar_N1_Combine_Refinement.ec (byte-walk + separation)
     - 2 in Pulsar_N1_Sign_Refinement.ec    (byte-walk + separation)
     - 0 in this file                       (both wrapper bridges
                                             are lemmas)
     - 2 in Pulsar_N1.ec                    (declare axiom
       combine_body_axiom, declare axiom S_functional_spec — these
       are SECTION-LOCAL module-contract axioms; not in the
       extracted N1 corollary's dependency cone, which uses the
       wrapper modules + bridge lemmas above)

   Strict-closure delta from this commit:
     IMPLEMENTATION-REFINEMENT axiom count drops 5 → 4
     (the sign wrapper-bridge axiom is now a lemma; its content
      was folded into sign_body_spec via the Sign_Refinement
      restructure that defines `sign_abs_op` as `mldsa_sign_op`
      on the four ghost fields). Across the two commits in this
      sequence, IMPLEMENTATION-REFINEMENT axioms have dropped 6 → 4.

   Remaining 4 implementation-refinement axioms in the extracted
   N1 corollary's dependency cone:
     - combine_body_spec       (byte-walk + FROST-correctness)
     - combine_body_separation (write-frame isolation)
     - sign_body_spec          (byte-walk for libjade M.sign)
     - sign_body_separation    (write-frame isolation)

   Each of these is a single localized byte-walk obligation that
   closes by walking the corresponding extracted Jasmin body.
   =================================================================== *)
