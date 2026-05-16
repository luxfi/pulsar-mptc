(* -------------------------------------------------------------------- *)
(* Pulsar — Class N4 public-key preservation across reshare           *)
(* -------------------------------------------------------------------- *)
(* STATUS: THEORY SHELL. The top-level lemma is stated with a meaningful *)
(* precondition (shadowing-bug fix landed); the proof body remains       *)
(* `admit` pending the reshare cryptographic reduction. The auxiliary    *)
(* binding-invariant lemma is a placeholder with postcondition `true`    *)
(* (also `admit`). See ./README.md for the high-assurance-track roadmap. *)
(* -------------------------------------------------------------------- *)
(* Claim:                                                                *)
(*   The Pulsar proactive-resharing protocol (Reshare in              *)
(*   spec/pulsar.tex §4.5) preserves the group public key across      *)
(*   committee rotations. Specifically: for every starting share set     *)
(*   `shares_old` over committee `C_old` with public key                 *)
(*   `derive_pk(reconstruct(shares_old))`, after running Reshare into a *)
(*   new committee `C_new`, the resulting share set `shares_new`         *)
(*   satisfies                                                           *)
(*                                                                       *)
(*       derive_pk(reconstruct(shares_new))  =  derive_pk(reconstruct(  *)
(*                                                shares_old))           *)
(*                                                                       *)
(*   provided ≥ threshold honest parties in both committees.             *)
(*                                                                       *)
(* Reduction strategy:                                                   *)
(*   1. Shamir-zero re-randomisation: Reshare produces a fresh sharing   *)
(*      of the SAME secret over R_q by sampling shares of zero and       *)
(*      adding them to fresh shares of the original secret.              *)
(*   2. R_q-linearity: derive_pk is the linear map t = A·s + e mod q,    *)
(*      so the public key depends only on s (the secret), not on the     *)
(*      sharing.                                                          *)
(*   3. ⇒ public key is invariant across reshare.                        *)
(*                                                                       *)
(* Auxiliary obligations:                                                *)
(*   - Reshare commits new committee members to the zero-share VSS       *)
(*     transcripts so dishonest old members cannot bias new shares.      *)
(*   - The reshare ceremony's accumulator commits to the OLD committee   *)
(*     roster (committeeRootFromShares) so reviewers can detect          *)
(*     post-hoc roster substitution.                                     *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

type group_pk_t.
type share_t.
type committee_t.
type reshare_transcript_t.

op derive_pk : share_t -> group_pk_t.
op reconstruct : int list -> share_t list -> share_t.

module type Pulsar_Reshare = {
  proc reshare(c_old : committee_t, shares_old : share_t list,
               c_new : committee_t) : share_t list * reshare_transcript_t
}.

section ClassN4.

declare module R <: Pulsar_Reshare.

(* Shamir-zero re-randomisation: R.reshare produces a fresh sharing of
   the SAME secret. The new share set, Lagrange-reconstructed at any
   quorum q_new, yields the same value as the original shares
   Lagrange-reconstructed at any quorum q_old. This is the
   *cryptographic-reduction* content N4 needs.

   For an arbitrary `declare module R <: Pulsar_Reshare`, this is NOT
   provable — a malicious R can emit garbage shares. The property is
   therefore stated as a section-local `declare axiom`: a refinement
   obligation that becomes a *proof obligation about the concrete R*
   when a Jasmin/Go-extracted implementation is plugged in. The
   honest-R case is discharged by the Shamir-secret-sharing-of-zero
   algebraic identity (Lean: `Crypto.Threshold.Lagrange
   .threshold_reconstructs_secret`). *)
declare axiom reshare_preserves_secret
      (c_old_pre c_new_pre : committee_t)
      (shares_old_pre : share_t list) (q_old q_new : int list) :
    hoare [ R.reshare :
              c_old = c_old_pre /\ shares_old = shares_old_pre
                /\ c_new = c_new_pre
            ==>
              reconstruct q_new res.`1 = reconstruct q_old shares_old_pre ].

(* Main theorem: the public key is invariant across reshare. Closed
   by the Shamir-zero re-randomisation axiom + congruence under the
   `derive_pk` operator. (Function congruence is implicit in EasyCrypt
   — if x = y then f x = f y.) *)
lemma pulsar_n4_pk_preservation
      (c_old_pre c_new_pre : committee_t)
      (shares_old_pre : share_t list) (q_old q_new : int list) :
    hoare [ R.reshare :
              c_old = c_old_pre /\ shares_old = shares_old_pre
                /\ c_new = c_new_pre
            ==>
              derive_pk (reconstruct q_new res.`1)
              = derive_pk (reconstruct q_old shares_old_pre) ].
proof.
  conseq (reshare_preserves_secret c_old_pre c_new_pre
            shares_old_pre q_old q_new) => /#.
qed.

(* Auxiliary lemma: the reshare transcript binds the committee.

   The postcondition is a placeholder (literally `true`), which makes
   the lemma vacuously true.  We retain the `admit` here rather than
   attempting a tactic discharge for an abstract-module hoare triple
   without a local EasyCrypt to verify the tactic invocation; the real
   work is restating the postcondition as the committee-root binding
   invariant (spec/pulsar.tex §4.5, enforced by the Pedersen DKG
   transcript). When that happens, the lemma's body becomes the
   reduction proper. *)
lemma pulsar_n4_transcript_binds_committee
      (c_old_pre c_new_pre : committee_t)
      (shares_old_pre : share_t list) :
    hoare [ R.reshare :
              c_old = c_old_pre /\ shares_old = shares_old_pre
                /\ c_new = c_new_pre
            ==> true (* placeholder postcondition pending the real
                       committee-root binding invariant; the lemma
                       is vacuously discharged at the current shape. *) ].
proof.
  (* Postcondition is `true`; trivially satisfied by any execution
     of R.reshare. The work of restating this as the real
     committee-root binding invariant (spec/pulsar.tex §4.5)
     remains open and is tracked in BLOCKERS.md / study/pulsar.md. *)
  proc true; auto.
qed.

end section ClassN4.
