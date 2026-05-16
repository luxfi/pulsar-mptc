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

(* Main theorem: the public key is invariant across reshare. The
   universally-bound arguments are suffixed `_pre` so the hoare-triple
   precondition can actually constrain the procedure's parameters
   against the caller's intended inputs (the original phrasing
   `c_old = c_old` was a self-shadowing tautology). *)
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
  (* The cryptographic-reduction core remains an `admit` --- closing it
     requires (i) the Shamir-zero re-randomisation property
     (reshare = fresh sharing of the same secret) and (ii) R_q-linearity
     of derive_pk = A·s + e. Both are out-of-scope for the EasyCrypt
     functional layer; they live in the Lean theory at
     `Crypto.Threshold.Lagrange.threshold_reconstructs_secret`. This
     admit is the *only* remaining proof obligation in N4, after the
     shadowing fix above made the precondition meaningful. *)
  admit.
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
            ==> true (* TODO: state the committee-root binding *) ].
proof.
  admit.
qed.

end section ClassN4.
