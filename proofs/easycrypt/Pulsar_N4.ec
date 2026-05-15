(* -------------------------------------------------------------------- *)
(* Pulsar — Class N4 public-key preservation across reshare           *)
(* -------------------------------------------------------------------- *)
(* STATUS: THEORY SHELL. The top-level lemma is stated; the proof body  *)
(* is `admit` with a TODO marker. See ./README.md for the high-          *)
(* assurance-track roadmap.                                              *)
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

require import AllCore List Int IntDiv Distr DBool DInt SmtMap.

type group_pk_t.
type share_t.
type committee_t.
type reshare_transcript_t.

op derive_pk : share_t -> group_pk_t.
op reconstruct : int list -> share_t list -> share_t.

module type PulsarM_Reshare = {
  proc reshare(c_old : committee_t, shares_old : share_t list,
               c_new : committee_t) : share_t list * reshare_transcript_t
}.

section ClassN4.

declare module R <: PulsarM_Reshare.

(* Main theorem: the public key is invariant across reshare. *)
lemma pulsar_m_n4_pk_preservation
      (c_old c_new : committee_t)
      (shares_old : share_t list) (q_old q_new : int list) :
    hoare [ R.reshare :
              c_old = c_old /\ shares_old = shares_old /\ c_new = c_new
            ==>
              derive_pk (reconstruct q_new res.`1)
              = derive_pk (reconstruct q_old shares_old) ].
proof.
  (* TODO: prove this once Jasmin extraction is wired *)
  admit.
qed.

(* Auxiliary lemma: the reshare transcript binds the OLD committee root *)
(* so a malicious dealer cannot substitute the committee roster.         *)
lemma pulsar_m_n4_transcript_binds_committee
      (c_old c_new : committee_t) (shares_old : share_t list) :
    hoare [ R.reshare :
              c_old = c_old /\ shares_old = shares_old /\ c_new = c_new
            ==> true (* TODO: state the binding invariant *) ].
proof.
  (* TODO: prove this once Jasmin extraction is wired *)
  admit.
qed.

end section ClassN4.
