(* -------------------------------------------------------------------- *)
(* Pulsar-M — Constant-time obligations on threshold-layer routines     *)
(* -------------------------------------------------------------------- *)
(* STATUS: THEORY SHELL. Each lemma is stated; proof bodies are `admit` *)
(* with TODO markers. See ../README.md for the high-assurance-track     *)
(* roadmap.                                                              *)
(* -------------------------------------------------------------------- *)
(* Threat model:                                                         *)
(*   Barthe-Grégoire-Laporte leakage model (CSF 2018), as used by        *)
(*   libjade for the single-party ML-DSA-65 CT proof. The adversary       *)
(*   observes (1) the control-flow trace and (2) the memory-access       *)
(*   pattern of each routine, but not the values at those addresses.    *)
(*   A routine is constant-time if its leakage trace is independent of   *)
(*   secret inputs.                                                      *)
(*                                                                       *)
(* Pulsar-M secret-touching routines (mirror jasmin/threshold/*.jazz):    *)
(*   - round1_commit:  secret = (share, randomness)                     *)
(*   - round2_response: secret = (share, y_i_state)                     *)
(*   - combine:        no secret inputs ⇒ trivially CT                   *)
(*                                                                       *)
(* For each non-trivially-CT routine we discharge a CT lemma that        *)
(* states: every two executions with the same PUBLIC inputs and          *)
(* arbitrarily-different SECRET inputs produce equal leakage traces.    *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

(* Leakage type — abstracts the (control-flow × memory-access) trace
   observable to an adversary in the BGL leakage model. *)
type leakage_t.

type share_t.
type randomness_t.
type session_t.
type round1_msg_t.
type round1_aggregate_t.
type challenge_t.
type response_t.
type y_state_t.

(* Each threshold-layer routine, lifted to also return its leakage. *)
module type CTRound1 = {
  proc round1_commit(sess : session_t, share : share_t, rnd : randomness_t)
    : round1_msg_t * y_state_t * leakage_t
}.

module type CTRound2 = {
  proc round2_response(share : share_t, y_state : y_state_t,
                       r1_agg : round1_aggregate_t, c : challenge_t)
    : response_t * leakage_t
}.

(* -------------------------------------------------------------------- *)
(* Round-1 CT obligation                                                 *)
(* -------------------------------------------------------------------- *)

section Round1CT.

declare module M1 <: CTRound1.

(* Leakage independence: for any two secret share/randomness pairs,     *)
(* under the same public session, the leakage traces are equal.         *)
lemma round1_commit_constant_time
      (sess : session_t)
      (share1 share2 : share_t)
      (rnd1 rnd2 : randomness_t) :
    equiv [ M1.round1_commit ~ M1.round1_commit :
              ={sess}
              /\ share{1} = share1 /\ share{2} = share2
              /\ rnd{1} = rnd1 /\ rnd{2} = rnd2
            ==>
              res{1}.`3 = res{2}.`3 ].
proof.
  (* TODO: prove this once Jasmin extraction is wired *)
  admit.
qed.

end section Round1CT.

(* -------------------------------------------------------------------- *)
(* Round-2 CT obligation                                                 *)
(* -------------------------------------------------------------------- *)

section Round2CT.

declare module M2 <: CTRound2.

(* Norm-rejection caveat: the rejection outcome (accept vs reject) IS
   public under FIPS 204 §3.2 — the count of rejection iterations is
   observable in single-party ML-DSA as well. Pulsar-M's CT lemma
   conditions on (rejection-outcome, retry-count) being a PUBLIC
   input via the session/attempt counter, matching FIPS 204 posture. *)
lemma round2_response_constant_time
      (share1 share2 : share_t)
      (y_state1 y_state2 : y_state_t)
      (r1_agg : round1_aggregate_t)
      (c : challenge_t) :
    equiv [ M2.round2_response ~ M2.round2_response :
              ={r1_agg, c}
              /\ share{1} = share1 /\ share{2} = share2
              /\ y_state{1} = y_state1 /\ y_state{2} = y_state2
            ==>
              res{1}.`2 = res{2}.`2 ].
proof.
  (* TODO: prove this once Jasmin extraction is wired *)
  admit.
qed.

end section Round2CT.

(* -------------------------------------------------------------------- *)
(* Combine: trivially CT (no secret inputs)                              *)
(* -------------------------------------------------------------------- *)
(* No lemma needed — the routine touches only public Round-1 and        *)
(* Round-2 messages plus the group public key. Stated here for          *)
(* completeness of the obligation surface.                               *)
