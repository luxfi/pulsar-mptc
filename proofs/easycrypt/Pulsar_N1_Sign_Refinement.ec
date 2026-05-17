(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 Sign refinement (extracted libjade ↔ FIPS204Sign) *)
(* -------------------------------------------------------------------- *)
(* This file is the discharge path for `Pulsar_N1.ec`'s section-local   *)
(* refinement axiom                                                     *)
(*                                                                      *)
(*    declare axiom S_functional_spec :                                 *)
(*      equiv [ S.sign ~ FIPS204Sign.sign :                             *)
(*                ={arg} ==> ={res} ].                                  *)
(*                                                                      *)
(* The strategy is the staged refinement Antoine outlined — break the   *)
(* whole proof into ladder rungs so reviewers can read it as small      *)
(* lemmas instead of one monster theorem.                               *)
(*                                                                      *)
(* Files (this is the top-level coordinator):                           *)
(*                                                                      *)
(*   MLDSA65_Encoding.ec       — byte-encoding/decoding lemmas:         *)
(*                               pack_pk, pack_sk, pack_signature,      *)
(*                               their inverses, and the structural     *)
(*                               relationships from FIPS 204 §3.7. The  *)
(*                               operators are already in               *)
(*                               `lemmas/MLDSA65_Functional.ec`; the    *)
(*                               byte-layout identities specific to     *)
(*                               libjade's representation live here.    *)
(*                                                                      *)
(*   MLDSA65_Jasmin_Layout.ec  — layout predicates relating the         *)
(*                               libjade-extracted `M.sign` Jasmin      *)
(*                               memory model (W64 pointers + memory)   *)
(*                               to the abstract `MLDSA65_Functional`   *)
(*                               types (bits / share_t / etc.).         *)
(*                                                                      *)
(*   Pulsar_N1_Sign_Refinement.ec  (THIS FILE) — the equiv lemma        *)
(*                               consuming the two above to discharge   *)
(*                               `S_functional_spec`.                   *)
(*                                                                      *)
(* The 7-step proof ladder:                                             *)
(*                                                                      *)
(*   1. Extracted `M.sign` writes sig bytes to `ptr_signature`.         *)
(*   2. Secret-key layout decodes to MLDSA65 functional sk.             *)
(*   3. Message pointer + m_len decodes to functional message.          *)
(*   4. Context layout decodes to functional ctx.                       *)
(*   5. Randomness path matches rho/rnd model.                          *)
(*   6. Packed output bytes equal `MLDSA65_Functional.fips204_sign`.    *)
(*   7. Therefore `M.sign` refines `FIPS204Sign.sign`.                  *)
(*                                                                      *)
(* Each step gets its own named `lemma` (one per rung) and a closure   *)
(* status (DONE / OPEN). The `S_functional_spec` REPLACEMENT — that's   *)
(* the headline lemma at the bottom of this file — only closes when    *)
(* all 7 rungs are closed.                                              *)
(*                                                                      *)
(* This file is hand-written (not auto-extracted). It is wired into    *)
(* `scripts/check-high-assurance.sh` so every CI push verifies it       *)
(* parses and the open rungs are explicit (`declare axiom`, NOT         *)
(* `admit`).                                                            *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* The extracted libjade ML-DSA-65 sign module. Same pull-in pattern as
   the combine refinement: `require import` only succeeds after
   `scripts/extract-jasmin-ec.sh` has run. *)
(* require import extraction.build.sign. *)

(* ===================================================================
   Abstract types (mirror MLDSA65_Functional + Pulsar_N1 boundary).
   Re-declared here so this file is self-contained; identified with
   the upstream types via section-local equalities when the bundle is
   composed.
   =================================================================== *)

type bits.
type signature_t.
type share_t.
type message_t.
type ctx_t.
type randomness_t.

(* Memory model: refines to libjade-extracted `glob_mem_t`. *)
type mem_t.

(* Pointer bundle the libjade `jade_sign` entry-point consumes. *)
type sign_ptrs_t = {
  ptr_signature : int;  (* W64 pointer to output sig buffer *)
  ptr_m         : int;  (* W64 pointer to message bytes *)
  m_len         : int;  (* W64 message length in bytes *)
  ptr_sk        : int;  (* W64 pointer to secret key blob *)
}.

(* Decoders matching libjade's byte layout. *)
op read_sk_at  : mem_t -> int -> share_t.
op read_msg_at : mem_t -> int -> int -> message_t.

(* libjade ML-DSA-65 sign API: deterministic mode (no ctx, no rnd
   parameter — libjade signs with deterministic randomness derived
   internally from K and the message). The `FIPS204Sign.sign` in
   `Pulsar_N1.ec` takes (sk, m, ctx, rho_rnd); the libjade extraction
   targets sk + m only — the ctx/rho_rnd dimensions are handled by
   the threshold layer above libjade. The refinement is therefore at
   the "single-party deterministic sign" boundary. *)
op read_sig_at : mem_t -> int -> signature_t.

(* ===================================================================
   Layer 1 (rung 1) — Extracted M.sign writes sig bytes to
   ptr_signature.

   Statement: a Hoare triple on `M.sign` saying "if the call
   succeeds (returns 0), the bytes at `ptr_signature` (length
   PULSARM_SIG_BYTES = 3293) are the signature value identified with
   `signature_t`".
   =================================================================== *)

(* libjade ML-DSA-65 sign signature: ptr_signature, ptr_m, m_len, ptr_sk
   plus a randombytes oracle. The randombytes is the source of the
   per-call rho_rnd. *)
module type SignBody = {
  proc sign(ptr_signature : int, ptr_m : int, m_len : int,
            ptr_sk : int) : int
}.

section SignRefinement.

declare module S <: SignBody.

(* Rung 1: open — depends on the byte-walk through the 4113-line
   extracted body. Tracked under issue #3. *)
declare axiom sign_body_writes_signature :
  forall (mem_pre : mem_t) (ptrs : sign_ptrs_t) (sig_abs : signature_t),
  hoare [ S.sign :
              ptr_signature = ptrs.`ptr_signature
           /\ ptr_m         = ptrs.`ptr_m
           /\ m_len         = ptrs.`m_len
           /\ ptr_sk        = ptrs.`ptr_sk
          ==>
              (* Postcondition placeholder pending memory-model
                 import. Will become: read_sig_at mem_post
                   ptrs.`ptr_signature = sig_abs, where sig_abs is
                 the abstract signature value the rung-6 packing
                 lemma names. *)
              true
        ].

(* ===================================================================
   Layer 2 (rungs 2-5) — Decoder identities.

   These are pure byte-structural lemmas: the layout of sk (rho || K
   || tr || s1 || s2 || t0 per FIPS 204 §3.5), message (raw bytes),
   ctx (in the threshold-layer wrapper, not in libjade itself), and
   rho_rnd path (libjade derives this internally from K + mu).

   For libjade single-party deterministic sign:
     ctx ≡ empty (handled at the Pulsar threshold layer)
     rho_rnd ≡ deterministic from (K, mu) per FIPS 204 §3.6
   so rungs 4 and 5 collapse to "no work" for libjade's API surface.
   They re-emerge as obligations on the threshold-layer wrapper, NOT
   on libjade itself, when the wrapper proof is written.
   =================================================================== *)

(* Rung 2: sk decoding. The byte-layout decoder is structural. *)
declare axiom rung2_sk_decode :
  forall (mem : mem_t) (ptr : int) (sk_abs : share_t),
    read_sk_at mem ptr = sk_abs.

(* Rung 3: message decoding. Direct byte-array view. *)
declare axiom rung3_msg_decode :
  forall (mem : mem_t) (ptr len : int) (m_abs : message_t),
    read_msg_at mem ptr len = m_abs.

(* Rungs 4 & 5: collapse to no-op for libjade deterministic sign. *)

(* ===================================================================
   Layer 3 (rung 6) — Packed output bytes equal
   MLDSA65_Functional.fips204_sign.

   The composed claim: after `M.sign` returns, the bytes at
   `ptr_signature` equal the `MLDSA65_Functional.fips204_sign`
   applied to the decoded inputs.
   =================================================================== *)

op fips204_sign : bits -> bits -> bits -> bits -> bits.
op sig_to_bits  : signature_t -> bits.
op sk_to_bits   : share_t -> bits.
op msg_to_bits  : message_t -> bits.
op ctx_to_bits  : ctx_t -> bits.
op rnd_to_bits  : randomness_t -> bits.

declare axiom rung6_pack_eq_fips204 :
  forall (mem : mem_t) (ptrs : sign_ptrs_t)
         (sk_abs : share_t) (m_abs : message_t)
         (ctx_abs : ctx_t) (rnd_abs : randomness_t),
    sig_to_bits (read_sig_at mem ptrs.`ptr_signature)
    = fips204_sign (sk_to_bits sk_abs)
                   (msg_to_bits m_abs)
                   (ctx_to_bits ctx_abs)
                   (rnd_to_bits rnd_abs).

(* ===================================================================
   Layer 4 (rung 7) — Therefore M.sign refines FIPS204Sign.sign.

   This is the lemma that ULTIMATELY replaces the section-local
   `declare axiom S_functional_spec` in `Pulsar_N1.ec`. It composes
   rungs 1-6 above.

   For now stated as a `declare axiom` (so reviewers see the
   composition shape in the file even before closure).
   =================================================================== *)

declare axiom rung7_S_functional_refines_FIPS204 :
  forall (mem_pre : mem_t) (ptrs : sign_ptrs_t)
         (sk_abs : share_t) (m_abs : message_t)
         (ctx_abs : ctx_t) (rnd_abs : randomness_t),
    sig_to_bits (read_sig_at mem_pre ptrs.`ptr_signature)
    = fips204_sign (sk_to_bits sk_abs) (msg_to_bits m_abs)
                   (ctx_to_bits ctx_abs) (rnd_to_bits rnd_abs).

end section SignRefinement.

(* ===================================================================
   Open work — explicitly named, tracked under #3.

   Rungs 4 & 5 are no-ops for libjade's API surface; the remaining
   rungs:

     Rung 1 (sign_body_writes_signature):       OPEN — byte-walk
       through 4113-line extracted `M.sign` body.
     Rung 2 (rung2_sk_decode):                  OPEN — sk byte
       decoder identity (FIPS 204 §3.5.4 sk packing).
     Rung 3 (rung3_msg_decode):                 OPEN — trivial
       memcpy view (no-op identity).
     Rung 6 (rung6_pack_eq_fips204):            OPEN — chains rungs
       1-3 through MLDSA65_Functional.fips204_sign.
     Rung 7 (rung7_S_functional_refines_FIPS204): OPEN — composes
       rungs above.

   When all rungs close:
     - This file's `declare axiom`s become `lemma`s.
     - `Pulsar_N1.S_functional_spec` is replaced by a `lemma`
       (with `S` instantiated as the extracted module).
     - The CI regression-warning for the declare-axiom shape flips
       to hard failure.
   =================================================================== *)
