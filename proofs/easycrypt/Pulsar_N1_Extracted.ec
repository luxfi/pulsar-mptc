(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 extracted byte-equality corollary                 *)
(* -------------------------------------------------------------------- *)
(* Decomplected from Pulsar_N1_Wrapper_Bridge.ec.                       *)
(*                                                                      *)
(* This file owns ONE thing: the concrete extracted N1 byte-equality    *)
(* theorem. Composes the combine-side and sign-side wrapper modules     *)
(* (each defined in its own per-side wrapper file) and instantiates     *)
(* the generic `Pulsar_N1.pulsar_n1_byte_equality` theorem with the     *)
(* equivalence hypotheses from each side's wrapper-bridge lemma.        *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* The two per-side wrapper files. Each provides its extracted-
   wrapper module + the procedure-level equiv against the
   corresponding abstract module (CombineAbs / FIPS204Sign). *)
require import Pulsar_N1_Combine_Wrapper.
require import Pulsar_N1_Sign_Wrapper.

(* Pulsar_N1 provides the generic byte-equality theorem
   `pulsar_n1_byte_equality` (proven inside `section ClassN1`,
   parametric on abstract T : Pulsar_Threshold + S : MLDSA65_Sign
   + the two declare-axiom equivalences combine_body_axiom /
   S_functional_spec). After section closure, it's exported as a
   universally-quantified lemma over (S, T, equiv-on-T.combine,
   equiv-on-S.sign). We supply concrete wrappers + bridge-lemma
   equivs here. *)
require import Pulsar_N1.

(* ===================================================================
   The concrete extracted N1 byte-equality corollary.

   Trust boundary of this corollary:
     - 2 axioms in the refinement files (component-level byte-walks):
         combine_body_compute_components_spec
                               (Pulsar_N1_Combine_Refinement.ec)
         sign_body_compute_components_spec
                               (Pulsar_N1_Sign_Refinement.ec)
       Each constrains the (c_tilde, z, h) component triple the
       extracted body produces. Byte-equality of the packed signature
       is then a derived lemma (combine_body_compute_sig_spec /
       sign_body_compute_sig_spec) via Pulsar_N1.pack_n1_signature
       being the same op on both sides.
     - 1 codec roundtrip axiom in Pulsar_N1
         pack_unpack_n1_signature_roundtrip
       Slots into the existing "~21 per-type FIPS 204 codec
       round-trip" category. Pack-injectivity is a derived lemma
       (pack_n1_signature_injective), not an axiom.
     - 0 ABI bridge identity axioms in either wrapper file
       (both wrapper bridges are lemmas).
     - 0 module-contract axioms in scope here
       (combine_body_axiom / S_functional_spec are
        section-local inside Pulsar_N1; this corollary
        does NOT depend on them, instead using the
        wrapper-bridge equivs which are real lemmas).
     - 4 Lean-bridged algebraic axioms (Lagrange/Shamir;
       see proofs/lean-easycrypt-bridge.md).
   =================================================================== *)

lemma pulsar_n1_byte_equality_extracted :
  equiv [
    Pulsar_N1.ThresholdRun(CombineExtractedWrapper).run
    ~ Pulsar_N1.SinglePartyRun(SignExtractedWrapper).run :
        ={group_pk, shares, quorum, m, ctx, rho_rnd}
      /\ uniq quorum{1}
      /\ size shares{1} = size quorum{1}
      /\ group_pk{1} = Pulsar_N1.derive_pk
                        (Pulsar_N1.reconstruct quorum{1} shares{1})
      /\ Pulsar_N1.accept_signing_attempt
           (Pulsar_N1.reconstruct quorum{1} shares{1})
           m{1} ctx{1} rho_rnd{1}
    ==> ={res}
  ].
proof.
  apply (Pulsar_N1.pulsar_n1_byte_equality
           SignExtractedWrapper CombineExtractedWrapper
           combine_wrapper_equiv_CombineAbs
           sign_wrapper_equiv_FIPS204Sign).
qed.

(* ===================================================================
   ACCOUNTING

   axioms (0):
     (none)

   PROVED lemmas:
     pulsar_n1_byte_equality_extracted

   The two byte-walk obligations are owned by the refinement
   files. The four Lean-bridged algebraic axioms are owned by
   Pulsar_N1.ec (lagrange_inverse_eval) and Pulsar_N4.ec
   (add_share_zeroR, reconstruct_linear, shamir_correct).

   See proofs/lean-easycrypt-bridge.md for the algebraic-bridge
   correspondence and proofs/easycrypt/extraction/
   {combine,sign}-byte-walk-roadmap.md for the remaining byte-
   walk obligations.
   =================================================================== *)
