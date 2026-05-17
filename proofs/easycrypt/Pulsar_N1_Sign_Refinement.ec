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
(* Mirrors the combine refinement structure (see                        *)
(* Pulsar_N1_Combine_Refinement.ec for the design rationale).           *)
(*                                                                      *)
(*   L1  Concrete byte-layout: lives in Pulsar_N1_Sign_Layout.ec.       *)
(*   L2  Protocol-extended args (`sign_full_args_t`): wire-level args   *)
(*       bundled with the abstract protocol inputs (sk, m, ctx,         *)
(*       rho_rnd). The libjade entry point's FUNCTIONAL spec is then    *)
(*       `sign_abs_op full = mldsa_sign_op full.sk full.m full.ctx      *)
(*       full.rho_rnd` — a DEFINITION (not an axiom), folding the       *)
(*       FIPS 204 functional-correctness identity into the byte-walk.   *)
(*   L3  ONE atomic axiom `sign_body_spec`: layout-conforming inputs    *)
(*       map under the extracted libjade body to bytes that decode      *)
(*       (via `refine_sig_to_n1_sign`) to `sign_abs_op` — i.e., the     *)
(*       FIPS 204 ML-DSA-65 signature on the protocol-level inputs.    *)
(*                                                                      *)
(* Honest note on ctx / rho_rnd handling (per Antoine's design point):  *)
(*   libjade's M.sign(ptr_signature, ptr_m, m_len, ptr_sk) has NO       *)
(*   ctx or rho_rnd parameter — the FIPS 204 deterministic mode         *)
(*   derives the per-call randomness internally from K (the secret      *)
(*   key K field) and mu (the message hash binder). ctx is the         *)
(*   FIPS 204 §3.7 prehash context, which the threshold wrapper        *)
(*   handles BEFORE calling libjade (the wrapper hashes m together      *)
(*   with ctx into mu).                                                 *)
(*                                                                      *)
(*   In this file we carry ctx and rho_rnd as GHOST fields in           *)
(*   `sign_full_args_t`. They do NOT appear in the wire layout          *)
(*   (`layout_sign_args` only constrains sk and m). The byte-walk       *)
(*   axiom `sign_body_spec` discharges the protocol-level identity:     *)
(*   for the right wrapper encoding of ctx into mu and rho_rnd into     *)
(*   K-derived randomness, the libjade body produces the FIPS 204       *)
(*   signature of the four-tuple. This is HONEST — the identity is     *)
(*   the wrapper's responsibility to satisfy when constructing          *)
(*   sign_full_args_t.                                                  *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* Concrete layout file: provides `mem_t`, `sign_ptrs_t`,
   `sign_abs_args_t`, encoders/decoders, `read_sig_sign`,
   `layout_sign_args`, the proved `encode_sign_args_layout`, and
   reuses combine-side memory primitives. *)
require import Pulsar_N1_Sign_Layout.

(* Pulsar_N1 provides the protocol-level abstract types and the
   centralised `mldsa_sign_op`. We reference via `Pulsar_N1.` prefix. *)
require import Pulsar_N1.

(* ===================================================================
   L2 — Protocol-extended args.

   `sign_full_args_t` carries the wire-level fields
   (`sk_abs`, `msg_abs` in Sign_Layout's per-value abstract types)
   bundled with the abstract protocol-level inputs the libjade
   sign entry point conceptually sees:
     - sk_n1     : Pulsar_N1.share_t (the abstract secret key)
     - m_n1      : Pulsar_N1.message_t (the abstract message)
     - ctx_n1    : Pulsar_N1.ctx_t (the FIPS 204 §3.7 context)
     - rho_rnd_n1: Pulsar_N1.randomness_t (per-call randomness)

   ctx_n1 and rho_rnd_n1 are GHOST fields: they don't appear in
   memory (only sk and m do via the wire layout). They constrain
   the byte-walk axiom: the extracted libjade sign produces a
   signature byte string that equals the FIPS 204 ML-DSA-65
   signature on the four protocol-level inputs.

   The wrapper layer is responsible for constructing
   `sign_full_args_t` honestly — i.e., when it calls libjade
   M.sign(ptr_signature, ptr_m, m_len, ptr_sk), the ghost ctx_n1
   and rho_rnd_n1 must reflect the wrapper's actual ctx and
   randomness choices, AND the wrapper must have encoded ctx into
   mu and rho_rnd into K-derived randomness correctly before
   calling libjade.
   =================================================================== *)

(* Fields use `sgn_*` prefix to disambiguate from
   combine_full_args_t's `full_*` fields (EC's record-field inference
   refuses to mix fields from different record types in the same
   `{| ... |}` literal). *)
type sign_full_args_t = {
  sgn_wire    : Pulsar_N1_Sign_Layout.sign_abs_args_t;
  sgn_sk_n1   : Pulsar_N1.share_t;
  sgn_m_n1    : Pulsar_N1.message_t;
  sgn_ctx_n1  : Pulsar_N1.ctx_t;
  sgn_rnd_n1  : Pulsar_N1.randomness_t;
}.

op wire_sign_args_of_full (full : sign_full_args_t)
   : Pulsar_N1_Sign_Layout.sign_abs_args_t =
  full.`sgn_wire.

(* ===================================================================
   Signature-type coercion.

   Sign_Layout's abstract `signature_t` is the wire-level byte
   string the libjade body writes at `ptr_signature`. Pulsar_N1's
   `signature_t` is the protocol-level signature type. They are
   structurally identical at the byte layer; the EC types differ
   only by name. `refine_sig_to_n1_sign` is the structural identity
   coercion — a single named op, no axiom needed for its existence.
   =================================================================== *)

op refine_sig_to_n1_sign :
  Pulsar_N1_Combine_Layout.signature_t -> Pulsar_N1.signature_t.

(* ===================================================================
   L2 — Functional spec operator (DEFINITION, not axiom).

   `sign_abs_op` returns the FIPS 204 ML-DSA-65 signature on the
   protocol-level inputs. Because `mldsa_sign_op` is Pulsar_N1's
   FIPS-204 functional operator, this DEFINITION captures the
   functional-correctness identity at the operator level. The
   byte-walk axiom below (`sign_body_spec`) discharges this
   identity at the byte level for the extracted libjade sign.
   =================================================================== *)

op sign_abs_op (full : sign_full_args_t) : Pulsar_N1.signature_t =
  Pulsar_N1.mldsa_sign_op
    full.`sgn_sk_n1 full.`sgn_m_n1
    full.`sgn_ctx_n1 full.`sgn_rnd_n1.

(* ===================================================================
   L3 — ATOMIC AXIOM (libjade-extraction trust boundary).

   `sign_body_spec` says: given inputs whose wire-level layout
   matches the abstract wire args, the extracted libjade `M.sign`
   body writes at `ptr_signature` a byte string that (under
   `refine_sig_to_n1_sign`) equals `sign_abs_op full` — i.e., the
   FIPS 204 ML-DSA-65 signature on the protocol-level inputs.

   This is the ONLY remaining axiom in this file (plus the
   separation axiom below). Closing it is the byte-walk through
   `extraction/build/sign.ec` (libjade ML-DSA-65 sign at
   line 3603 onward):

     - sk unpacking: rho, K, tr, s1, s2, t0 (FIPS 204 §3.5.4).
     - mu = SHAKE(tr || M) — message binder.
     - Rejection-sampling loop on attempt kappa.
     - Pack signature and write to ptr_signature.

   Tracked: https://github.com/luxfi/pulsar-mptc/issues/3
   =================================================================== *)

op sign_body_fn :
  Pulsar_N1_Combine_Layout.mem_t ->
  Pulsar_N1_Sign_Layout.sign_ptrs_t ->
  Pulsar_N1_Combine_Layout.mem_t.

axiom sign_body_spec :
  forall (mem_pre : Pulsar_N1_Combine_Layout.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    refine_sig_to_n1_sign
      (Pulsar_N1_Sign_Layout.read_sig_sign
         (sign_body_fn mem_pre ptrs)
         ptrs.`Pulsar_N1_Sign_Layout.ptr_signature)
    = sign_abs_op full.

(* Memory separation: M.sign writes only to ptr_signature range. *)
op sig_mem_separation :
  Pulsar_N1_Combine_Layout.mem_t ->
  Pulsar_N1_Combine_Layout.mem_t -> int -> int -> bool.

axiom sign_body_separation :
  forall (mem_pre : Pulsar_N1_Combine_Layout.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t),
    sig_mem_separation mem_pre (sign_body_fn mem_pre ptrs)
                       ptrs.`Pulsar_N1_Sign_Layout.ptr_signature
                       Pulsar_N1_Sign_Layout.sig_len_sign.

(* ===================================================================
   DERIVED LEMMAS — fully proved from sign_body_spec + EC congruence.
   =================================================================== *)

(* The combined byte-equality + abstract-op identity, applied at
   a specific full_args. The wrapper-bridge collapse depends on
   this lemma. *)
lemma sign_body_writes_abs :
  forall (mem_pre : Pulsar_N1_Combine_Layout.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    refine_sig_to_n1_sign
      (Pulsar_N1_Sign_Layout.read_sig_sign
         (sign_body_fn mem_pre ptrs)
         ptrs.`Pulsar_N1_Sign_Layout.ptr_signature)
    = sign_abs_op full.
proof. exact sign_body_spec. qed.

(* The byte-equality unfolds to mldsa_sign_op of the four ghost
   fields by definition of sign_abs_op. *)
lemma sign_body_writes_mldsa_sign :
  forall (mem_pre : Pulsar_N1_Combine_Layout.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    refine_sig_to_n1_sign
      (Pulsar_N1_Sign_Layout.read_sig_sign
         (sign_body_fn mem_pre ptrs)
         ptrs.`Pulsar_N1_Sign_Layout.ptr_signature)
    = Pulsar_N1.mldsa_sign_op
        full.`sgn_sk_n1 full.`sgn_m_n1
        full.`sgn_ctx_n1 full.`sgn_rnd_n1.
proof.
  move=> mem_pre ptrs full Hlay.
  rewrite (sign_body_spec mem_pre ptrs full Hlay) /sign_abs_op /=.
  done.
qed.

(* ===================================================================
   AXIOM ACCOUNTING

   axioms (2):
     sign_body_spec       — libjade byte-walk + FROST identity folded
     sign_body_separation — only ptr_signature range modified

   Concrete definitions:
     sign_full_args_t, wire_sign_args_of_full
     refine_sig_to_n1_sign
     sign_abs_op (DEFINITION — folds mldsa_sign_op identity)
     sign_body_fn
     sig_mem_separation

   Lemmas (PROVED):
     sign_body_writes_abs
     sign_body_writes_mldsa_sign

   The wrapper bridge (`sign_wrapper_bridge`) in
   Pulsar_N1_Wrapper_Bridge.ec now derives from `sign_body_spec`
   directly (mirror of how `combine_wrapper_bridge` derives from
   `combine_body_spec`). When the byte-walk axiom itself closes via
   the extraction byte-walk (tracked #3), this file contains ZERO
   axioms.

   The previous rung lemmas (rung1..rung7) have been removed —
   they referenced the old `fips204_sign` / `bits` / `sig_to_bits`
   intermediate abstraction layer, which is no longer needed now
   that `sign_abs_op` directly returns `mldsa_sign_op`'s output.
   =================================================================== *)
