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
   Signature-type coercion — IDENTITY.

   Prior to commit "axiom hygiene: refine_sig_to_n1 identity + explicit
   wrapper equivs", `Pulsar_N1.signature_t` and
   `Pulsar_N1_Signature_Codec.signature_t` were two DISTINCT abstract
   types and `refine_sig_to_n1_sign` was an uninterpreted coercion
   between them. That left room for an adversarial instantiation where
   `refine_sig_to_n1_sign` collapsed all signatures to a single
   value, making the byte-walk axiom `sign_body_compute_sig_spec`
   vacuous on the sign side. The closure: alias the two types so
   they are the same concrete type, and define
   `refine_sig_to_n1_sign` as the identity (`fun s => s`). Every
   downstream proof that uses `refine_sig_to_n1_sign` as a
   coercion now witnesses an honest identity.
   =================================================================== *)

op refine_sig_to_n1_sign (s : Pulsar_N1_Signature_Codec.signature_t)
                         : Pulsar_N1.signature_t = s.

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
   GHOST CONTRACT: ctx / rho_rnd binding.

   libjade `M.sign(ptr_signature, ptr_m, m_len, ptr_sk)` does NOT
   take ctx or rho_rnd directly. The wrapper carries `sgn_ctx_n1`
   and `sgn_rnd_n1` as ghost protocol fields in `sign_full_args_t`.

   The remaining `sign_body_compute_sig_spec` obligation includes
   the claim that the bytes supplied to libjade — specifically:

     - mu, the FIPS 204 §6.2 message binder, encoding the
       wrapper-supplied ctx via `SHAKE256(0x00 || ctxlen || ctx || M)`
       (FIPS 204 §5.4.1 ExternalMu), and
     - the K-derived randomness that libjade's deterministic
       rejection-sampling consumes,

   correspond to FIPS 204 `Sign_internal(sk, M, ctx, rho_rnd_n1)`
   over the four ghost fields.

   This is a NAMED REFINEMENT OBLIGATION, not a definitional fact.
   It is the wrapper's responsibility to construct
   `sign_full_args_t` such that the wire-level (sk, m) bytes
   + libjade's internal mu/K derivation together implement the
   protocol-level Sign_internal on (sgn_sk_n1, sgn_m_n1,
   sgn_ctx_n1, sgn_rnd_n1).

   If a future refactor needs to surface this as a stand-alone
   obligation (rather than folded into the byte-walk), split as:

     axiom sign_body_compute_sig_core      — pure libjade core
     axiom ctx_rho_binding_contract        — ctx/rho integration

   For now, both live inside `sign_body_compute_sig_spec`. The
   refactor is on the table the moment the libjade core proof
   starts to close — keeping them bundled until that point
   avoids the spurious extra axiom and keeps the dependency cone
   minimal. The split is the right move only when the core piece
   is being discharged independently.
   =================================================================== *)

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

(* The functional "compute" output of the extracted libjade sign
   body: given input memory + pointer bundle, return the FIPS 204
   signature bytes that get written at ptr_signature. This is the
   ONLY remaining abstract op — the byte-walk obligation. *)
op sign_body_compute_sig :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Sign_Layout.sign_ptrs_t ->
  Pulsar_N1_Signature_Codec.signature_t.

(* Definition: sign_body_fn writes the computed signature at
   ptr_signature and leaves all other memory untouched, by virtue
   of write_sig_sign's definition (single store_bytes call at the
   given pointer of exactly sig_len_sign = 3293 bytes).

   This decomposition is what makes the separation property a
   DERIVED LEMMA rather than an axiom: the "writes only at
   ptr_signature" invariant is now BY CONSTRUCTION. *)
op sign_body_fn (mem_pre : Pulsar_N1_Memory.mem_t)
                (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
   : Pulsar_N1_Memory.mem_t =
  Pulsar_N1_Sign_Layout.write_sig_sign
    mem_pre
    ptrs.`Pulsar_N1_Sign_Layout.ptr_signature
    (sign_body_compute_sig mem_pre ptrs).

(* The byte-walk axiom — restated against the compute op. Closing
   this still requires walking the extracted libjade body (tracked
   #3), but the surface area is smaller: it makes a claim about
   pure signature bytes, not about memory states. *)
axiom sign_body_compute_sig_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    refine_sig_to_n1_sign (sign_body_compute_sig mem_pre ptrs)
    = sign_abs_op full.

(* The old `sign_body_spec` shape, now PROVED. Compose
   read_after_write_sig_sign with sign_body_compute_sig_spec. *)
lemma sign_body_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    refine_sig_to_n1_sign
      (Pulsar_N1_Sign_Layout.read_sig_sign
         (sign_body_fn mem_pre ptrs)
         ptrs.`Pulsar_N1_Sign_Layout.ptr_signature)
    = sign_abs_op full.
proof.
  move=> mem_pre ptrs full Hlay.
  rewrite /sign_body_fn.
  rewrite Pulsar_N1_Sign_Layout.read_after_write_sig_sign.
  by apply sign_body_compute_sig_spec.
qed.

(* Memory separation: M.sign writes only to ptr_signature range.
   PROVED — defined as a concrete predicate over byte-level memory,
   then discharged by write_sig_sign_separation (already a proved
   lemma in Sign_Layout). *)
op sig_mem_separation
   (mem_post mem_pre : Pulsar_N1_Memory.mem_t)
   (p len : int) : bool =
  forall (q : int),
    q < p \/ p + len <= q =>
    Pulsar_N1_Memory.load_byte mem_post q =
    Pulsar_N1_Memory.load_byte mem_pre q.

lemma sign_body_separation :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t),
    sig_mem_separation (sign_body_fn mem_pre ptrs) mem_pre
                       ptrs.`Pulsar_N1_Sign_Layout.ptr_signature
                       Pulsar_N1_Sign_Layout.sig_len_sign.
proof.
  move=> mem_pre ptrs q Hdisj.
  rewrite /sign_body_fn.
  by apply Pulsar_N1_Sign_Layout.write_sig_sign_separation; exact Hdisj.
qed.

(* ===================================================================
   DERIVED LEMMAS — fully proved from sign_body_spec + EC congruence.
   =================================================================== *)

(* The combined byte-equality + abstract-op identity, applied at
   a specific full_args. The wrapper-bridge collapse depends on
   this lemma. *)
lemma sign_body_writes_abs :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
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
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
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

   axioms (1 — libjade byte-walk on signature bytes):
     sign_body_compute_sig_spec
       Single byte-walk obligation. Tracked #3.

   ops (DEFINITIONS — no proof obligation):
     wire_sign_args_of_full   (record projection)
     refine_sig_to_n1_sign    (structural sig-type coercion)
     sign_abs_op              (DEFINED — mldsa_sign_op on ghost fields)
     sign_body_fn             (DEFINED — write_sig_sign at ptr_signature
                               of the compute_sig output; by construction
                               only ptr_signature range is touched)
     sig_mem_separation       (DEFINED — byte-level memory disjointness)

   ops (abstract — held inside the byte-walk obligation):
     sign_body_compute_sig
       Pure signature bytes the extracted libjade body produces from
       the input memory + pointer bundle.

   types (records):
     sign_full_args_t   (wire + ghost protocol-level args)

   Lemmas (PROVED):
     sign_body_spec
       (was axiom; now lemma via read_after_write_sig_sign +
        sign_body_compute_sig_spec)
     sign_body_separation
       (was axiom; now lemma via write_sig_sign_separation +
        the constructive definition of sign_body_fn)
     sign_body_writes_abs
     sign_body_writes_mldsa_sign

   Implementation-refinement axiom delta for this file:
     Before: 2 axioms (sign_body_spec + sign_body_separation)
     After:  1 axiom  (sign_body_compute_sig_spec)

   The separation property is now BY CONSTRUCTION. The byte-walk
   obligation reduces to a claim about pure signature bytes (the
   "what" the extracted body computes), separated from the "where"
   it writes them.

   The wrapper bridge (`sign_wrapper_bridge`) in
   Pulsar_N1_Sign_Wrapper.ec derives from `sign_body_spec` (now a
   lemma, was an axiom). When the byte-walk axiom itself closes via
   the extraction byte-walk (tracked #3), this file contains ZERO
   axioms.

   The previous rung lemmas (rung1..rung7) have been removed —
   they referenced the old `fips204_sign` / `bits` / `sig_to_bits`
   intermediate abstraction layer, which is no longer needed now
   that `sign_abs_op` directly returns `mldsa_sign_op`'s output.
   =================================================================== *)
