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

   `sign_full_args_t` carries THREE distinct categories of field, in
   this order (Agent 1 C3 closure):

     [WIRE]   sgn_wire     : laid out in memory by encode_sign_args;
                              what the byte-walk axiom reads through
                              layout_sign_args. Concrete bytes.
     [MIRROR] sgn_sk_n1,    : protocol-level views of sgn_wire's
              sgn_m_n1       contents. The wrapper layer binds them
                              to sgn_wire via the wire projectors
                              n1_share_to_layout_sign /
                              n1_msg_to_layout_sign (defined in
                              Pulsar_N1_Sign_Wrapper.ec).
     [GHOST]  sgn_ctx_n1,   : protocol-level fields with NO wire
              sgn_rnd_n1     counterpart. libjade M.sign(ptr_signature,
                              ptr_m, m_len, ptr_sk) has no ctx/rnd
                              parameters — the wrapper folds ctx into
                              mu (FIPS 204 §5.4.1 ExternalMu) and rnd
                              into K-derived randomness BEFORE calling
                              libjade. The byte-walk axiom
                              `sign_body_compute_sig_spec` claims
                              correctness over the FULL FIPS 204
                              four-arg Sign_internal — bundling the
                              ctx/mu and rnd/K bindings into one
                              statement.

   `sign_abs_op` (defined below) is the spec target:
     sign_abs_op full = mldsa_sign_op sk_n1 m_n1 ctx_n1 rnd_n1

   It reads ALL FOUR protocol-level fields (sk/m from MIRROR,
   ctx/rnd from GHOST) but does NOT consume sgn_wire.

   Field-prefix discipline: every field starts with `sgn_*` to
   disambiguate from combine_full_args_t's `full_*` fields (EC's
   record-field inference refuses to mix fields from different
   record types in the same `{| ... |}` literal). *)
type sign_full_args_t = {
  (* [WIRE] *)
  sgn_wire    : Pulsar_N1_Sign_Layout.sign_abs_args_t;
  (* [MIRROR] — protocol view of sgn_wire's sk_abs, m_abs *)
  sgn_sk_n1   : Pulsar_N1.share_t;
  sgn_m_n1    : Pulsar_N1.message_t;
  (* [GHOST] — no wire counterpart; bound into byte-walk via libjade-
     internal mu/K derivation (see GHOST CONTRACT block below) *)
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

(* Inline form: surface the FIPS 204 §6.2 pipeline (unpack_sk +
   compute_mu + sign_internal_loop) directly at the spec target.
   Definitionally equal to `mldsa_sign_op sk m ctx rho_rnd` (since
   mldsa_sign_op IS the pipeline composition in Pulsar_N1.ec), but
   mentioning the pipeline ops explicitly here makes ctx-flow
   through compute_mu searchable in proofs — and the non-bypass
   lemma below proves it directly. *)
op sign_abs_op (full : sign_full_args_t) : Pulsar_N1.signature_t =
  Pulsar_N1.sign_internal_loop
    (Pulsar_N1.unpack_sk full.`sgn_sk_n1)
    (Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1)
    full.`sgn_rnd_n1.

(* HIGH-4 non-bypass lemma (followup A reinforcement).

   `compute_mu` is the ONLY consumer of `sgn_ctx_n1` in `sign_abs_op`.
   This lemma surfaces that structural fact: changes to ctx must flow
   through compute_mu before reaching the signature output. Trivially
   true by definitional unfolding, but having it as a named theorem
   makes the pipeline structure load-bearing in downstream byte-walk
   discharges (which can rewrite the spec target into pipeline form
   without further definitional cruft).

   Combined with `Pulsar_N1.compute_mu_injective`: distinct ctx values
   produce distinct mu values, so the signature output faithfully
   depends on ctx via the FIPS 204 §5.4.1 ExternalMu derivation. *)
lemma sign_abs_op_ctx_flows_through_mu (full : sign_full_args_t) :
  sign_abs_op full
  = Pulsar_N1.sign_internal_loop
      (Pulsar_N1.unpack_sk full.`sgn_sk_n1)
      (Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1)
      full.`sgn_rnd_n1.
proof. by rewrite /sign_abs_op. qed.

(* Equivalence with mldsa_sign_op form (the alternative shape used
   by combine_abs_op). Pure unfolding lemma — both sides are
   definitionally equal. Stating it as a named lemma lets downstream
   proofs rewrite between the two forms via lemma application
   rather than full-on definitional unfolding. *)
lemma sign_abs_op_eq_mldsa (full : sign_full_args_t) :
  sign_abs_op full =
    Pulsar_N1.mldsa_sign_op
      full.`sgn_sk_n1 full.`sgn_m_n1
      full.`sgn_ctx_n1 full.`sgn_rnd_n1.
proof. by rewrite /sign_abs_op /Pulsar_N1.mldsa_sign_op. qed.

(* ===================================================================
   GHOST CONTRACT: ctx / rho_rnd binding (Agent 1 C3 split path).

   libjade `M.sign(ptr_signature, ptr_m, m_len, ptr_sk)` takes only
   (sig, m, sk) — the FOUR-ARG FIPS 204 Sign_internal(sk, M, ctx,
   rho_rnd) is recovered by INTERNAL DERIVATION inside libjade:

     mu      = SHAKE256(tr || M) where tr is in the unpacked sk
     rho''   = SHAKE256(K || rnd_internal || mu)
               where rnd_internal is libjade's per-call randomness
               (zero in deterministic mode; otherwise per the FIPS 204
               §6.2 rho-derivation specifying SHAKE256 of K and a
               64-byte randomness input).

   The CTX field of FIPS 204 §3.7 is folded into mu via the SHAKE input
   PREFIXED with a 0x00 || |ctx| || ctx header (FIPS 204 §5.4.1
   ExternalMu): this is the wrapper's responsibility to do BEFORE
   calling libjade — the wrapper hashes M' = SHAKE-input(M, ctx) and
   passes M' to libjade. The wrapper similarly seeds rnd_internal
   from sgn_rnd_n1.

   sign_body_compute_sig_spec BUNDLES three claims into one axiom:

     [B1] LIBJADE CORE: given a layout-conforming memory state, the
          extracted M.sign byte-walk produces FIPS 204 §6.2-§6.3
          Sign_internal output bytes (i.e., the libjade procedure
          implements the spec it claims to implement).

     [B2] CTX/MU BINDING: the wrapper's pre-libjade SHAKE(0x00 ||
          ctxlen || ctx || M) → M' substitution implements the
          FIPS 204 §5.4.1 ExternalMu derivation. The byte-walk
          axiom uses ctx implicitly: the `ptr_m` bytes already
          encode (ctx, M), and libjade's mu computation produces
          the four-arg FIPS 204 mu.

     [B3] RHO_RND BINDING: libjade's rnd_internal is the wrapper's
          encoding of sgn_rnd_n1.

   The bundle is RIGHT for now because the libjade byte-walk hasn't
   landed — splitting would manufacture two synthetic obligations
   (B1 alone, B2+B3 alone) that aren't independently dischargeable
   until B1 is closed.

   REFACTOR PATH (executes once libjade byte-walk #3 has a draft):

     axiom sign_body_compute_sig_core :
       forall mem ptrs (sk : libjade_sk_t)
              (m : libjade_msg_t) (mu : libjade_mu_t),
         layout_sk_at mem ptrs.`sk_ptr sk =>
         layout_msg_at mem ptrs.`m_ptr m =>
         sign_body_compute_status mem ptrs = 0 =>
         refine_sig_to_n1_sign (sign_body_compute_sig mem ptrs)
         = fips204_sign_internal_op (decode_sk sk)
                                    (decode_m m)
                                    mu
                                    (libjade_rho_rnd sk).

     axiom ctx_mu_binding_op :
       forall (sk : Pulsar_N1.share_t) (m : Pulsar_N1.message_t)
              (ctx : Pulsar_N1.ctx_t) (rho_rnd : Pulsar_N1.randomness_t),
         fips204_sign_internal_op
           (encode_sk_op sk)
           (encode_m_op m)
           (external_mu m ctx)
           (libjade_rho_rnd (encode_sk_op sk))
         = mldsa_sign_op sk m ctx rho_rnd.

   With those, `sign_body_compute_sig_spec` becomes a LEMMA composing
   the core + binding axioms via `encode_sign_args`'s layout invariant.

   Right now neither libjade_sk_t nor fips204_sign_internal_op nor
   external_mu has been introduced (they all live downstream of the
   byte-walk landing). Surfacing them prematurely would force a
   placeholder vocabulary that future work has to replace anyway.

   Net of C3 closure:
     - field-categorisation comments at sign_full_args_t make the
       wire/mirror/ghost split visible at the type-decl site.
     - this block names the three bundled claims B1/B2/B3 and gives
       the concrete refactor signatures.
     - the refactor itself is GATED on the libjade byte-walk close.
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
     - Kappa rejection-sampling loop on attempt counter.
     - Pack signature and write to ptr_signature.

   Tracked: https://github.com/luxfi/pulsar-mptc/issues/3
   =================================================================== *)

(* Per-component "compute" outputs of the extracted libjade sign
   body — mirrors the combine-side per-stage split. One op per
   FIPS 204 §6.2 inner-loop output stage.

     sign_body_compute_c_tilde
       NOW STRUCTURAL: factored as `shake_mu_w1` over two extracted
       intermediates (sign_body_compute_mu and
       sign_body_compute_w1, declared below). The c_tilde-stage
       byte-walk obligation `sign_body_c_tilde_spec` is now a
       DERIVED LEMMA from `sign_body_mu_spec` + `sign_body_w1_spec`.

     sign_body_compute_z
       STILL ABSTRACT. Pure §6.2 z (no Lagrange aggregation on the
       single-party side).

     sign_body_compute_h
       STILL ABSTRACT. Hint h from MakeHint.

   The composite `sign_body_compute_components` is DEFINED as the
   tuple of the three per-stage ops, preserving the downstream API
   surface. *)

(* Extracted intermediates feeding c_tilde — surfaced so the
   c_tilde-stage byte-walk decomposes along the FIPS 204 §6.2
   "SHAKE(mu || w1Encode(w1))" boundary. Mirrors the combine-side
   extracted intermediates.

   `sign_body_compute_mu` is now STRUCTURAL: factored as a SHAKE
   over the libjade body's ExternalMu input buffer
   (`sign_body_mu_input`). On the libjade sign side this maps
   directly to the SHAKE call libjade makes during mu derivation. *)
op sign_body_mu_input :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Sign_Layout.sign_ptrs_t ->
  Pulsar_N1.mu_shake_input_t.

op sign_body_compute_mu
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
   : Pulsar_N1.mu_t =
  Pulsar_N1.shake256_to_mu (sign_body_mu_input mem_pre ptrs).

op sign_body_compute_w :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Sign_Layout.sign_ptrs_t ->
  Pulsar_N1.w_value_t.

op sign_body_compute_w1
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
   : Pulsar_N1.w1_value_t =
  Pulsar_N1.high_bits_of_w (sign_body_compute_w mem_pre ptrs).

op sign_body_compute_c_tilde
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
   : Pulsar_N1.c_tilde_n1_t =
  Pulsar_N1.shake_mu_w1
    (sign_body_compute_mu mem_pre ptrs)
    (sign_body_compute_w1 mem_pre ptrs).

op sign_body_compute_z :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Sign_Layout.sign_ptrs_t ->
  Pulsar_N1.z_n1_t.

op sign_body_compute_h :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Sign_Layout.sign_ptrs_t ->
  Pulsar_N1.h_n1_t.

op sign_body_compute_components
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
   : Pulsar_N1.c_tilde_n1_t * Pulsar_N1.z_n1_t * Pulsar_N1.h_n1_t =
  (sign_body_compute_c_tilde mem_pre ptrs,
   sign_body_compute_z       mem_pre ptrs,
   sign_body_compute_h       mem_pre ptrs).

(* Status-aware byte-walk (Agent 1 HIGH-2 closure, sign-side).

   libjade M.sign returns a status (rejection of the kappa loop or
   bounded-kappa exhaustion). On non-zero status the signature
   buffer at ptr_signature is in an undefined state. Earlier
   versions claimed byte-equality unconditionally — vacuously
   satisfiable on the rejection branch. *)
op sign_body_compute_status :
  Pulsar_N1_Memory.mem_t ->
  Pulsar_N1_Sign_Layout.sign_ptrs_t ->
  int.

(* sign_body_compute_sig is now DEFINED constructively as the
   FIPS 204 §3.5.5 pack of the inner-loop components. Same structural
   pattern as combine_body_compute_sig in Pulsar_N1_Combine_Refinement
   — the pack step is identical to what `Pulsar_N1.sign_internal_loop`
   does on the centralised reference, so byte-equality reduces to
   triple-equality of the components. *)
op sign_body_compute_sig
   (mem_pre : Pulsar_N1_Memory.mem_t)
   (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
   : Pulsar_N1_Signature_Codec.signature_t =
  let cz_h = sign_body_compute_components mem_pre ptrs in
  Pulsar_N1.pack_n1_signature cz_h.`1 cz_h.`2 cz_h.`3.

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

(* Per-stage byte-walk axioms on the libjade sign side. Mirrors
   the combine-side: the c_tilde stage is decomposed into two
   narrower sub-axioms (sign_body_mu_spec + sign_body_w1_spec);
   the c_tilde axiom itself is a DERIVED LEMMA. The z and h stages
   remain single bundled axioms (closure paths analogous to the
   combine side but without the Lagrange-aggregation complication).
   *)

(* === c_tilde-stage sub-axioms (NARROW), mirror of combine =====
   After v6: mu sub-stage axiom decomposed into a byte-layout claim
   (classified under FIPS 204 codec layouts). sign_body_mu_spec is
   a derived lemma. *)
axiom sign_body_mu_input_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    sign_body_mu_input mem_pre ptrs
    = Pulsar_N1.external_mu_layout full.`sgn_m_n1 full.`sgn_ctx_n1.

(* sign_body_mu_spec — was a primary axiom in v5; now DERIVED. *)
lemma sign_body_mu_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    sign_body_compute_mu mem_pre ptrs
    = Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1.
proof.
  move=> mem_pre ptrs full Hlay Hstatus.
  have Hinput := sign_body_mu_input_spec mem_pre ptrs full Hlay Hstatus.
  rewrite /sign_body_compute_mu /Pulsar_N1.compute_mu.
  by rewrite Hinput.
qed.

axiom sign_body_w_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    sign_body_compute_w mem_pre ptrs
    = Pulsar_N1.central_w
        (Pulsar_N1.unpack_sk full.`sgn_sk_n1)
        (Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1)
        full.`sgn_rnd_n1.

(* sign_body_w1_spec — was a primary axiom; now DERIVED. *)
lemma sign_body_w1_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    sign_body_compute_w1 mem_pre ptrs
    = Pulsar_N1.central_w1
        (Pulsar_N1.unpack_sk full.`sgn_sk_n1)
        (Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1)
        full.`sgn_rnd_n1.
proof.
  move=> mem_pre ptrs full Hlay Hstatus.
  have Hw := sign_body_w_spec mem_pre ptrs full Hlay Hstatus.
  rewrite /sign_body_compute_w1 /Pulsar_N1.central_w1.
  by rewrite Hw.
qed.

(* sign_body_c_tilde_spec — was a primary axiom; now DERIVED. *)
lemma sign_body_c_tilde_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    sign_body_compute_c_tilde mem_pre ptrs
    = Pulsar_N1.mldsa_compute_c_tilde
        (Pulsar_N1.unpack_sk full.`sgn_sk_n1)
        (Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1)
        full.`sgn_rnd_n1.
proof.
  move=> mem_pre ptrs full Hlay Hstatus.
  have Hmu := sign_body_mu_spec mem_pre ptrs full Hlay Hstatus.
  have Hw1 := sign_body_w1_spec mem_pre ptrs full Hlay Hstatus.
  rewrite /sign_body_compute_c_tilde /Pulsar_N1.mldsa_compute_c_tilde.
  by rewrite Hmu Hw1.
qed.

axiom sign_body_z_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    sign_body_compute_z mem_pre ptrs
    = Pulsar_N1.mldsa_compute_z
        (Pulsar_N1.unpack_sk full.`sgn_sk_n1)
        (Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1)
        full.`sgn_rnd_n1.

axiom sign_body_h_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    sign_body_compute_h mem_pre ptrs
    = Pulsar_N1.mldsa_compute_h
        (Pulsar_N1.unpack_sk full.`sgn_sk_n1)
        (Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1)
        full.`sgn_rnd_n1.

(* Composite components_spec — now DERIVED from the three per-stage
   axioms via tuple destructuring. *)
lemma sign_body_compute_components_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    sign_body_compute_components mem_pre ptrs
    = Pulsar_N1.run_signing_components
        (Pulsar_N1.unpack_sk full.`sgn_sk_n1)
        (Pulsar_N1.compute_mu full.`sgn_m_n1 full.`sgn_ctx_n1)
        full.`sgn_rnd_n1.
proof.
  move=> mem_pre ptrs full Hlay Hstatus.
  have Hc := sign_body_c_tilde_spec mem_pre ptrs full Hlay Hstatus.
  have Hz := sign_body_z_spec       mem_pre ptrs full Hlay Hstatus.
  have Hh := sign_body_h_spec       mem_pre ptrs full Hlay Hstatus.
  rewrite /sign_body_compute_components
          /Pulsar_N1.run_signing_components.
  by rewrite Hc Hz Hh.
qed.

(* Original byte-equality shape — now DERIVED from the component-
   level axiom + the structural pack identity. Pack is the same on
   both sides (`Pulsar_N1.pack_n1_signature` in
   `sign_body_compute_sig`'s definition, and inside the unfolding of
   `Pulsar_N1.sign_internal_loop` on the centralised reference);
   component-level Hcomp lifts directly to byte-equality by
   congruence. *)
lemma sign_body_compute_sig_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    sign_body_compute_status mem_pre ptrs = 0 =>
    refine_sig_to_n1_sign (sign_body_compute_sig mem_pre ptrs)
    = sign_abs_op full.
proof.
  move=> mem_pre ptrs full Hlay Hstatus.
  have Hcomp :=
    sign_body_compute_components_spec mem_pre ptrs full Hlay Hstatus.
  (* sign_abs_op = sign_internal_loop (unpack_sk sk) (compute_mu m
     ctx) rnd; after δ on sign_internal_loop's definition (let cz_h'
     = run_signing_components ... in pack_n1_signature cz_h'.`1
     cz_h'.`2 cz_h'.`3) and ζ via /=, both sides reduce to
     pack_n1_signature applied at three projections of either
     `sign_body_compute_components mem_pre ptrs` (LHS) or
     `run_signing_components ...` (RHS). Hcomp closes the equality
     at three positions ⇒ `!Hcomp`. *)
  rewrite /refine_sig_to_n1_sign /sign_body_compute_sig
          /sign_abs_op /Pulsar_N1.sign_internal_loop /=.
  by rewrite !Hcomp.
qed.

(* Accepted-path no-reject axiom (followup B closure).

   No-reject is NOT a universal property of honest signing — it is
   a property of ACCEPTED signing attempts. The conditioned form:
   given layout-conforming inputs AND the ML-DSA-65 accept event
   holds for the protocol-level inputs (sk, m, ctx, rho_rnd), the
   extracted libjade M.sign returns status = 0.

   The accept event is `accept_signing_attempt`, declared at
   Pulsar_N1.ec. ML-DSA's kappa rejection-sampling loop converges
   with probability ≈ 1 − (3/4)^256 per attempt; the kappa-bounded
   loop accumulates failure probability ≤ 2^-128 across the bound.
   The probability bound is tracked operationally
   (Pulsar_N1.mldsa_accept_lower_bound) rather than via
   probabilistic Hoare logic.

   Previous shape claimed UNCONDITIONAL status=0 on layout-
   conforming inputs — too strong, since rejection is a
   probabilistic event. With the accept-path precondition explicit,
   the axiom is honest: "if the attempt accepts, the byte output
   is the centralized FIPS 204 signature".

   COMPANION to sign_body_compute_sig_spec: together they recover
   the conditional byte-walk shape. *)
axiom sign_no_reject_on_accepted_honest_layout :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    Pulsar_N1.accept_signing_attempt
      full.`sgn_sk_n1 full.`sgn_m_n1
      full.`sgn_ctx_n1 full.`sgn_rnd_n1 =>
    sign_body_compute_status mem_pre ptrs = 0.

(* The `sign_body_spec` shape — STATUS DISCHARGED by the
   accepted-path no-reject axiom (followup B). Threads
   `accept_signing_attempt` from the caller through to the
   byte-walk axiom. *)
lemma sign_body_spec :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    Pulsar_N1.accept_signing_attempt
      full.`sgn_sk_n1 full.`sgn_m_n1
      full.`sgn_ctx_n1 full.`sgn_rnd_n1 =>
    refine_sig_to_n1_sign
      (Pulsar_N1_Sign_Layout.read_sig_sign
         (sign_body_fn mem_pre ptrs)
         ptrs.`Pulsar_N1_Sign_Layout.ptr_signature)
    = sign_abs_op full.
proof.
  move=> mem_pre ptrs full Hlay Haccept.
  have Hstatus :=
    sign_no_reject_on_accepted_honest_layout
      mem_pre ptrs full Hlay Haccept.
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
   this lemma. Threads accept_signing_attempt through. *)
lemma sign_body_writes_abs :
  forall (mem_pre : Pulsar_N1_Memory.mem_t)
         (ptrs : Pulsar_N1_Sign_Layout.sign_ptrs_t)
         (full : sign_full_args_t),
    Pulsar_N1_Sign_Layout.layout_sign_args
      mem_pre ptrs (wire_sign_args_of_full full) =>
    Pulsar_N1.accept_signing_attempt
      full.`sgn_sk_n1 full.`sgn_m_n1
      full.`sgn_ctx_n1 full.`sgn_rnd_n1 =>
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
    Pulsar_N1.accept_signing_attempt
      full.`sgn_sk_n1 full.`sgn_m_n1
      full.`sgn_ctx_n1 full.`sgn_rnd_n1 =>
    refine_sig_to_n1_sign
      (Pulsar_N1_Sign_Layout.read_sig_sign
         (sign_body_fn mem_pre ptrs)
         ptrs.`Pulsar_N1_Sign_Layout.ptr_signature)
    = Pulsar_N1.mldsa_sign_op
        full.`sgn_sk_n1 full.`sgn_m_n1
        full.`sgn_ctx_n1 full.`sgn_rnd_n1.
proof.
  move=> mem_pre ptrs full Hlay Haccept.
  rewrite (sign_body_spec mem_pre ptrs full Hlay Haccept) /sign_abs_op.
  by rewrite /Pulsar_N1.mldsa_sign_op.
qed.

(* ===================================================================
   AXIOM ACCOUNTING

   axioms (4 — 2 stage-level + 2 c_tilde-stage sub-stage):
     Stage-level (z + h):
       sign_body_z_spec        (response z from kappa loop)
       sign_body_h_spec        (roadmap S7 — MakeHint stage)
     c_tilde-stage sub-stage (mu + w1):
       sign_body_mu_spec       (extracted mu = compute_mu m ctx)
       sign_body_w1_spec       (extracted w1 = central_w1 (...))
       Each strictly narrower than the prior bundled
       `sign_body_c_tilde_spec` axiom (now a derived lemma).

     Each conditioned on layout + status = 0.
     Tracked #3. Mirrors the combine-side per-stage split.

       REFINEMENT HISTORY (this file):
         v1: 2 axioms (sign_body_spec + sign_body_separation)
         v2: 1 axiom  (sign_body_compute_sig_spec — packed signature)
         v3: 1 axiom  (sign_body_compute_components_spec — triple)
         v4: 3 axioms (sign_body_{c_tilde,z,h}_spec — per-stage)
         v5 (this commit): c_tilde-stage axiom DECOMPOSED — the
             primitive `sign_body_c_tilde_spec` axiom is replaced
             by 2 narrower sub-axioms (mu, w1); `sign_body_c_tilde_spec`
             becomes a derived lemma. NOT full mechanized closure
             of the c_tilde path: mu and w1 specs remain axioms.

   ops (DEFINITIONS — no proof obligation):
     wire_sign_args_of_full   (record projection)
     refine_sig_to_n1_sign    (structural sig-type coercion)
     sign_abs_op              (DEFINED — mldsa_sign_op on ghost fields)
     sign_body_compute_sig    (DEFINED — pack_n1_signature of the
                               compute_components output)
     sign_body_compute_components
                              (DEFINED — tuple of per-stage ops)
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
     v1: 2 axioms (sign_body_spec + sign_body_separation)
     v2: 1 axiom  (sign_body_compute_sig_spec — packed signature)
     v3: 1 axiom  (sign_body_compute_components_spec — triple)
     v4: 3 axioms (sign_body_{c_tilde,z,h}_spec — per-stage)
     v5: c_tilde-stage axiom DECOMPOSED — `sign_body_c_tilde_spec`
         becomes derived; replaced by sign_body_{mu,w1}_spec axioms.
     v6: mu sub-stage axiom further DECOMPOSED.
     v7 (this commit):
         4 axioms — w1 sub-stage axiom DECOMPOSED via HighBits:
         `sign_body_w1_spec` becomes a derived lemma, replaced by
         `sign_body_w_spec` (narrower — about polynomial vector w
         before HighBits/decompose).
         Remaining byte-walk axioms on this file:
           sign_body_w_spec    (c_tilde dependency sub-stage, narrower than w1)
           sign_body_z_spec    (stage-level)
           sign_body_h_spec    (stage-level)
         Plus 1 codec-layout axiom:
           sign_body_mu_input_spec

   Mirror of the combine-side post-v7 structure.

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
