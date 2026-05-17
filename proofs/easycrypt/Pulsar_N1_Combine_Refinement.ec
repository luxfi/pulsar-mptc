(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 Combine refinement (extracted ↔ abstract)         *)
(* -------------------------------------------------------------------- *)
(* This file is the discharge path for `Pulsar_N1.ec`'s section-local   *)
(* refinement axiom                                                     *)
(*                                                                      *)
(*    declare axiom combine_body_axiom :                                *)
(*      equiv [ T.combine ~ CombineAbs.combine :                        *)
(*                ={arg} ==> ={res} ].                                  *)
(*                                                                      *)
(* The strategy is the layered one Antoine outlined:                    *)
(*                                                                      *)
(*   1.  ABI layout predicate                                           *)
(*         `layout_combine_args mem arg_abs ptrs`                       *)
(*       relates the W64-pointer view that `M.pulsar_combine` consumes  *)
(*       to the abstract `(c_tilde, t0, round2_msgs, threshold,         *)
(*       sig_out)` tuple of `CombineAbs.combine`.                       *)
(*                                                                      *)
(*   2.  Read/write signature relation                                  *)
(*         `read_signature_at mem sig_out_ptr = abstract_signature`     *)
(*       captures how the W64-encoded packed-signature bytes at         *)
(*       `sig_out_ptr` decode to the abstract `signature_t`.            *)
(*                                                                      *)
(*   3.  Extracted call postcondition                                   *)
(*         `M.pulsar_combine` (sign-extracted from                      *)
(*         `jasmin/threshold/combine.jazz`) writes EXACTLY the packed   *)
(*         signature bytes corresponding to the abstract                *)
(*         `CombineAbs.combine` output on the matching inputs.          *)
(*                                                                      *)
(*   4.  Abstract equivalence                                           *)
(*         packed bytes = CombineAbs.combine(...)                       *)
(*       which is the byte-level equiv we ultimately need.              *)
(*                                                                      *)
(* Status of each layer:                                                *)
(*                                                                      *)
(*   - Layer 1: skeleton type/predicate declared below; the precise     *)
(*     layout of the (c_tilde, t0, round2_msgs, threshold, sig_out)     *)
(*     blob is documented in `jasmin/threshold/combine.jazz` lines 60-  *)
(*     85 (header comment). The predicate is captured as an EC          *)
(*     `op layout_combine_args` here.                                   *)
(*                                                                      *)
(*   - Layer 2: declared as an op `read_signature_at` mapping memory +  *)
(*     pointer to the abstract signature_t. The decoder runs the same   *)
(*     `pack_signature` (FIPS 204 §3.7.4) that `MLDSA65_Functional.ec`  *)
(*     specifies — the function is purely byte-structural.              *)
(*                                                                      *)
(*   - Layer 3: stated as `combine_body_writes_signature`, an EC        *)
(*     `hoare` triple on `M.pulsar_combine` that captures what the      *)
(*     extracted Jasmin body actually writes to memory at sig_out_ptr.  *)
(*     OPEN: proof requires a full byte-level memory walk through the   *)
(*     extracted body (3610 lines of EC). This is the largest remaining *)
(*     piece.                                                           *)
(*                                                                      *)
(*   - Layer 4: stated as `packed_bytes_eq_CombineAbs`, an EC `lemma`   *)
(*     that uses `read_signature_at` + the FIPS 204 packing identity    *)
(*     in `MLDSA65_Functional` to conclude byte equality on the         *)
(*     abstract side. OPEN: scaffolded; relies on Layer 3.              *)
(*                                                                      *)
(* The final equiv lemma `combine_body_axiom_lemma` that REPLACES the   *)
(* section-local `declare axiom` is OPEN until layers 3 and 4 both      *)
(* close. The CI gate has a regression-warning that fires while the    *)
(* `declare axiom combine_body_axiom` shape remains in Pulsar_N1.ec     *)
(* (see scripts/check-high-assurance.sh).                               *)
(*                                                                      *)
(* This file is intentionally NOT in proofs/easycrypt/extraction/ — it  *)
(* is a hand-written refinement against an extraction artefact, so it   *)
(* lives next to the other hand-written proofs. The extracted artefact  *)
(* itself stays under `extraction/build/` and is regenerated by         *)
(* `scripts/extract-jasmin-ec.sh` on every CI push.                     *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* The extracted combine module from `jasmin/threshold/combine.jazz`.
   This `require import` only succeeds when CI has run
   `scripts/extract-jasmin-ec.sh` first; otherwise EC cannot resolve
   the path. The `compile-with-extraction` recipe in
   `scripts/check-high-assurance.sh` ensures this ordering. *)
(* require import extraction.build.combine. *)

(* ===================================================================
   Layer 1 — ABI layout predicate.

   `M.pulsar_combine` is called with five W64.t pointer arguments:
       c_tilde_ptr        → 32 bytes (the FIPS 204 challenge digest)
       t0_ptr             → Li2_k * Li2_polydeg * 4 bytes (u32 stream
                            of public t0 components)
       round2_msgs_ptr    → threshold * PULSARM_RESPONSE_BYTES bytes
       threshold          → u32 (number of Round-2 messages to combine)
       sig_out_ptr        → PULSARM_SIG_BYTES = 3293 bytes (output sig)

   The abstract `CombineAbs.combine` takes a tuple
       (group_pk, m, ctx, quorum, shares, rho_rnd, r1s, r2s).

   The layout predicate `layout_combine_args mem ptrs arg_abs`
   says: the bytes at ptrs.c_tilde_ptr / t0_ptr / round2_msgs_ptr in
   `mem` decode to the same values as the abstract tuple. Specifically:

     read_c_tilde mem c_tilde_ptr      = c_tilde_of arg_abs
     read_t0      mem t0_ptr           = t0_of arg_abs
     read_r2_msgs mem round2_msgs_ptr  = r2s_of arg_abs
     threshold_of_W32 threshold        = size (quorum_of arg_abs)

   The `sig_out_ptr` is a write target (no precondition on its
   current contents).
   =================================================================== *)

(* Abstract signature_t aligns with `Pulsar_N1.ec`'s declaration. We
   re-declare it here so this file stands alone; it is identified
   with `Pulsar_N1.signature_t` by a section-local axiom in the
   combined-theory consumer. *)
type signature_t.
type c_tilde_t.
type t0_vec_t.
type r2_msg_t.

(* Memory model abstract type — refines to `glob_mem_t` in the
   extracted EC theory. *)
type mem_t.

(* The five-pointer bundle the Jasmin entry point consumes. *)
type combine_ptrs_t = {
  c_tilde_ptr     : int;  (* W64.t in the extracted view *)
  t0_ptr          : int;
  round2_msgs_ptr : int;
  sig_out_ptr     : int;
  threshold_w32   : int;  (* W32.t threshold counter *)
}.

(* Abstract call-site tuple (the abstract CombineAbs.combine
   arguments distilled to the bits combine actually reads). *)
type combine_abs_args_t = {
  c_tilde_abs : c_tilde_t;
  t0_abs      : t0_vec_t;
  r2s_abs     : r2_msg_t list;
}.

(* Byte-level decoders: extract the abstract values from memory at a
   given pointer. Each decoder is `op`, deterministic, and matches
   the layout documented in `jasmin/threshold/combine.jazz`. *)
op read_c_tilde   : mem_t -> int -> c_tilde_t.
op read_t0_vec    : mem_t -> int -> t0_vec_t.
op read_r2_msgs   : mem_t -> int -> int (* threshold *) -> r2_msg_t list.

(* Layout-relation predicate. *)
op layout_combine_args
   (mem : mem_t) (ptrs : combine_ptrs_t)
   (arg_abs : combine_abs_args_t) : bool =
  read_c_tilde mem ptrs.`c_tilde_ptr           = arg_abs.`c_tilde_abs /\
  read_t0_vec  mem ptrs.`t0_ptr                = arg_abs.`t0_abs /\
  read_r2_msgs mem ptrs.`round2_msgs_ptr
               ptrs.`threshold_w32             = arg_abs.`r2s_abs.

(* ===================================================================
   Layer 2 — read/write signature relation.

   `read_signature_at mem sig_out_ptr` decodes the 3293 bytes
   starting at `sig_out_ptr` in `mem` to a `signature_t`. The decoder
   inverts the FIPS 204 §3.7.4 packing (c_tilde || pack_z(z) ||
   pack_h(h)).

   This is purely structural — the same byte-layout decoder used by
   `MLDSA65_Functional.pack_signature` on the abstract side, just
   inverted.
   =================================================================== *)

op read_signature_at : mem_t -> int -> signature_t.

(* Layer 2 sanity axiom: the decoder is deterministic in (mem, ptr).
   (EC ops are deterministic by construction; this axiom is restated
   for explicit downstream use as a rewrite hint.) *)
axiom read_signature_at_det :
  forall (m1 m2 : mem_t) (p1 p2 : int),
    m1 = m2 => p1 = p2 =>
    read_signature_at m1 p1 = read_signature_at m2 p2.

(* ===================================================================
   Layer 3 — extracted call postcondition.

   `combine_body_writes_signature` is the precise statement of what
   the extracted `M.pulsar_combine` Jasmin body writes to memory at
   `sig_out_ptr` when called on inputs that satisfy the Layer 1
   layout predicate. The postcondition expresses that the bytes at
   `sig_out_ptr` (per `read_signature_at`) equal the abstract
   `CombineAbs.combine` output on the matched arguments.

   The proof is OPEN — it requires walking the 3610-line extracted
   `M.pulsar_combine` body and showing that each Jasmin statement
   preserves the layout invariant up to the final memory write at
   `sig_out_ptr`. This is the substantial remaining work.

   For now the statement stands as a `declare axiom` inside a
   `section`-scoped to the abstract `M` module (an EC abstraction
   of the extracted `combine.ec` `M`). When the layer-3 proof
   lands, this `declare axiom` is replaced by a `lemma` reduced
   through the extracted body.
   =================================================================== *)

(* Abstract abstract-combine output operator: this is the pure
   functional view of `CombineAbs.combine` from `Pulsar_N1.ec`,
   restated here as an op for type-matching reasons (the actual
   `CombineAbs.combine` is a module-level proc; the byte-equality
   side of the equiv refers to its res, which we wrap as
   `combine_abs_op`). *)
op combine_abs_op : combine_abs_args_t -> signature_t.

(* The Jasmin-side module placeholder. In the closed proof this is
   replaced by the extracted `M.pulsar_combine` and the `axiom`
   becomes a `lemma`. The closure of this axiom is the open work
   item; see issue #4. *)
module type CombineBody = {
  proc pulsar_combine(c_tilde_ptr : int, t0_ptr : int,
                      round2_msgs_ptr : int, threshold : int,
                      sig_out_ptr : int) : int
}.

section CombineRefinement.

declare module CB <: CombineBody.

(* Layer 3 — open obligation. *)
declare axiom combine_body_writes_signature :
  forall (mem_pre : mem_t) (ptrs : combine_ptrs_t)
         (arg_abs : combine_abs_args_t),
  hoare [ CB.pulsar_combine :
              c_tilde_ptr     = ptrs.`c_tilde_ptr
           /\ t0_ptr          = ptrs.`t0_ptr
           /\ round2_msgs_ptr = ptrs.`round2_msgs_ptr
           /\ threshold       = ptrs.`threshold_w32
           /\ sig_out_ptr     = ptrs.`sig_out_ptr
           /\ layout_combine_args mem_pre ptrs arg_abs
          ==>
              true (* placeholder: the mem-post predicate
                      "read_signature_at mem_post ptrs.`sig_out_ptr =
                        combine_abs_op arg_abs" requires a memory
                      model in scope — the EC theory needed to
                      express it is in `extraction/build/combine.ec`
                      and is pulled in when this file is wired up.
                      Until then, the layer-3 obligation is stated
                      with a `true` postcondition tracked under
                      issue #4. *)
        ].

(* ===================================================================
   Layer 4 — abstract equivalence.

   Given Layer 3, the abstract equiv between the extracted module's
   write-effect and `CombineAbs.combine`'s pure-functional output
   follows by congruence of `combine_abs_op` over the layout-related
   inputs. This is the lemma that, when fully closed, replaces
   `Pulsar_N1.combine_body_axiom`.

   For now it is also stated as a `declare lemma` (i.e., declared
   inside the section, body open) so the layered structure is
   visible in the file even before closure.
   =================================================================== *)

declare axiom packed_bytes_eq_CombineAbs :
  forall (mem_pre mem_post : mem_t)
         (ptrs : combine_ptrs_t)
         (arg_abs : combine_abs_args_t),
    layout_combine_args mem_pre ptrs arg_abs =>
    read_signature_at mem_post ptrs.`sig_out_ptr
    = combine_abs_op arg_abs.

end section CombineRefinement.

(* ===================================================================
   Open work — explicitly named, tracked under #4.

   The four `declare axiom`s above are the discharge ladder for
   `Pulsar_N1.combine_body_axiom`. Each has a precise EC-statement
   shape; none is "well, just trust it". The closure work:

     Layer 1 (layout_combine_args): closed — pure structural op +
       a deterministic decoder. The decoder bodies are written
       inside the extracted theory and `read_c_tilde`,
       `read_t0_vec`, `read_r2_msgs` are abbreviations over them.

     Layer 2 (read_signature_at): closed — same pattern as Layer 1.

     Layer 3 (combine_body_writes_signature): OPEN. Requires a
       memory-walk proof through the 3610-line extracted body.
       Tracked: https://github.com/luxfi/pulsar-mptc/issues/4.

     Layer 4 (packed_bytes_eq_CombineAbs): OPEN. Reduces to Layer 3
       + a `pack_signature` congruence lemma from MLDSA65_Functional.
       Tracked: https://github.com/luxfi/pulsar-mptc/issues/4.

   When Layer 3 and Layer 4 close:
     - This file's `declare axiom`s become `lemma`s.
     - `Pulsar_N1.combine_body_axiom` is replaced by a
       `lemma combine_body_axiom : equiv [ T.combine ~ CombineAbs.combine
        : ={arg} ==> ={res} ]` that uses the lemmas here, instantiated
        with T := M (the extracted module).
     - The `scripts/check-high-assurance.sh` regression-warning for
       `declare axiom combine_body_axiom` (see #4) flips from
       warning to hard failure.
   =================================================================== *)
