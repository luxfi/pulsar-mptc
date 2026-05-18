(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 Sign concrete memory layout                       *)
(* -------------------------------------------------------------------- *)
(* Sign-side analogue of `Pulsar_N1_Combine_Layout.ec`.                 *)
(*                                                                      *)
(* The libjade ML-DSA-65 single-party sign entry-point ABI (extracted   *)
(* at extraction/build/sign.ec line 3603) is:                           *)
(*                                                                      *)
(*   proc sign(ptr_signature : W64.t, ptr_m : W64.t,                    *)
(*             m_len : W64.t, ptr_sk : W64.t) : W64.t                   *)
(*                                                                      *)
(* with the buffers:                                                    *)
(*   ptr_sk        → 4032 bytes (FIPS 204 §3.5.4 sk packing:            *)
(*                    rho || K || tr || s1 || s2 || t0)                 *)
(*   ptr_m         → m_len bytes (the message)                          *)
(*   ptr_signature → 3293 bytes (FIPS 204 §3.5.5 signature packing:     *)
(*                    c_tilde || pack_z || pack_h)                      *)
(*                                                                      *)
(* This file pins those buffers to a concrete byte-level memory model   *)
(* (REUSING the memory model + proved memory-frame lemmas from          *)
(* `Pulsar_N1_Combine_Layout.ec`) and proves that the concrete encoder  *)
(* `encode_sign_args` produces a layout-conforming memory state +       *)
(* pointer bundle on the corresponding abstract args.                   *)
(*                                                                      *)
(* Trust-boundary delta vs the prior sign refinement file alone:        *)
(*   - `read_sk_at`, `read_msg_at` are no longer abstract ops; they are *)
(*     concrete EC definitions (FIPS 204 §3.5.4 / message bytes).       *)
(*   - The layout-correctness facts `encode_layout_sk`,                 *)
(*     `encode_layout_msg`, and the aggregate                           *)
(*     `encode_sign_args_layout` are PROVED lemmas instead of axioms.   *)
(*   - The encode/decode round-trip + length axioms for `share_t`      *)
(*     and `message_t` are small per-type structural identities (same  *)
(*     shape as the combine-side per-type axioms).                      *)
(*                                                                      *)
(* What this file does NOT yet provide:                                 *)
(*   - The `sign_body_compute_sig_spec` byte-walk; that still requires  *)
(*     walking the extracted libjade `M.sign` body and stays as an     *)
(*     axiom in `Pulsar_N1_Sign_Refinement.ec` (tracked #3).            *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv SmtMap.

(* Decomplected imports: no longer pulls in combine-specific encoders
   just to reach the byte-memory model or the FIPS 204 signature
   codec. Memory primitives live in Pulsar_N1_Memory; the FIPS 204
   signature_t + read_sig_at / write_sig_at + their proved frame
   lemmas live in Pulsar_N1_Signature_Codec. *)
require import Pulsar_N1_Memory.
require import Pulsar_N1_Signature_Codec.

(* ===================================================================
   Sign ABI size constants.

   The libjade single-party sign ABI (per
   jasmin/ml-dsa-65/libjade/oldsrc-should-delete/crypto_sign/dilithium/
   dilithium3/amd64/ref/sign.jazz and the EC extraction at line 3603):

     ptr_sk        →  4032 bytes  (FIPS 204 §3.5.4 sk packing:
                                   rho 32 || K 32 || tr 64 ||
                                   s1 4*96 || s2 6*96 || t0 6*416)
     ptr_signature →  3293 bytes  (FIPS 204 §3.5.5 sig packing:
                                   c_tilde 32 || z 4*640 || h 83)

   `sig_len_sign` mirrors `Pulsar_N1_Signature_Codec.sig_len`
   (both are the FIPS 204 §3.5.5 ML-DSA-65 signature length).
   =================================================================== *)

op sk_len       : int = 4032.
op sig_len_sign : int = 3293.        (* = sig_len from Signature_Codec *)

(* ===================================================================
   Sign-side abstract input/output types.

   These are LOCAL abstract types parallel to the combine layout's
   per-value types. They are deliberately NOT shared with
   `Pulsar_N1_Sign_Refinement.ec`'s `share_t` / `message_t` so that
   this file can be re-used without coupling its abstract namespace
   to the refinement scaffold's namespace; the wrapper bridge
   composes the two (via op-level `n1_*_to_refine`-style adapters).
   =================================================================== *)

type share_t.
type message_t.

(* Byte encoders/decoders for the per-value sign-side types. Their
   concrete byte layouts are defined by FIPS 204 §3.5.4 (sk packing)
   + the trivial message-byte identity. Here we just need their
   existence + round-trip + length as small axioms. *)

op encode_sk  : share_t   -> int list.
op decode_sk  : int list  -> share_t.
op encode_msg : message_t -> int list.
op decode_msg : int list  -> message_t.

axiom encode_decode_sk  (x : share_t)   : decode_sk  (encode_sk  x) = x.
axiom encode_decode_msg (x : message_t) : decode_msg (encode_msg x) = x.

axiom encode_sk_len  (x : share_t)   : size (encode_sk  x) = sk_len.

(* The message length is data-dependent (set by the caller's `m_len`
   argument to the libjade sign entry point); we surface that as an
   op-level identity rather than a fixed constant. The encoder for
   `encode_msg` MUST produce a byte list whose length matches the
   caller-supplied `m_len_val`. *)
op msg_len : message_t -> int.

axiom encode_msg_len (x : message_t) : size (encode_msg x) = msg_len x.
axiom msg_len_ge0    (x : message_t) : 0 <= msg_len x.

(* ===================================================================
   Sign ABI pointer bundle.

   Mirrors the libjade entry-point's four word-arguments. The
   `m_len` field is the data-dependent message-byte count from the
   caller; `ptr_sk` / `ptr_m` / `ptr_signature` are byte addresses.
   =================================================================== *)

type sign_ptrs_t = {
  ptr_signature : int;
  ptr_m         : int;
  m_len         : int;
  ptr_sk        : int;
}.

(* ===================================================================
   Concrete read definitions.

   `read_sk` and `read_msg` decode the bytes at the given pointer
   ranges. `read_sig_sign` reads the signature output buffer; it
   uses the COMBINE layout's `signature_t` / `decode_signature` so
   the two sides agree on the FIPS 204 §3.5.5 sig packing.
   =================================================================== *)

op read_sk (m : mem_t) (p : int) : share_t =
  decode_sk (load_bytes m p sk_len).

op read_msg (m : mem_t) (p : int) (l : int) : message_t =
  decode_msg (load_bytes m p l).

(* Thin sign-side aliases over Pulsar_N1_Signature_Codec.read_sig_at
   / write_sig_at. Kept for backward compatibility with the
   Refinement-file consumers; sig_len_sign = sig_len by construction. *)
op read_sig_sign (m : mem_t) (p : int) : signature_t = read_sig_at m p.

op write_sig_sign (m : mem_t) (p : int) (s : signature_t) : mem_t =
  write_sig_at m p s.

(* The layout predicate: memory reads at the given pointers decode
   to the abstract args, and the pointer bundle's `m_len` field
   matches the actual message length. *)

type sign_abs_args_t = {
  sk_abs  : share_t;
  m_abs   : message_t;
}.

(* Pointer-disjointness predicate (Agent 1 C2 — sign side).
   The three sign-side byte buffers (ptr_signature, ptr_m, ptr_sk)
   must not overlap, and the signature buffer must have room for
   sig_len_sign bytes. Without this conjunct an adversarial layout
   could alias buffers (e.g. ptr_signature overlapping ptr_sk) and
   the byte-walk axiom would be discharged on a memory state where
   libjade M.sign would have clobbered the sk it just read. *)
op sign_pointers_well_separated (ptrs : sign_ptrs_t) : bool =
  let p_s = ptrs.`ptr_signature in
  let p_m = ptrs.`ptr_m in
  let p_k = ptrs.`ptr_sk in
  let m_l = ptrs.`m_len in
     0 <= p_s
  /\ p_s + sig_len_sign <= p_m
  /\ p_m + m_l <= p_k
  /\ 0 <= m_l.

op layout_sign_args
   (mem : mem_t) (ptrs : sign_ptrs_t)
   (arg_abs : sign_abs_args_t) : bool =
     read_sk  mem ptrs.`ptr_sk                       = arg_abs.`sk_abs
  /\ read_msg mem ptrs.`ptr_m ptrs.`m_len            = arg_abs.`m_abs
  /\ ptrs.`m_len = msg_len arg_abs.`m_abs
  /\ sign_pointers_well_separated ptrs.

(* ===================================================================
   Concrete encoder: lay out the abstract args into memory at fresh,
   trivially non-overlapping pointers.

   Pointer layout:
     ptr_signature at 0                                 (sig_len_sign bytes,
                                                         WRITTEN BY M.sign,
                                                         starts as zeros)
     ptr_m         at sig_len_sign                      (m_len_val bytes)
     ptr_sk        at sig_len_sign + m_len_val          (sk_len bytes)

   The signature buffer is zeroed at encode time; the extracted
   `M.sign` overwrites it. `encode_sign_args` only writes the sk
   + message bytes (the inputs) — that's all the layout predicate
   constrains.
   =================================================================== *)

op encode_sign_args (sk : share_t) (m : message_t) (m_len_val : int)
   : mem_t * sign_ptrs_t =
  let p_sig = 0 in
  let p_m   = sig_len_sign in
  let p_sk  = sig_len_sign + m_len_val in
  let m0 = fun (_ : int) => 0 in
  let m1 = store_bytes m0 p_m  (encode_msg m) in
  let m2 = store_bytes m1 p_sk (encode_sk  sk) in
  let ptrs = {| ptr_signature = p_sig;
                ptr_m         = p_m;
                m_len         = m_len_val;
                ptr_sk        = p_sk |} in
  (m2, ptrs).

(* ===================================================================
   Structural lemmas — all PROVED, no axioms.

   The two conjuncts of `layout_sign_args` are each provable
   directly from `store_bytes_load_bytes` + `store_bytes_disjoint`
   + the per-type encode/decode round-trip:

     - encode_layout_sk  : sk-byte read from encoded memory equals
                           the original abstract sk.
     - encode_layout_msg : message-byte read from encoded memory
                           equals the original abstract message.

   The aggregate `encode_sign_args_layout` composes them. The
   `m_len` conjunct is definitional (encoder sets it from the
   caller-supplied argument).
   =================================================================== *)

(* The sk pointer is `sig_len_sign + m_len_val`, with `sk_len`
   bytes written there as the LAST store_bytes call. Reading
   `sk_len` bytes at that address therefore returns `encode_sk sk`
   directly via `store_bytes_load_bytes`. Decoding inverts via
   `encode_decode_sk`. *)
lemma encode_layout_sk
      (sk : share_t) (m : message_t) (m_len_val : int) :
  0 <= m_len_val =>
  size (encode_msg m) = m_len_val =>
  read_sk (encode_sign_args sk m m_len_val).`1
          (encode_sign_args sk m m_len_val).`2.`ptr_sk
  = sk.
proof.
  move=> Hml_ge0 Hmsg_len.
  rewrite /read_sk /encode_sign_args /=.
  have Hsk_len : size (encode_sk sk) = sk_len by exact encode_sk_len.
  have ->: sk_len = size (encode_sk sk) by rewrite Hsk_len.
  by rewrite store_bytes_load_bytes encode_decode_sk.
qed.

(* The message pointer is `sig_len_sign`, with `m_len_val` bytes
   written there. The subsequent sk write at
   `sig_len_sign + m_len_val` is disjoint from the message range
   `[sig_len_sign, sig_len_sign + m_len_val)` (since
   m_len_val + 0 = m_len_val and the sk write base is exactly
   sig_len_sign + m_len_val). `load_bytes_after_disjoint_write`
   peels the sk write off, then `store_bytes_load_bytes` gives
   `encode_msg m` directly, which `encode_decode_msg` inverts. *)
lemma encode_layout_msg
      (sk : share_t) (m : message_t) (m_len_val : int) :
  0 <= m_len_val =>
  size (encode_msg m) = m_len_val =>
  read_msg (encode_sign_args sk m m_len_val).`1
           (encode_sign_args sk m m_len_val).`2.`ptr_m
           (encode_sign_args sk m m_len_val).`2.`m_len
  = m.
proof.
  move=> Hml_ge0 Hmsg_len.
  rewrite /read_msg /encode_sign_args /=.
  have Hsk_len : size (encode_sk sk) = sk_len by exact encode_sk_len.
  (* Peel the sk write off the message range. The sk write is at
     base = sig_len_sign + m_len_val with size sk_len. The message
     range is [sig_len_sign, sig_len_sign + m_len_val). They are
     disjoint because (sig_len_sign + m_len_val) is exactly the
     upper bound of the message range and the lower bound of the
     sk write. We use the second branch of the disjointness
     condition: p + L <= q. *)
  have ->:
    load_bytes
      (store_bytes
         (store_bytes (fun _ : int => 0) sig_len_sign (encode_msg m))
         (sig_len_sign + m_len_val) (encode_sk sk))
      sig_len_sign m_len_val
    = load_bytes
        (store_bytes (fun _ : int => 0) sig_len_sign (encode_msg m))
        sig_len_sign m_len_val.
  - apply load_bytes_after_disjoint_write; first by exact Hml_ge0.
    by left.
  (* Now apply store_bytes_load_bytes with the message bytes. *)
  have ->: m_len_val = size (encode_msg m) by rewrite Hmsg_len.
  by rewrite store_bytes_load_bytes encode_decode_msg.
qed.

(* Aggregate encoder-correctness — DERIVED from the two conjuncts
   above + the definitional m_len identity (encoder sets
   ptrs.`m_len := m_len_val by construction, and the precondition
   ties m_len_val := msg_len m).

   This is the sign-side mirror of `encode_combine_args_layout`. *)
lemma encode_sign_args_layout
      (sk : share_t) (m : message_t) :
  layout_sign_args
    (encode_sign_args sk m (msg_len m)).`1
    (encode_sign_args sk m (msg_len m)).`2
    {| sk_abs = sk; m_abs = m |}.
proof.
  rewrite /layout_sign_args.
  have Hml_ge0 : 0 <= msg_len m by exact msg_len_ge0.
  have Hmsg_len : size (encode_msg m) = msg_len m by exact encode_msg_len.
  split.
  - by apply (encode_layout_sk sk m (msg_len m)).
  split.
  - by apply (encode_layout_msg sk m (msg_len m)).
  by rewrite /encode_sign_args /=.
qed.

(* ===================================================================
   Signature-write structural lemmas — mirror the combine layout's
   `read_after_write_signature` and `write_signature_separation` for
   the sign-side output buffer. These are derived directly from the
   reused combine-side memory-model lemmas + `encode_signature_len`.
   =================================================================== *)

lemma read_after_write_sig_sign
      (mem : mem_t) (p : int) (s : signature_t) :
  read_sig_sign (write_sig_sign mem p s) p = s.
proof. rewrite /read_sig_sign /write_sig_sign; exact read_after_write_sig. qed.

lemma write_sig_sign_separation
      (mem : mem_t) (p : int) (s : signature_t) (q : int) :
  q < p \/ p + sig_len_sign <= q =>
  load_byte (write_sig_sign mem p s) q = load_byte mem q.
proof.
  move=> Hdisj.
  rewrite /write_sig_sign.
  apply write_sig_separation.
  (* sig_len_sign and Signature_Codec.sig_len are both 3293 —
     definitionally equal. *)
  by rewrite /sig_len_sign in Hdisj; rewrite /sig_len.
qed.

(* ===================================================================
   AXIOM ACCOUNTING (this file)

   Concrete definitions (no proof obligation):
     sk_len, sig_len_sign,
     sign_ptrs_t, sign_abs_args_t,
     read_sk, read_msg, read_sig_sign, write_sig_sign,
     layout_sign_args, encode_sign_args.

   PROVED lemmas (5, no admit):
     encode_layout_sk
     encode_layout_msg
     encode_sign_args_layout    (composes the 2 sub-claims)
     read_after_write_sig_sign
     write_sig_sign_separation

   Axioms (5, all small per-type structural identities):
     - 2 sk encode/decode round-trip + length:
         encode_decode_sk, encode_sk_len
     - 2 message encode/decode round-trip + length:
         encode_decode_msg, encode_msg_len
     - 1 message-length non-negativity:
         msg_len_ge0

   Memory-model facts (REUSED from Pulsar_N1_Combine_Layout, all
   already PROVED lemmas there):
     store_bytes_load_bytes
     store_bytes_disjoint
     load_bytes_after_disjoint_write
     plus the combine-side signature encode/decode + length axioms
     (encode_decode_signature, encode_signature_len) which we reuse
     for read_after_write_sig_sign / write_sig_sign_separation.

   Phase reductions:
     Phase 1 (this file): both encode-layout conjuncts proved as
     lemmas; aggregate `encode_sign_args_layout` is derived (no
     conjunct axioms). The sign-side mirror of the combine layout's
     "encode_*_layout becomes a lemma" reduction is now complete.

   This file: 5 axioms (all per-type encode/decode identities),
              5 proved lemmas, 0 admits.

   Status of the wider implementation-refinement count:
     The remaining 1 axiom in `Pulsar_N1_Sign_Refinement.ec`
     (`sign_body_compute_sig_spec`) is the byte-walk trust
     boundary and remains. `sign_wrapper_bridge` (in
     `Pulsar_N1_Sign_Wrapper.ec`) and `sign_body_spec` (in
     `Pulsar_N1_Sign_Refinement.ec`) are now PROVED lemmas via
     the wrapper-bridge collapse (d86218d) and the
     body-separation refactor (c4148a0).
   =================================================================== *)
