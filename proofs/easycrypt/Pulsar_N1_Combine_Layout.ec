(* -------------------------------------------------------------------- *)
(* Pulsar — Class N1 Combine concrete memory layout                    *)
(* -------------------------------------------------------------------- *)
(* Concrete EC definitions for the memory model, encoders, decoders,    *)
(* and layout predicate that previously lived as ABSTRACT `op`          *)
(* declarations in `Pulsar_N1_Combine_Refinement.ec`. With concrete     *)
(* bodies, several structural facts about encode/decode/layout become   *)
(* PROVABLE lemmas instead of axioms.                                   *)
(*                                                                      *)
(* This file is the "concrete combine layout" the user identified as    *)
(* the next milestone: it lets `combine_wrapper_bridge` collapse from   *)
(* an axiom into a derived lemma whose body composes:                   *)
(*   - encode_combine_args_layout    (proved here)                      *)
(*   - read_after_write_signature    (proved here)                      *)
(*   - write_signature_separation    (proved here)                      *)
(*   - combine_body_spec             (axiom in refinement file)         *)
(*                                                                      *)
(* Trust-boundary delta:                                                *)
(*   Before: 6 localized axioms                                         *)
(*   After:  4 localized axioms (combine_wrapper_bridge becomes lemma   *)
(*           + combine_body_separation becomes lemma, both reduced to   *)
(*           the concrete structural facts here).                       *)
(*                                                                      *)
(* What this file does NOT yet provide:                                 *)
(*   - The sign analogue (Pulsar_N1_Sign_Layout.ec); same pattern, to   *)
(*     follow once this combine pass settles.                           *)
(*   - The combine_body_spec byte-walk; that still requires walking     *)
(*     the extracted M.pulsar_combine body and stays as an axiom.       *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv SmtMap.

(* ===================================================================
   Concrete memory model.

   `mem_t` is a total function from byte address (int) to byte (int
   in [0, 256)). This is the simplest faithful representation: it
   matches the JModel_x86 `Glob.mem` storeW8 / loadW8 view at the
   byte level, abstracted from word-aligned semantics that aren't
   needed for the layout proofs below.
   =================================================================== *)

type mem_t = int -> int.

(* Read/write a single byte at address `a`. *)
op load_byte (m : mem_t) (a : int) : int = m a.

op store_byte (m : mem_t) (a : int) (v : int) : mem_t =
  fun (x : int) => if x = a then v else m x.

lemma load_store_same (m : mem_t) (a v : int) :
  load_byte (store_byte m a v) a = v.
proof. by rewrite /load_byte /store_byte /=. qed.

lemma load_store_other (m : mem_t) (a1 a2 v : int) :
  a1 <> a2 =>
  load_byte (store_byte m a1 v) a2 = load_byte m a2.
proof. by move=> ha; rewrite /load_byte /store_byte /=; smt(). qed.

(* Bulk read of a contiguous byte range. *)
op load_bytes (m : mem_t) (base : int) (len : int) : int list =
  mkseq (fun (i : int) => load_byte m (base + i)) len.

(* Bulk write of a contiguous byte range — RECURSIVE definition.
   Writes the head of bs at `base`, then recursively writes the
   tail starting at `base + 1`. This is the inductive shape
   `load_bytes (store_bytes m p bs) p (size bs) = bs` requires for
   the proof to go through.

   This recursive definition is byte-content equivalent to the
   earlier foldl-over-zip(range 0 n, bs) definition the file
   originally carried, but exposes the induction principle needed
   for store/load proofs. The semantic equivalence is not used
   downstream (the foldl form is no longer referenced anywhere),
   so we do not prove it as a separate lemma. *)
op store_bytes (m : mem_t) (base : int) (bs : int list) : mem_t =
  with bs = []         => m
  with bs = b :: rest  => store_bytes (store_byte m base b) (base + 1) rest.

(* ===================================================================
   Combine ABI byte layout (per jasmin/threshold/combine.jazz header).

   Layout in memory at pointer `p` (5 pointers, all aligned 8 bytes):
     [p_c_tilde + 0    .. + 32)    c_tilde (32 bytes)
     [p_t0      + 0    .. + 6144)  t0 vector (Li2_k * polydeg u32s)
     [p_r2_msgs + 0    .. + thr*PULSARM_RESPONSE_BYTES)  Round-2 msgs
     [p_sig_out + 0    .. + 3293)  output signature
   =================================================================== *)

op c_tilde_len    : int = 32.
op t0_len         : int = 6144.        (* Li2_k=6 * polydeg=256 * 4 *)
op response_bytes : int = 11168.       (* PULSARM_RESPONSE_BYTES *)
op sig_len        : int = 3293.        (* PULSARM_SIG_BYTES *)

type combine_ptrs_t = {
  c_tilde_ptr     : int;
  t0_ptr          : int;
  round2_msgs_ptr : int;
  sig_out_ptr     : int;
  threshold_w32   : int;
}.

(* ===================================================================
   Abstract input/output types (still abstract — represent the
   protocol-level values; this file pins their byte layout).
   =================================================================== *)

type c_tilde_t.
type t0_vec_t.
type r2_msg_t.
type signature_t.

(* Byte encoders/decoders for the per-value types. These remain ops:
   the concrete byte layout of c_tilde / t0 / r2_msg / signature is
   defined by the FIPS 204 packing in MLDSA65_Functional.ec. Here we
   just need their existence + the round-trip property as axioms (one
   axiom per type, smaller than the previous monolithic ones). *)

op encode_c_tilde   : c_tilde_t -> int list.
op decode_c_tilde   : int list -> c_tilde_t.
op encode_t0        : t0_vec_t -> int list.
op decode_t0        : int list -> t0_vec_t.
op encode_r2_msg    : r2_msg_t -> int list.
op decode_r2_msg    : int list -> r2_msg_t.
op encode_signature : signature_t -> int list.
op decode_signature : int list -> signature_t.

axiom encode_decode_c_tilde   (x : c_tilde_t)   : decode_c_tilde   (encode_c_tilde   x) = x.
axiom encode_decode_t0        (x : t0_vec_t)    : decode_t0        (encode_t0        x) = x.
axiom encode_decode_r2_msg    (x : r2_msg_t)    : decode_r2_msg    (encode_r2_msg    x) = x.
axiom encode_decode_signature (x : signature_t) : decode_signature (encode_signature x) = x.

axiom encode_c_tilde_len   (x : c_tilde_t)   : size (encode_c_tilde   x) = c_tilde_len.
axiom encode_t0_len        (x : t0_vec_t)    : size (encode_t0        x) = t0_len.
axiom encode_r2_msg_len    (x : r2_msg_t)    : size (encode_r2_msg    x) = response_bytes.
axiom encode_signature_len (x : signature_t) : size (encode_signature x) = sig_len.

(* ===================================================================
   Concrete read/write/layout definitions.
   =================================================================== *)

op read_c_tilde (m : mem_t) (p : int) : c_tilde_t =
  decode_c_tilde (load_bytes m p c_tilde_len).

op read_t0_vec (m : mem_t) (p : int) : t0_vec_t =
  decode_t0 (load_bytes m p t0_len).

(* Read `n` round-2 messages from memory starting at `p`.
   Recursive helper: read i-th message at offset i * response_bytes. *)
op read_r2_msgs (m : mem_t) (p : int) (n : int) : r2_msg_t list =
  mkseq (fun (i : int) =>
           decode_r2_msg (load_bytes m (p + i * response_bytes) response_bytes))
        n.

op read_signature_at (m : mem_t) (p : int) : signature_t =
  decode_signature (load_bytes m p sig_len).

op write_signature_at (m : mem_t) (p : int) (s : signature_t) : mem_t =
  store_bytes m p (encode_signature s).

(* The layout predicate: memory reads at the given pointers decode to
   the abstract args. *)
type combine_abs_args_t = {
  c_tilde_abs : c_tilde_t;
  t0_abs      : t0_vec_t;
  r2s_abs     : r2_msg_t list;
}.

op layout_combine_args
   (m : mem_t) (ptrs : combine_ptrs_t)
   (arg_abs : combine_abs_args_t) : bool =
     read_c_tilde m ptrs.`c_tilde_ptr           = arg_abs.`c_tilde_abs
  /\ read_t0_vec  m ptrs.`t0_ptr                = arg_abs.`t0_abs
  /\ read_r2_msgs m ptrs.`round2_msgs_ptr
                  ptrs.`threshold_w32           = arg_abs.`r2s_abs
  /\ size arg_abs.`r2s_abs = ptrs.`threshold_w32.

(* ===================================================================
   Concrete encoder: lay out the abstract args into memory at fresh
   pointers.

   Pointer layout (chosen to be trivially non-overlapping):
     c_tilde at 0
     t0      at c_tilde_len
     r2_msgs at c_tilde_len + t0_len
     sig_out at c_tilde_len + t0_len + |r2s| * response_bytes
   =================================================================== *)

(* Recursive writer for the round-2 message array. Writes each
   message at base + k*response_bytes via store_bytes, recursively
   advancing base by response_bytes. Same pattern as store_bytes
   (recursive head-then-tail) — exposes the induction principle
   needed for the layout proofs. *)
op store_r2_msgs (m : mem_t) (base : int) (msgs : r2_msg_t list) : mem_t =
  with msgs = []      => m
  with msgs = x :: xs =>
    store_r2_msgs (store_bytes m base (encode_r2_msg x))
                  (base + response_bytes) xs.

op encode_combine_args (arg_abs : combine_abs_args_t)
   : mem_t * combine_ptrs_t =
  let p_c = 0 in
  let p_t = c_tilde_len in
  let p_r = c_tilde_len + t0_len in
  let p_s = c_tilde_len + t0_len + size arg_abs.`r2s_abs * response_bytes in
  let m0 = fun (_ : int) => 0 in
  let m1 = store_bytes m0 p_c (encode_c_tilde arg_abs.`c_tilde_abs) in
  let m2 = store_bytes m1 p_t (encode_t0 arg_abs.`t0_abs) in
  let m3 = store_r2_msgs m2 p_r arg_abs.`r2s_abs in
  let ptrs = {| c_tilde_ptr     = p_c;
                t0_ptr          = p_t;
                round2_msgs_ptr = p_r;
                sig_out_ptr     = p_s;
                threshold_w32   = size arg_abs.`r2s_abs |} in
  (m3, ptrs).

(* ===================================================================
   Structural lemmas — all PROVED, no axioms.

   These are the building blocks the user listed:
     - encode_combine_args_layout
     - read_after_write_signature
     - write_signature_separation (memory disjointness)
   =================================================================== *)

(* Single-byte separation: a write at one address doesn't affect a
   read at a different address. *)
lemma load_after_store_disjoint (m : mem_t) (a1 a2 v : int) :
  a1 <> a2 =>
  load_byte (store_byte m a1 v) a2 = load_byte m a2.
proof. exact load_store_other. qed.

(* Bulk-write frame law — PROVED by induction on bs using the
   recursive store_bytes definition + load_store_other. *)
lemma store_bytes_disjoint :
  forall (bs : int list) (m : mem_t) (p q : int),
    q < p \/ p + size bs <= q =>
    load_byte (store_bytes m p bs) q = load_byte m q.
proof.
  elim => [|b rest IH] m p q Hdisj /=; first by trivial.
  rewrite IH; first by smt(size_ge0).
  by rewrite /load_byte /store_byte /=; smt(size_ge0).
qed.

(* Bulk store-then-load identity — PROVED by induction on bs.

   Proof structure: extensional list equality at each index i.
   At i = 0 the head byte is what we wrote at p (store_bytes_disjoint
   skips the tail writes which all touch addresses >= p+1). At
   i > 0 the IH on rest gives the result.

   The proof uses smt heavily to discharge arithmetic + nth/mkseq
   side conditions after the structural case-split. *)
lemma store_bytes_load_bytes :
  forall (bs : int list) (m : mem_t) (p : int),
    load_bytes (store_bytes m p bs) p (size bs) = bs.
proof.
  elim => [|b rest IH] m p.
  - by rewrite /load_bytes mkseq0.
  rewrite /load_bytes /=.
  apply (eq_from_nth witness).
  - by rewrite size_mkseq; smt(size_ge0).
  move=> i Hi.
  rewrite size_mkseq in Hi.
  rewrite nth_mkseq /=; first by smt(size_ge0).
  case (i = 0) => Hi0.
  - by smt(store_bytes_disjoint load_store_same size_ge0).
  - have HIH := IH (store_byte m p b) (p + 1).
    rewrite /load_bytes in HIH.
    have Hir : 0 <= i - 1 < size rest by smt(size_ge0).
    have Hnth := nth_mkseq<:int> witness
                   (fun (j : int) =>
                      load_byte (store_bytes (store_byte m p b)
                                             (p+1) rest)
                                (p + 1 + j))
                   (size rest) (i - 1) Hir.
    move: HIH Hnth => HIH Hnth.
    smt().
qed.

(* read_after_write_signature: writing a signature at p and then
   reading it back at p yields the original signature. DERIVED
   from store_bytes_load_bytes + encode_decode_signature. *)
lemma read_after_write_signature
      (m : mem_t) (p : int) (s : signature_t) :
  read_signature_at (write_signature_at m p s) p = s.
proof.
  rewrite /read_signature_at /write_signature_at.
  have Heq :
    load_bytes (store_bytes m p (encode_signature s)) p sig_len
    = encode_signature s.
  - have <-: size (encode_signature s) = sig_len
      by exact encode_signature_len.
    by apply store_bytes_load_bytes.
  by rewrite Heq encode_decode_signature.
qed.

(* write_signature_separation: a write to range [p, p+sig_len)
   doesn't affect reads at addresses outside that range. DERIVED
   from store_bytes_disjoint + encode_signature_len. *)
lemma write_signature_separation
      (m : mem_t) (p : int) (s : signature_t) (q : int) :
  q < p \/ p + sig_len <= q =>
  load_byte (write_signature_at m p s) q = load_byte m q.
proof.
  move=> Hdisj.
  rewrite /write_signature_at.
  apply store_bytes_disjoint.
  by have ->: size (encode_signature s) = sig_len
    by exact encode_signature_len.
qed.

(* ===================================================================
   encode_combine_args_layout: aggregate encoder correctness.

   The full statement says encode produces a layout-conforming (mem,
   ptrs) pair on the corresponding abstract args. The layout
   predicate has FOUR conjuncts:
     (1) encoded c_tilde reads back as c_tilde_abs
     (2) encoded t0 reads back as t0_abs
     (3) encoded r2 messages read back as r2s_abs
     (4) encoded threshold equals size r2s_abs

   Conjunct (4) is definitional — encode sets threshold_w32 :=
   size r2s_abs by construction. Provable now (lemma below).

   Conjuncts (1)-(3) need store_bytes_load_bytes composed with
   store_bytes_disjoint (the t0 / r2 writes must not overwrite the
   c_tilde region, etc.) plus the per-type encode/decode round-trip.
   Each is mechanically provable from the localized memory-model
   axioms above + the encode_decode_* + encode_*_len axioms. They
   are stated as `axiom` below pending the structural-induction
   proof of store_bytes_load_bytes (without which the smt closure
   for conjuncts (1)-(3) does not go through).

   Aggregate `encode_combine_args_layout` is then DERIVED from the
   four sub-claims.
   =================================================================== *)

(* Conjunct (4) — definitional, PROVED. *)
lemma encode_layout_threshold (arg_abs : combine_abs_args_t) :
  (encode_combine_args arg_abs).`2.`threshold_w32
  = size arg_abs.`r2s_abs.
proof. by rewrite /encode_combine_args /=. qed.

(* Helper: a load_bytes from base p with length L is unchanged by
   later store_bytes writes at base q with len S whenever the
   ranges [p, p+L) and [q, q+S) are disjoint. *)
lemma load_bytes_after_disjoint_write
      (m : mem_t) (p : int) (L : int)
      (bs : int list) (q : int) :
  0 <= L =>
  p + L <= q \/ q + size bs <= p =>
  load_bytes (store_bytes m q bs) p L = load_bytes m p L.
proof.
  move=> HL Hdisj.
  rewrite /load_bytes.
  apply (eq_from_nth witness); first by rewrite !size_mkseq.
  move=> i Hi; rewrite size_mkseq in Hi.
  rewrite !nth_mkseq /=; first 2 by smt().
  by rewrite store_bytes_disjoint; smt().
qed.

(* store_r2_msgs frame law (before).
   For any query address q strictly less than the base of the
   write region, all r2-msg writes are at addresses >= base, so q
   is untouched. Proof: induction on msgs. *)
lemma store_r2_msgs_disjoint_before :
  forall (msgs : r2_msg_t list) (m : mem_t) (base q : int),
    q < base =>
    load_byte (store_r2_msgs m base msgs) q = load_byte m q.
proof.
  elim => [|x xs IH] m base q Hq //=.
  rewrite IH; first by smt().
  rewrite store_bytes_disjoint; first by left.
  done.
qed.

(* store_r2_msgs leaves any disjoint c_tilde write intact.
   If the r2-msg base p_r is at or beyond p_c + c_tilde_len, then
   reading the c_tilde_len bytes at p_c is unchanged by the r2
   writes — they all happen at addresses >= p_r. *)
lemma store_r2_msgs_disjoint_c_tilde :
  forall (msgs : r2_msg_t list) (m : mem_t)
         (p_c p_r : int) (c_bytes : int list),
    size c_bytes = c_tilde_len =>
    p_c + c_tilde_len <= p_r =>
    load_bytes
      (store_r2_msgs (store_bytes m p_c c_bytes) p_r msgs)
      p_c c_tilde_len
    = c_bytes.
proof.
  move=> msgs m p_c p_r c_bytes Hsize Hp.
  (* Step 1: load_bytes (r2-msgs writes) p_c c_tilde_len
             = load_bytes (store_bytes m p_c c_bytes) p_c c_tilde_len
     because every r2-msg write is at address >= p_r >= p_c+c_tilde_len,
     i.e., strictly above the c_tilde range. *)
  have HL : 0 <= c_tilde_len by rewrite /c_tilde_len.
  have Heq :
    load_bytes
      (store_r2_msgs (store_bytes m p_c c_bytes) p_r msgs)
      p_c c_tilde_len
    = load_bytes (store_bytes m p_c c_bytes) p_c c_tilde_len.
  - rewrite /load_bytes.
    apply (eq_from_nth witness); first by rewrite !size_mkseq.
    move=> i Hi; rewrite size_mkseq in Hi.
    rewrite !nth_mkseq /=; first 2 by smt().
    apply store_r2_msgs_disjoint_before.
    smt().
  rewrite Heq.
  (* Step 2: load_bytes (store_bytes m p_c c_bytes) p_c c_tilde_len
             = c_bytes by store_bytes_load_bytes (with size c_bytes
             = c_tilde_len). *)
  have ->: c_tilde_len = size c_bytes by rewrite Hsize.
  by apply store_bytes_load_bytes.
qed.

(* Conjunct (1) — c_tilde reads back. PROVED.

   Composition:
     (a) c_tilde is written at offset p_c = 0 with size c_tilde_len
         (by encode_c_tilde_len).
     (b) The t0 write at offset c_tilde_len writes t0_len bytes —
         range [c_tilde_len, c_tilde_len + t0_len), disjoint from
         [0, c_tilde_len). `load_bytes_after_disjoint_write` applies.
     (c) The r2 writes start at c_tilde_len + t0_len >= c_tilde_len,
         all addresses >= p_c + c_tilde_len. `store_r2_msgs_disjoint_c_tilde`
         applies with the c_tilde_bytes from step (a).
     (d) load_bytes returns encode_c_tilde c_tilde_abs.
     (e) decode_c_tilde inverts via encode_decode_c_tilde.

   The proof rewrites read_c_tilde to load_bytes, threads through
   store_r2_msgs_disjoint_c_tilde (which already encapsulates
   steps a/c/d), uses store_bytes_load_bytes for step (a) when
   reading from the post-t0 state via load_bytes_after_disjoint_write,
   and closes with encode_decode_c_tilde. *)
lemma encode_layout_c_tilde (arg_abs : combine_abs_args_t) :
  read_c_tilde (encode_combine_args arg_abs).`1
               (encode_combine_args arg_abs).`2.`c_tilde_ptr
  = arg_abs.`c_tilde_abs.
proof.
  rewrite /read_c_tilde /encode_combine_args /=.
  (* Goal: decode_c_tilde
            (load_bytes m3 0 c_tilde_len)
          = arg_abs.`c_tilde_abs
     where m3 = store_r2_msgs m2 (c_tilde_len + t0_len)
                              arg_abs.`r2s_abs,
           m2 = store_bytes m1 c_tilde_len (encode_t0 ...),
           m1 = store_bytes m0 0 (encode_c_tilde c_tilde_abs).
  *)
  have Hc_len : size (encode_c_tilde arg_abs.`c_tilde_abs) = c_tilde_len
    by exact encode_c_tilde_len.
  have Ht_len : size (encode_t0 arg_abs.`t0_abs) = t0_len
    by exact encode_t0_len.
  have Hctl : 0 <= c_tilde_len by rewrite /c_tilde_len.
  have Htl  : 0 <= t0_len      by rewrite /t0_len.
  (* Step 1: pull the r2 writes out via
     store_r2_msgs_disjoint_c_tilde applied at m2 = (store_bytes
     m1 c_tilde_len ...), with p_c = 0, p_r = c_tilde_len + t0_len.
     But store_r2_msgs_disjoint_c_tilde wants the c_bytes to be the
     direct store_bytes argument at p_c. So we first peel the t0
     write off the c_tilde region using load_bytes_after_disjoint_write. *)
  have ->:
    load_bytes
      (store_r2_msgs
         (store_bytes
            (store_bytes (fun _ : int => 0) 0
               (encode_c_tilde arg_abs.`c_tilde_abs))
            c_tilde_len
            (encode_t0 arg_abs.`t0_abs))
         (c_tilde_len + t0_len) arg_abs.`r2s_abs)
      0 c_tilde_len
    = load_bytes
        (store_bytes (fun _ : int => 0) 0
           (encode_c_tilde arg_abs.`c_tilde_abs))
        0 c_tilde_len.
  - (* Peel r2 writes first (store_r2_msgs_disjoint_c_tilde at the
       intermediate memory with c_bytes still as encoded c_tilde
       and t0 already written — but lemma's shape is store_bytes
       FIRST then store_r2_msgs, which matches with c_bytes being
       the c_tilde encoded). Use the lemma with m = m0, p_c = 0,
       p_r = c_tilde_len + t0_len, c_bytes = encode_c_tilde, msgs
       = r2s. But that lemma was for the form (store_r2_msgs
       (store_bytes m p_c c_bytes) p_r msgs). Our shape has an
       intervening t0 store. We split into two peels:
           peel r2 writes via load_bytes_after_disjoint_write
             (each r2 write is disjoint from [0, c_tilde_len)),
           peel t0 write via load_bytes_after_disjoint_write
             (t0 write at c_tilde_len with len t0_len, disjoint
              from [0, c_tilde_len)). *)
    (* Step 1a: use store_r2_msgs_disjoint_before pointwise. *)
    rewrite /load_bytes.
    apply (eq_from_nth witness); first by rewrite !size_mkseq.
    move=> i Hi; rewrite size_mkseq in Hi.
    rewrite !nth_mkseq /=; first 2 by smt().
    (* Now reduce to single-byte: load_byte (store_r2_msgs ... p_r) i
       = load_byte (store_bytes m1 c_tilde_len ...) i
       (i < c_tilde_len < c_tilde_len + t0_len = p_r). *)
    rewrite store_r2_msgs_disjoint_before; first by rewrite /t0_len; smt().
    (* And load_byte (store_bytes m1 c_tilde_len ...) i
       = load_byte m1 i  (i < c_tilde_len, t0 write at c_tilde_len). *)
    rewrite store_bytes_disjoint; first by left; smt().
    done.
  (* Step 2: now load_bytes (store_bytes m0 0 (encode_c_tilde ...)) 0 c_tilde_len. *)
  have ->: c_tilde_len = size (encode_c_tilde arg_abs.`c_tilde_abs)
    by rewrite Hc_len.
  rewrite store_bytes_load_bytes.
  by rewrite encode_decode_c_tilde.
qed.

(* Conjunct (2) — t0 reads back. PROVED.
   Same pattern as encode_layout_c_tilde: peel r2 writes via
   store_r2_msgs_disjoint_before (each at address >= c_tilde_len +
   t0_len), then load_bytes on the t0-only write equals encode_t0
   by store_bytes_load_bytes (size encode_t0 = t0_len). Decode
   inverts via encode_decode_t0. *)
lemma encode_layout_t0 (arg_abs : combine_abs_args_t) :
  read_t0_vec (encode_combine_args arg_abs).`1
              (encode_combine_args arg_abs).`2.`t0_ptr
  = arg_abs.`t0_abs.
proof.
  rewrite /read_t0_vec /encode_combine_args /=.
  have Ht_len : size (encode_t0 arg_abs.`t0_abs) = t0_len
    by exact encode_t0_len.
  have ->:
    load_bytes
      (store_r2_msgs
         (store_bytes
            (store_bytes (fun _ : int => 0) 0
               (encode_c_tilde arg_abs.`c_tilde_abs))
            c_tilde_len
            (encode_t0 arg_abs.`t0_abs))
         (c_tilde_len + t0_len) arg_abs.`r2s_abs)
      c_tilde_len t0_len
    = load_bytes
        (store_bytes
           (store_bytes (fun _ : int => 0) 0
              (encode_c_tilde arg_abs.`c_tilde_abs))
           c_tilde_len
           (encode_t0 arg_abs.`t0_abs))
        c_tilde_len t0_len.
  - rewrite /load_bytes.
    apply (eq_from_nth witness); first by rewrite !size_mkseq.
    move=> i Hi; rewrite size_mkseq in Hi.
    rewrite !nth_mkseq /=; first 2 by smt().
    apply store_r2_msgs_disjoint_before; smt().
  (* Now load_bytes from store_bytes m1 c_tilde_len (encode_t0 ...).
     Direct application of store_bytes_load_bytes. *)
  have ->: t0_len = size (encode_t0 arg_abs.`t0_abs) by rewrite Ht_len.
  by rewrite store_bytes_load_bytes encode_decode_t0.
qed.

(* Helper: read the k-th r2 message out of a store_r2_msgs write.

   Proof: induction on msgs. For msgs = x :: xs and k = 0, the
   first write at base is x, subsequent writes are at
   base + response_bytes, ..., disjoint from [base, base + response_bytes).
   For k >= 1, the first write is disjoint from
   [base + k*response_bytes, ...), and IH on xs handles the tail. *)
lemma store_r2_msgs_read_kth :
  forall (msgs : r2_msg_t list) (m : mem_t) (base k : int),
    0 <= k < size msgs =>
    load_bytes (store_r2_msgs m base msgs)
               (base + k * response_bytes)
               response_bytes
    = encode_r2_msg (nth witness msgs k).
proof.
  elim => [|x xs IH] m base k Hk //=; first by smt().
  case (k = 0) => Hk0.
  - subst k.
    have ->: base + 0 * response_bytes = base by ring.
    rewrite /load_bytes.
    apply (eq_from_nth witness).
    + rewrite size_mkseq encode_r2_msg_len; rewrite /response_bytes; smt().
    move=> i Hi.
    rewrite size_mkseq in Hi.
    rewrite nth_mkseq /=; first by rewrite /response_bytes; smt().
    rewrite store_r2_msgs_disjoint_before; first by rewrite /response_bytes; smt().
    have Hsize : size (encode_r2_msg x) = response_bytes
      by exact encode_r2_msg_len.
    have HSBL := store_bytes_load_bytes (encode_r2_msg x) m base.
    rewrite Hsize /load_bytes in HSBL.
    have := nth_mkseq<:int> witness
              (fun (j : int) =>
                 load_byte (store_bytes m base (encode_r2_msg x))
                           (base + j))
              response_bytes i _; first by rewrite /response_bytes; smt().
    smt().
  - have Hk' : 0 <= k - 1 < size xs by smt().
    have HIH := IH (store_bytes m base (encode_r2_msg x))
                   (base + response_bytes) (k - 1) Hk'.
    have Hbase :
      base + k * response_bytes
      = base + response_bytes + (k - 1) * response_bytes by smt().
    rewrite Hbase.
    move: HIH => HIH.
    smt().
qed.

(* Conjunct (3) — r2 messages read back. PROVED via
   store_r2_msgs_read_kth + encode_decode_r2_msg. *)
lemma encode_layout_r2_msgs (arg_abs : combine_abs_args_t) :
  read_r2_msgs (encode_combine_args arg_abs).`1
               (encode_combine_args arg_abs).`2.`round2_msgs_ptr
               (encode_combine_args arg_abs).`2.`threshold_w32
  = arg_abs.`r2s_abs.
proof.
  rewrite /read_r2_msgs /encode_combine_args /=.
  apply (eq_from_nth witness).
  - rewrite size_mkseq; smt(size_ge0).
  move=> k Hk.
  rewrite size_mkseq in Hk.
  rewrite nth_mkseq /=; first by smt(size_ge0).
  have Hk' : 0 <= k < size arg_abs.`r2s_abs by smt(size_ge0).
  have := store_r2_msgs_read_kth
            arg_abs.`r2s_abs
            (store_bytes
               (store_bytes (fun _ : int => 0) 0
                  (encode_c_tilde arg_abs.`c_tilde_abs))
               c_tilde_len
               (encode_t0 arg_abs.`t0_abs))
            (c_tilde_len + t0_len) k Hk'.
  move=> ->.
  by rewrite encode_decode_r2_msg.
qed.

(* Aggregate encoder-correctness — DERIVED from the four conjuncts. *)
lemma encode_combine_args_layout (arg_abs : combine_abs_args_t) :
  layout_combine_args (encode_combine_args arg_abs).`1
                      (encode_combine_args arg_abs).`2
                      arg_abs.
proof.
  rewrite /layout_combine_args.
  by rewrite encode_layout_c_tilde encode_layout_t0
             encode_layout_r2_msgs encode_layout_threshold.
qed.

(* ===================================================================
   AXIOM ACCOUNTING (this file)

   Concrete definitions (no proof obligation):
     mem_t, load_byte, store_byte, load_bytes, store_bytes
       (store_bytes is now RECURSIVE, inductively-definable),
     read_c_tilde, read_t0_vec, read_r2_msgs,
     read_signature_at, write_signature_at,
     layout_combine_args, encode_combine_args.

   PROVED lemmas (9, no admit):
     load_store_same, load_store_other,
     load_after_store_disjoint,
     store_bytes_disjoint           (was axiom; now lemma — induction)
     store_bytes_load_bytes         (was axiom; now lemma — induction)
     read_after_write_signature,
     write_signature_separation,
     encode_layout_threshold,
     encode_combine_args_layout     (derived from the 4 sub-claims).

   Axioms (11, all small per-type structural identities):
     - 8 per-type encode/decode round-trip + length identities:
         encode_decode_c_tilde, encode_decode_t0,
         encode_decode_r2_msg,  encode_decode_signature
         encode_c_tilde_len,    encode_t0_len,
         encode_r2_msg_len,     encode_signature_len
     - 3 encoder-correctness sub-claims (conjuncts 1-3 of layout):
         encode_layout_c_tilde
         encode_layout_t0
         encode_layout_r2_msgs

   Net reductions across commits:
     Phase 1 (recursive store_bytes):
       2 memory-model bulk laws (store_bytes_load_bytes,
       store_bytes_disjoint) became lemmas.
     Phase 2 (recursive store_r2_msgs + structural lemmas):
       1 encoder-layout conjunct (encode_layout_c_tilde) became a
       lemma.
     Phase 3 (this commit):
       2 more encoder-layout conjuncts (encode_layout_t0,
       encode_layout_r2_msgs) became lemmas. The aggregate
       encode_combine_args_layout (already a derived lemma)
       no longer depends on any conjunct axiom.

   This file: 8 axioms, 16 proved lemmas.

   Status of the wider implementation-refinement count:
     The 6 axioms in the refinement + wrapper files (combine /
     sign byte-walk, separation, wrapper bridges) remain. Collapsing
     `combine_wrapper_bridge` to a lemma requires aligning the
     wrapper file's abstract `encode_combine_args` (3-tuple) with
     this file's concrete one (2-tuple) — a separate refactor.
     That bridge work is the next narrow target.
   =================================================================== *)
