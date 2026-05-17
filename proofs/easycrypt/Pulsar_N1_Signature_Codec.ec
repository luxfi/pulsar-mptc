(* -------------------------------------------------------------------- *)
(* Pulsar — FIPS 204 signature byte-codec                              *)
(* -------------------------------------------------------------------- *)
(* Decomplected from Pulsar_N1_Combine_Layout.                          *)
(*                                                                      *)
(* This file holds the FIPS 204 ML-DSA-65 signature-bytes view shared   *)
(* by combine and sign. Three concerns live here, and only three:       *)
(*                                                                      *)
(*   1. The abstract `signature_t` type (FIPS 204 §3.5.5 c_tilde || z   *)
(*      || h, 3293 bytes for ML-DSA-65).                                *)
(*   2. Encode / decode + length, as named per-type axioms (the         *)
(*      FIPS 204 packing is fully specified at the bit level in         *)
(*      `lemmas/MLDSA65_Functional.ec`; we surface only the round-trip  *)
(*      property here).                                                 *)
(*   3. read_sig_at / write_sig_at — read/write a packed signature at   *)
(*      a memory pointer — plus the two proved frame lemmas             *)
(*      (read_after_write_sig + write_sig_separation). These compose    *)
(*      Pulsar_N1_Memory's bulk primitives with the codec.              *)
(*                                                                      *)
(* What this file is NOT:                                               *)
(*                                                                      *)
(*   - It does NOT contain the bit-level FIPS 204 §3.5.5 packing        *)
(*     spec — that's `MLDSA65_Functional.pack_signature` /              *)
(*     `unpack_signature` (when those land). Here we only need the      *)
(*     round-trip + length identities to discharge layout proofs.       *)
(*                                                                      *)
(*   - It does NOT contain combine- or sign-specific encoders for       *)
(*     other wire types (c_tilde, t0, r2_msg, sk packing, message       *)
(*     bytes). Those live in the per-procedure layout files.            *)
(*                                                                      *)
(* Decomplect benefit: Pulsar_N1_Sign_Layout no longer imports          *)
(* Pulsar_N1_Combine_Layout. The two layouts now share Memory + this    *)
(* codec only.                                                          *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Pulsar_N1_Memory.

(* ===================================================================
   FIPS 204 ML-DSA-65 signature length (bytes).
   3293 = 32 (c_tilde) + 5 * 640 (z packing) + 55 (h.weight cap) + 6
        (per FIPS 204 §3.5.5 sig packing for parameter set 3).
   =================================================================== *)

op sig_len : int = 3293.

(* ===================================================================
   The abstract signature type + codec ops.

   `signature_t` is abstract — its concrete byte-level shape is the
   FIPS 204 §3.5.5 packing, specified separately in
   MLDSA65_Functional.ec. We expose two property axioms (round-trip
   + length) that the layout-correctness proofs consume.
   =================================================================== *)

type signature_t.

op encode_signature : signature_t -> int list.
op decode_signature : int list  -> signature_t.

axiom encode_decode_signature (x : signature_t) :
  decode_signature (encode_signature x) = x.

axiom encode_signature_len (x : signature_t) :
  size (encode_signature x) = sig_len.

(* ===================================================================
   Memory-level signature read / write.

   These compose the memory primitives (load_bytes / store_bytes from
   Pulsar_N1_Memory) with the codec above. They're shared by both
   layout files via the thin wrappers
   `Pulsar_N1_Combine_Layout.read_signature_at` /
   `Pulsar_N1_Sign_Layout.read_sig_sign` (kept for backward
   compatibility with the existing Refinement-file consumers).
   =================================================================== *)

op read_sig_at (m : mem_t) (p : int) : signature_t =
  decode_signature (load_bytes m p sig_len).

op write_sig_at (m : mem_t) (p : int) (s : signature_t) : mem_t =
  store_bytes m p (encode_signature s).

(* ===================================================================
   Frame lemmas — PROVED, no axioms beyond the per-type codec ones.
   =================================================================== *)

(* Round-trip: writing a signature at p and reading back from p
   returns the original. *)
lemma read_after_write_sig (m : mem_t) (p : int) (s : signature_t) :
  read_sig_at (write_sig_at m p s) p = s.
proof.
  rewrite /read_sig_at /write_sig_at.
  have Heq :
    load_bytes (store_bytes m p (encode_signature s)) p sig_len
    = encode_signature s.
  - have <-: size (encode_signature s) = sig_len
      by exact encode_signature_len.
    by apply store_bytes_load_bytes.
  by rewrite Heq encode_decode_signature.
qed.

(* Separation: a write to [p, p + sig_len) doesn't affect reads at
   addresses outside that range. *)
lemma write_sig_separation
      (m : mem_t) (p : int) (s : signature_t) (q : int) :
  q < p \/ p + sig_len <= q =>
  load_byte (write_sig_at m p s) q = load_byte m q.
proof.
  move=> Hdisj.
  rewrite /write_sig_at.
  apply store_bytes_disjoint.
  by have ->: size (encode_signature s) = sig_len
    by exact encode_signature_len.
qed.

(* ===================================================================
   ACCOUNTING

   axioms (2 — per-type FIPS 204 §3.5.5 round-trip + length):
     encode_decode_signature
     encode_signature_len

   ops (definitions):
     sig_len, signature_t,
     encode_signature, decode_signature,
     read_sig_at, write_sig_at.

   PROVED lemmas (0 admits):
     read_after_write_sig
     write_sig_separation
   =================================================================== *)
