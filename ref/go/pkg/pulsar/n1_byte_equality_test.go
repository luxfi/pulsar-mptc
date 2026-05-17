// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// n1_byte_equality_test.go — empirical validation of the Class N1
// output-interchangeability theorem.
//
// The EasyCrypt theorem Pulsar_N1.pulsar_n1_byte_equality_extracted
// (in proofs/easycrypt/Pulsar_N1_Wrapper_Bridge.ec) says:
//
//   For any honest threshold-sign session whose share set
//   reconstructs to a centralized FIPS 204 secret key SK, the
//   resulting signature bytes are IDENTICAL to those produced by
//   FIPS 204 Sign_internal(SK, msg, ctx) — i.e., threshold-sign is
//   output-byte-equivalent to single-party deterministic FIPS 204
//   signing under the corresponding centralized key.
//
// This is the load-bearing property of Pulsar Class N1: any FIPS 204
// verifier (a stock ML-DSA-65 implementation, on-chain pre-compile,
// hardware verifier) accepts threshold-produced signatures with NO
// code change, because the bytes look exactly like a centralized
// FIPS 204 signature.
//
// The implementation strategy that makes this property hold is
// "centralized recovery": Combine reconstructs the master seed via
// Lagrange interpolation of the share set, derives the centralized
// FIPS 204 SK via KeyFromSeed, and calls mldsaSign directly. See
// threshold.go around line 418.
//
// This test performs an end-to-end byte-equality check:
//
//   1. Run the DKG to produce shares + group public key.
//   2. Reconstruct the master seed from a threshold quorum of shares
//      using the SAME Lagrange + cSHAKE256 mix as Combine.
//   3. Derive the centralized SK via KeyFromSeed(masterSeed).
//   4. Sign centrally with deterministic FIPS 204 mode.
//   5. Run the full threshold-sign protocol on the same (sid,
//      attempt, msg, ctx, quorum) under the same shares.
//   6. Assert that the two signatures are BYTE-IDENTICAL.
//
// Catches: any divergence between the centralized FIPS 204 path and
// the threshold-sign path — wrong Shamir coefficient, wrong
// committee root, wrong cSHAKE256 mix input layout, wrong sign-call
// arguments, etc. A regression on any of these would cause the
// signatures to differ and the test to fail.

import (
	"bytes"
	"testing"
)

// reconstructMasterSeed Lagrange-reconstructs the DKG master seed
// from a quorum of KeyShares + the full committee membership. This
// mirrors the in-Combine reconstruction at threshold.go:386-415
// exactly — same shamirReconstructGF, same byteSum byte ordering,
// same committeeRoot, same cSHAKE256 tag.
func reconstructMasterSeed(t *testing.T, quorum []*KeyShare, committee []*KeyShare) [SeedSize]byte {
	t.Helper()
	shares := make([]shamirShare, len(quorum))
	for i, ks := range quorum {
		var buf [shareWireSize]byte
		copy(buf[:], ks.Share[:])
		shares[i] = shareFromBytes(ks.EvalPoint, buf)
	}
	byteSum, err := shamirReconstructGF(shares)
	if err != nil {
		t.Fatal(err)
	}
	committeeRoot := committeeRootFromShares(committee)
	byteSumBytes := make([]byte, SeedSize*2)
	for b := 0; b < SeedSize; b++ {
		byteSumBytes[2*b] = byte(byteSum[b] >> 8)
		byteSumBytes[2*b+1] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	var seed [SeedSize]byte
	copy(seed[:], cshake256(mixInput, SeedSize, tagSeedShare))
	return seed
}

func TestN1_ByteEquality_ThresholdMatchesCentralized(t *testing.T) {
	// Three configurations spanning small / typical / larger
	// thresholds. Every config must produce byte-identical
	// signatures from the two paths.
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"5of3", 5, 3},
		{"7of4", 7, 4},
		{"10of7", 10, 7},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params := MustParamsFor(ModeP65)
			pub, shares, _, ident := runDKGWithIdentities(t, tc.n, tc.t, ModeP65)

			msg := []byte("Pulsar Class N1 byte-equality test message")
			var ctx []byte // empty context — match between paths

			// --- Threshold-sign path. ---
			var sid [16]byte
			copy(sid[:], "n1-byte-eq-sid-1")
			attempt := uint32(1)
			quorum := make([]NodeID, tc.t)
			for i := 0; i < tc.t; i++ {
				quorum[i] = shares[i].NodeID
			}
			sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)

			signers := make([]*ThresholdSigner, tc.t)
			for i := 0; i < tc.t; i++ {
				s, err := NewThresholdSigner(
					params, sid, attempt, quorum, shares[i],
					sessionKeys[shares[i].NodeID], msg,
					deterministicReader([]byte{byte(i), 0xBE, 0xEF}),
				)
				if err != nil {
					t.Fatalf("NewThresholdSigner party %d: %v", i, err)
				}
				signers[i] = s
			}
			r1 := make([]*Round1Message, tc.t)
			for i, s := range signers {
				m, err := s.Round1(msg)
				if err != nil {
					t.Fatalf("Round1 party %d: %v", i, err)
				}
				r1[i] = m
			}
			r2 := make([]*Round2Message, tc.t)
			for i, s := range signers {
				m, ev, err := s.Round2(r1)
				if err != nil {
					t.Fatalf("Round2 party %d: %v (ev=%v)", i, err, ev)
				}
				r2[i] = m
			}
			// false = deterministic FIPS 204 mode (KAT-reproducible).
			// Match this in the centralized path below.
			thresholdSig, err := Combine(
				params, pub, msg, ctx, false,
				sid, attempt, quorum, tc.t, r1, r2, shares,
			)
			if err != nil {
				t.Fatalf("Combine: %v", err)
			}
			if len(thresholdSig.Bytes) != params.SignatureSize {
				t.Fatalf("threshold sig size %d, want %d",
					len(thresholdSig.Bytes), params.SignatureSize)
			}

			// --- Centralized FIPS 204 path. ---
			// Reconstruct the master seed from the threshold-sized
			// quorum of shares using the EXACT same Lagrange +
			// cSHAKE256 mix that Combine uses internally.
			masterSeed := reconstructMasterSeed(t, shares[:tc.t], shares)
			centralSK, err := KeyFromSeed(params, masterSeed)
			if err != nil {
				t.Fatalf("KeyFromSeed: %v", err)
			}
			// Sanity: reconstructed pubkey must match the DKG group
			// pubkey. If this fails, every other check is moot.
			if !centralSK.Pub.Equal(pub) {
				t.Fatalf("reconstructed pubkey != DKG group pubkey")
			}
			// false = deterministic FIPS 204 mode, matching Combine
			// above. The rng arg is irrelevant when randomized=false.
			centralSig, err := Sign(params, centralSK, msg, ctx, false, nil)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			// --- The headline assertion. ---
			if !bytes.Equal(thresholdSig.Bytes, centralSig.Bytes) {
				// Show a concise prefix-mismatch report so it's
				// obvious WHERE the divergence starts.
				diffAt := -1
				for i := 0; i < len(thresholdSig.Bytes) && i < len(centralSig.Bytes); i++ {
					if thresholdSig.Bytes[i] != centralSig.Bytes[i] {
						diffAt = i
						break
					}
				}
				t.Fatalf(
					"Class N1 byte-equality VIOLATED for %s:\n"+
						"  first differing byte at offset %d\n"+
						"  threshold prefix = %x\n"+
						"  central   prefix = %x",
					tc.name, diffAt,
					thresholdSig.Bytes[:min(32, len(thresholdSig.Bytes))],
					centralSig.Bytes[:min(32, len(centralSig.Bytes))],
				)
			}

			// Sanity (already covered by TestThresholdSign_RoundTrip,
			// repeated here so a failure of this test makes the
			// chain of properties obvious):
			if err := Verify(params, pub, msg, thresholdSig); err != nil {
				t.Fatalf("threshold sig fails FIPS 204 Verify: %v", err)
			}
			if err := Verify(params, pub, msg, centralSig); err != nil {
				t.Fatalf("centralized sig fails FIPS 204 Verify: %v", err)
			}
		})
	}
}

// min is a tiny helper since this file's Go target may pre-date
// the generic `min` builtin in older toolchains.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
