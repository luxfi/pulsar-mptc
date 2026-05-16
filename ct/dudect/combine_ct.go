// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// combine_ct.go — cgo bridge exposing pulsar.Combine to the C
// dudect harness in dudect_combine.c.
//
// The bridge pre-builds a (Round1Message, Round2Message) tape from a
// real threshold ceremony, then for every dudect sample replaces ONE
// party's Round-2 reveal bytes with caller-supplied bytes (fixed for
// class A, random for class B). Combine then runs over the mutated
// tape.
//
// The targeted leak channel is the partial-signature share bytes —
// these are the secret-derived bytes that flow into the cSHAKE256
// commit re-derivation, the GF(257) Lagrange reconstruction, and the
// final ML-DSA SignTo call. Any data-dependent branch in those paths
// would surface here as a Welch t-statistic above the dudect
// threshold.
//
// Build (Linux):
//   GOWORK=off go build -buildmode=c-shared \
//       -o libpulsar_combine.so ./combine_ct.go
// Build (macOS):
//   GOWORK=off go build -buildmode=c-shared \
//       -o libpulsar_combine.dylib ./combine_ct.go

package main

/*
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/pulsar/ref/go/pkg/pulsar"
)

// Long-lived fixture: a real (n=3, t=2) threshold ceremony at
// ModeP65. The dudect main loop calls pulsar_combine_ct_setup()
// once, then drives pulsar_combine_ct() with per-sample partial-sig
// bytes for the target party.
var (
	cFixtureParams    *pulsar.Params
	cFixturePub       *pulsar.PublicKey
	cFixtureMsg       []byte
	cFixtureSessionID [16]byte
	cFixtureAttempt   uint32
	cFixtureQuorum    []pulsar.NodeID
	cFixtureThreshold int
	cFixtureRound1    []*pulsar.Round1Message
	cFixtureRound2    []*pulsar.Round2Message
	cFixtureShares    []*pulsar.KeyShare
	// cFixtureTargetIdx is the index in Round2 whose PartialSig bytes
	// the dudect harness rewrites each sample.
	cFixtureTargetIdx int
	// cFixtureR2BufLen is the length of PartialSig (128 bytes per
	// the v0.1 commit-and-reveal layout in threshold.go).
	cFixtureR2BufLen int
)

//export pulsar_combine_ct_setup
//
// Build a real threshold ceremony fixture once. Returns 0 on
// success, non-zero on failure.
//
// Topology: n=3 parties, t=2 threshold, ModeP65. This is the
// smallest non-trivial threshold ceremony — keeps the dudect run
// time per sample bounded.
func pulsar_combine_ct_setup() C.int {
	params := pulsar.MustParamsFor(pulsar.ModeP65)
	n, t := 3, 2

	committee := make([]pulsar.NodeID, n)
	for i := 0; i < n; i++ {
		committee[i] = pulsar.NodeID{byte(i + 1)}
	}

	// DKG.
	dkgSessions := make([]*pulsar.DKGSession, n)
	for i := 0; i < n; i++ {
		s, err := pulsar.NewDKGSession(params, committee, t, committee[i], rand.Reader)
		if err != nil {
			return 1
		}
		dkgSessions[i] = s
	}
	r1 := make([]*pulsar.DKGRound1Msg, n)
	for i, s := range dkgSessions {
		m, err := s.Round1()
		if err != nil {
			return 2
		}
		r1[i] = m
	}
	r2 := make([]*pulsar.DKGRound2Msg, n)
	for i, s := range dkgSessions {
		m, err := s.Round2(r1)
		if err != nil {
			return 3
		}
		r2[i] = m
	}
	outputs := make([]*pulsar.DKGOutput, n)
	for i, s := range dkgSessions {
		out, err := s.Round3(r1, r2)
		if err != nil {
			return 4
		}
		outputs[i] = out
	}

	pub := outputs[0].GroupPubkey
	shares := make([]*pulsar.KeyShare, n)
	for i := range outputs {
		shares[i] = outputs[i].SecretShare
	}

	// Threshold sign.
	msg := []byte("dudect constant-time smoke: Pulsar Combine class N4")
	quorum := make([]pulsar.NodeID, t)
	for i := 0; i < t; i++ {
		quorum[i] = shares[i].NodeID
	}

	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return 5
	}
	signers := make([]*pulsar.ThresholdSigner, t)
	for i := 0; i < t; i++ {
		s, err := pulsar.NewThresholdSigner(params, sid, 1, quorum, shares[i], msg, rand.Reader)
		if err != nil {
			return 6
		}
		signers[i] = s
	}
	sr1 := make([]*pulsar.Round1Message, t)
	for i, s := range signers {
		m, err := s.Round1(msg)
		if err != nil {
			return 7
		}
		sr1[i] = m
	}
	sr2 := make([]*pulsar.Round2Message, t)
	for i, s := range signers {
		m, _, err := s.Round2(sr1)
		if err != nil {
			return 8
		}
		sr2[i] = m
	}

	// Sanity: Combine succeeds on the un-mutated tape. Without this
	// check the dudect run could silently measure the time for an
	// always-rejecting Combine path.
	if _, err := pulsar.Combine(params, pub, msg, nil, false, sid, 1, quorum, t, sr1, sr2, shares); err != nil {
		return 9
	}

	cFixtureParams = params
	cFixturePub = pub
	cFixtureMsg = msg
	cFixtureSessionID = sid
	cFixtureAttempt = 1
	cFixtureQuorum = quorum
	cFixtureThreshold = t
	cFixtureRound1 = sr1
	cFixtureRound2 = sr2
	cFixtureShares = shares
	cFixtureTargetIdx = 0
	cFixtureR2BufLen = len(sr2[0].PartialSig)
	return 0
}

//export pulsar_combine_ct_partial_size
//
// Returns the PartialSig byte length. The C harness sizes its
// per-sample buffer to this width.
func pulsar_combine_ct_partial_size() C.size_t {
	return C.size_t(cFixtureR2BufLen)
}

//export pulsar_combine_ct
//
// One dudect measurement sample.
//
// data points to partial_size bytes that overwrite Round2[target].
// PartialSig before Combine runs. Combine's return value is
// discarded — class-B random bytes will produce a commit mismatch
// and Combine returns an error; that's expected and timing-
// irrelevant.
//
// IMPORTANT: this function must NOT branch on the rewrite payload.
// The mutation is a pure copy.
func pulsar_combine_ct(data *C.uint8_t) {
	if cFixtureParams == nil {
		return
	}
	n := cFixtureR2BufLen
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), n)

	// Clone Round2 so the tape stays usable across samples. The
	// inner PartialSig slice is reallocated per sample so the rest of
	// the harness can keep the original tape pristine.
	r2 := make([]*pulsar.Round2Message, len(cFixtureRound2))
	for i, m := range cFixtureRound2 {
		r2[i] = m
	}
	mutated := *cFixtureRound2[cFixtureTargetIdx]
	mutated.PartialSig = append([]byte{}, src...)
	r2[cFixtureTargetIdx] = &mutated

	_, _ = pulsar.Combine(
		cFixtureParams,
		cFixturePub,
		cFixtureMsg,
		nil,
		false,
		cFixtureSessionID,
		cFixtureAttempt,
		cFixtureQuorum,
		cFixtureThreshold,
		cFixtureRound1,
		r2,
		cFixtureShares,
	)
}

func main() {}
