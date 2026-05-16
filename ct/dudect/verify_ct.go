// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// verify_ct.go — cgo bridge exposing pulsar.Verify to the C dudect
// harness in dudect_verify.c.
//
// The bridge owns ONE long-lived test fixture (public key + valid
// signature on a fixed message). dudect drives a fixed-vs-random
// classification on the signature bytes; the harness mutates a
// caller-supplied scratch buffer that is fed into Verify. Verify is
// expected to be constant-time over all of (pk, message, signature),
// because the underlying FIPS 204 verifier is constant-time by
// design (FIPS 204 §6.3) and pulsar.Verify is a thin dispatch on
// top (verify.go — Class N1 manifesto).
//
// The harness deliberately calls VerifyCtx with the EXACT same byte
// lengths every time, regardless of class — so any timing difference
// dudect detects is real bit-level dependence, not control-flow
// dependence on input length / structure.
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libpulsar_verify.dylib ./verify_ct.go
//
// On Linux the output extension is .so; the Makefile selects the right
// one for the host platform.

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

// Long-lived fixture. The dudect main loop calls
// pulsar_verify_ct_setup() once at startup, then calls
// pulsar_verify_ct() in a tight measurement loop.
var (
	fixtureParams *pulsar.Params
	fixturePub    *pulsar.PublicKey
	fixtureMsg    []byte
	fixtureSig    *pulsar.Signature
)

//export pulsar_verify_ct_setup
//
// Initialise the long-lived fixture. Returns 0 on success, non-zero
// on failure. Must be called once before pulsar_verify_ct.
//
// We use ModeP65 (the Lux consensus production target, see
// params.go). The fixture pk/signature are freshly generated under
// crypto/rand so the dudect run is not deterministic across launches
// — that's intentional: the timing property must hold for ANY valid
// (pk, msg, sig) triple, not a single hardcoded test vector.
func pulsar_verify_ct_setup() C.int {
	params := pulsar.MustParamsFor(pulsar.ModeP65)
	sk, err := pulsar.GenerateKey(params, rand.Reader)
	if err != nil {
		return 1
	}
	msg := []byte("dudect constant-time smoke message: Pulsar Verify class N1")
	sig, err := pulsar.Sign(params, sk, msg, nil, true, rand.Reader)
	if err != nil {
		return 2
	}
	// Sanity round-trip: any failure here means the fixture itself
	// is broken before dudect starts measuring.
	if err := pulsar.Verify(params, sk.Pub, msg, sig); err != nil {
		return 3
	}
	fixtureParams = params
	fixturePub = sk.Pub
	fixtureMsg = msg
	fixtureSig = sig
	return 0
}

//export pulsar_verify_ct_sig_size
//
// Returns the FIPS 204 signature size for the configured mode. The
// C harness uses this to size its per-sample scratch buffer to the
// exact wire width Verify expects.
func pulsar_verify_ct_sig_size() C.size_t {
	if fixtureParams == nil {
		return 0
	}
	return C.size_t(fixtureParams.SignatureSize)
}

//export pulsar_verify_ct
//
// One dudect measurement sample.
//
// data points to sig_size bytes of caller-controlled signature bytes
// (one dudect "class" picks fixed bytes, the other picks random
// bytes; that classification happens in the C harness). The bridge
// constructs a *Signature wrapping those bytes and calls
// pulsar.Verify; the return value is ignored (Verify returns an
// error for class-B random bytes; that's expected and irrelevant —
// we measure cycles, not result).
//
// The function MUST be branchless on data — any data-dependent
// branch we introduce here pollutes the measurement before Verify
// even starts. We only copy data into a fresh slice and dispatch.
func pulsar_verify_ct(data *C.uint8_t) {
	if fixtureParams == nil {
		return
	}
	n := fixtureParams.SignatureSize
	sigBytes := unsafe.Slice((*byte)(unsafe.Pointer(data)), n)
	sig := &pulsar.Signature{
		Mode:  fixtureParams.Mode,
		Bytes: append([]byte{}, sigBytes...),
	}
	// Return value deliberately unused. dudect measures the elapsed
	// cycles regardless of pass/fail. We must not branch on the
	// return value, or the C harness would see a control-flow
	// difference that is OUR fault, not Verify's.
	_ = pulsar.Verify(fixtureParams, fixturePub, fixtureMsg, sig)
}

// main is required for `go build -buildmode=c-shared`.
func main() {}
