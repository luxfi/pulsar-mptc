// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// abort.go — identifiable-abort complaints.
//
// Every detected deviation in DKG, Sign, or Reshare produces a signed
// AbortEvidence. The system-model slashing layer consumes these
// complaints; a quorum of distinct accusers against the same accused
// is a disqualification event.
//
// pulsar.tex §4.5 enumerates the complaint taxonomy. This file
// gives the canonical wire format and the verification routines that
// any third party (chain validator, audit observer, slashing module)
// uses to check a complaint is well-formed.

import (
	"encoding/binary"
	"errors"
)

// Errors returned by abort-evidence verification.
var (
	ErrInvalidComplaint = errors.New("pulsar: complaint structure invalid")
	ErrComplaintSelfAcc = errors.New("pulsar: complaint accuser equals accused")
	ErrComplaintNoSig   = errors.New("pulsar: complaint missing accuser signature")
	ErrComplaintKind    = errors.New("pulsar: complaint kind out of range")
	ErrComplaintNoEv    = errors.New("pulsar: complaint missing evidence blob")
)

// AbortSignatureVerifier is the pluggable identity-layer signature
// verifier. Third parties (chain validators, audit observers, slashing
// modules) call VerifyAbortEvidence with an instance that wraps their
// production identity-key scheme (Ed25519, hybrid PQ, BLS, etc.).
//
// `transcript` is the canonical to-be-signed bytes returned by
// TranscriptForComplaint(e). `signature` is e.Signature. `accuser` is
// e.Accuser — the verifier looks up the accuser's public identity key
// in its own validator-set record and runs the underlying scheme's
// verify.
//
// Return true iff the signature is valid AND the accuser's identity is
// known to the verifier (i.e., the accuser is a registered party at
// the complained-about epoch). A nil verifier check is rejected by
// VerifyAbortEvidence via ErrComplaintNoSig — there is no implicit
// "skip signature verification" path.
type AbortSignatureVerifier interface {
	VerifyAbortSignature(accuser NodeID, transcript, signature []byte) bool
}

// MarshalAbortEvidence serialises an AbortEvidence to its canonical
// wire form. Layout:
//
//   1 byte    kind
//   32 bytes  accuser NodeID
//   32 bytes  accused NodeID
//   8 bytes   epoch (big-endian uint64)
//   4 bytes   evidence length (big-endian uint32)
//   N bytes   evidence
//   4 bytes   signature length (big-endian uint32)
//   M bytes   signature
//
// Wire-stable across versions; new ComplaintKind values append to
// the kind table but do not shift existing field offsets.
func MarshalAbortEvidence(e *AbortEvidence) ([]byte, error) {
	if e == nil {
		return nil, ErrInvalidComplaint
	}
	if e.Accuser == e.Accused {
		return nil, ErrComplaintSelfAcc
	}
	buf := make([]byte, 0, 1+32+32+8+4+len(e.Evidence)+4+len(e.Signature))
	buf = append(buf, byte(e.Kind))
	buf = append(buf, e.Accuser[:]...)
	buf = append(buf, e.Accused[:]...)
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], e.Epoch)
	buf = append(buf, epochBuf[:]...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(e.Evidence)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, e.Evidence...)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(e.Signature)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, e.Signature...)
	return buf, nil
}

// UnmarshalAbortEvidence parses canonical wire bytes into an
// AbortEvidence. Returns ErrInvalidComplaint on any structural
// failure (truncated buffer, oversize length fields).
func UnmarshalAbortEvidence(buf []byte) (*AbortEvidence, error) {
	if len(buf) < 1+32+32+8+4+0+4 {
		return nil, ErrInvalidComplaint
	}
	e := &AbortEvidence{}
	off := 0
	e.Kind = ComplaintKind(buf[off])
	off += 1
	copy(e.Accuser[:], buf[off:off+32])
	off += 32
	copy(e.Accused[:], buf[off:off+32])
	off += 32
	e.Epoch = binary.BigEndian.Uint64(buf[off : off+8])
	off += 8
	evLen := binary.BigEndian.Uint32(buf[off : off+4])
	off += 4
	if int(evLen) > len(buf)-off-4 {
		return nil, ErrInvalidComplaint
	}
	e.Evidence = append([]byte{}, buf[off:off+int(evLen)]...)
	off += int(evLen)
	sigLen := binary.BigEndian.Uint32(buf[off : off+4])
	off += 4
	if int(sigLen) > len(buf)-off {
		return nil, ErrInvalidComplaint
	}
	e.Signature = append([]byte{}, buf[off:off+int(sigLen)]...)
	if e.Accuser == e.Accused {
		return nil, ErrComplaintSelfAcc
	}
	return e, nil
}

// transcriptForComplaint returns the canonical transcript hash that
// the accuser's long-term identity key signs over. The accuser's
// signature is what makes the complaint a slashing-eligible artifact.
//
// transcriptForComplaint is the byte string passed to the identity-
// key signer (e.g. Ed25519); the chain's slashing module verifies the
// signature against the accuser's published identity key in the
// validator-set record.
func transcriptForComplaint(e *AbortEvidence) []byte {
	parts := [][]byte{
		[]byte{byte(e.Kind)},
		e.Accuser[:],
		e.Accused[:],
	}
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], e.Epoch)
	parts = append(parts, epochBuf[:])
	parts = append(parts, e.Evidence)
	out := []byte{}
	out = append(out, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, encodeString(p)...)
	}
	return out
}

// TranscriptForComplaint is the public counterpart to
// transcriptForComplaint, exposed so that callers can pre-compute the
// to-be-signed bytes when constructing a complaint outside this
// package (the package does not sign — identity-key signing happens
// in the consumer's chain-specific identity layer).
func TranscriptForComplaint(e *AbortEvidence) []byte {
	return transcriptForComplaint(e)
}

// VerifyAbortEvidenceForm performs the third-party-verifiable
// STRUCTURAL well-formedness check on an AbortEvidence (Agent 4 H1
// closure). Independent of any signature scheme.
//
// Checks:
//   - e is non-nil.
//   - accuser != accused.
//   - kind is in the registered ComplaintKind range (1..N).
//   - evidence blob is non-empty (kind-specific structural validation
//     of the blob is the consumer's responsibility; the form check
//     only ensures the blob is present).
//   - signature is non-empty.
//
// Returns the first matching error, or nil if all structural checks
// pass. Third-party verifiers should call this BEFORE attempting
// signature verification — a well-formed transcript depends on the
// form being valid first.
func VerifyAbortEvidenceForm(e *AbortEvidence) error {
	if e == nil {
		return ErrInvalidComplaint
	}
	if e.Accuser == e.Accused {
		return ErrComplaintSelfAcc
	}
	switch e.Kind {
	case ComplaintEquivocation, ComplaintBadDelivery,
		ComplaintMACFailure, ComplaintRangeFailure:
		// known kind
	default:
		return ErrComplaintKind
	}
	if len(e.Evidence) == 0 {
		return ErrComplaintNoEv
	}
	if len(e.Signature) == 0 {
		return ErrComplaintNoSig
	}
	return nil
}

// VerifyAbortEvidence performs the FULL third-party verification of an
// AbortEvidence (Agent 4 H1 closure):
//
//  1. Structural well-formedness via VerifyAbortEvidenceForm.
//  2. Identity-layer signature check via the supplied verifier.
//
// The verifier MUST be non-nil — the package does not provide a
// default "skip signature" path. Returns ErrComplaintNoSig if the
// supplied verifier rejects the signature (i.e., the accuser's
// identity is not on file or the signature is forged).
//
// Pure form validation is available standalone via
// VerifyAbortEvidenceForm.
func VerifyAbortEvidence(e *AbortEvidence, v AbortSignatureVerifier) error {
	if err := VerifyAbortEvidenceForm(e); err != nil {
		return err
	}
	if v == nil {
		return ErrComplaintNoSig
	}
	if !v.VerifyAbortSignature(e.Accuser, TranscriptForComplaint(e), e.Signature) {
		return ErrComplaintNoSig
	}
	return nil
}
