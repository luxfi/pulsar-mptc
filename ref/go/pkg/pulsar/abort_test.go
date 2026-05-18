// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"testing"
)

func TestAbortEvidence_RoundTrip(t *testing.T) {
	original := &AbortEvidence{
		Kind:      ComplaintEquivocation,
		Accuser:   NodeID{1, 2, 3},
		Accused:   NodeID{4, 5, 6},
		Epoch:     42,
		Evidence:  []byte("some-evidence-blob"),
		Signature: []byte("identity-key-signature"),
	}
	wire, err := MarshalAbortEvidence(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalAbortEvidence(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != original.Kind {
		t.Fatalf("Kind mismatch")
	}
	if got.Accuser != original.Accuser {
		t.Fatalf("Accuser mismatch")
	}
	if got.Accused != original.Accused {
		t.Fatalf("Accused mismatch")
	}
	if got.Epoch != original.Epoch {
		t.Fatalf("Epoch mismatch")
	}
	if !bytes.Equal(got.Evidence, original.Evidence) {
		t.Fatalf("Evidence mismatch")
	}
	if !bytes.Equal(got.Signature, original.Signature) {
		t.Fatalf("Signature mismatch")
	}
}

func TestAbortEvidence_RejectsSelfAccusation(t *testing.T) {
	e := &AbortEvidence{
		Kind:    ComplaintEquivocation,
		Accuser: NodeID{1},
		Accused: NodeID{1},
	}
	if _, err := MarshalAbortEvidence(e); err != ErrComplaintSelfAcc {
		t.Fatalf("self-accusation not rejected: %v", err)
	}
}

func TestAbortEvidence_RejectsTruncated(t *testing.T) {
	if _, err := UnmarshalAbortEvidence([]byte{0x01}); err != ErrInvalidComplaint {
		t.Fatalf("truncated bytes not rejected: %v", err)
	}
}

func TestAbortEvidence_Nil(t *testing.T) {
	if _, err := MarshalAbortEvidence(nil); err != ErrInvalidComplaint {
		t.Fatalf("nil evidence not rejected: %v", err)
	}
}

func TestAbortEvidence_TranscriptStable(t *testing.T) {
	e := &AbortEvidence{
		Kind:     ComplaintBadDelivery,
		Accuser:  NodeID{1},
		Accused:  NodeID{2},
		Epoch:    7,
		Evidence: []byte("evidence"),
	}
	t1 := TranscriptForComplaint(e)
	t2 := TranscriptForComplaint(e)
	if !bytes.Equal(t1, t2) {
		t.Fatalf("transcript not deterministic")
	}
	if len(t1) == 0 {
		t.Fatalf("empty transcript")
	}
}

// stubVerifier is a deterministic AbortSignatureVerifier for tests:
// it accepts iff the signature equals a fixed prefix of the transcript.
type stubVerifier struct {
	acceptPrefix []byte
}

func (s *stubVerifier) VerifyAbortSignature(_ NodeID, transcript, signature []byte) bool {
	if len(signature) > len(transcript) {
		return false
	}
	if !bytes.HasPrefix(transcript, signature) {
		return false
	}
	if !bytes.Equal(signature[:len(s.acceptPrefix)], s.acceptPrefix) {
		return false
	}
	return true
}

func TestVerifyAbortEvidenceForm_HappyPath(t *testing.T) {
	e := &AbortEvidence{
		Kind:      ComplaintBadDelivery,
		Accuser:   NodeID{1},
		Accused:   NodeID{2},
		Epoch:     1,
		Evidence:  []byte("evidence"),
		Signature: []byte("sig"),
	}
	if err := VerifyAbortEvidenceForm(e); err != nil {
		t.Fatalf("form check rejected valid evidence: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsNil(t *testing.T) {
	if err := VerifyAbortEvidenceForm(nil); err != ErrInvalidComplaint {
		t.Fatalf("nil not rejected: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsSelfAcc(t *testing.T) {
	e := &AbortEvidence{Kind: ComplaintEquivocation, Accuser: NodeID{1}, Accused: NodeID{1},
		Evidence: []byte("x"), Signature: []byte("y")}
	if err := VerifyAbortEvidenceForm(e); err != ErrComplaintSelfAcc {
		t.Fatalf("self-acc not rejected: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsBadKind(t *testing.T) {
	e := &AbortEvidence{Kind: ComplaintKind(99), Accuser: NodeID{1}, Accused: NodeID{2},
		Evidence: []byte("x"), Signature: []byte("y")}
	if err := VerifyAbortEvidenceForm(e); err != ErrComplaintKind {
		t.Fatalf("bad kind not rejected: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsNoEvidence(t *testing.T) {
	e := &AbortEvidence{Kind: ComplaintEquivocation, Accuser: NodeID{1}, Accused: NodeID{2},
		Signature: []byte("sig")}
	if err := VerifyAbortEvidenceForm(e); err != ErrComplaintNoEv {
		t.Fatalf("empty evidence not rejected: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsNoSignature(t *testing.T) {
	e := &AbortEvidence{Kind: ComplaintEquivocation, Accuser: NodeID{1}, Accused: NodeID{2},
		Evidence: []byte("x")}
	if err := VerifyAbortEvidenceForm(e); err != ErrComplaintNoSig {
		t.Fatalf("empty signature not rejected: %v", err)
	}
}

func TestVerifyAbortEvidence_HappyPath(t *testing.T) {
	e := &AbortEvidence{
		Kind:     ComplaintBadDelivery,
		Accuser:  NodeID{1},
		Accused:  NodeID{2},
		Epoch:    1,
		Evidence: []byte("ev"),
	}
	// sign := first 4 bytes of transcript
	transcript := TranscriptForComplaint(e)
	e.Signature = append([]byte{}, transcript[:4]...)
	v := &stubVerifier{acceptPrefix: transcript[:4]}
	if err := VerifyAbortEvidence(e, v); err != nil {
		t.Fatalf("verify rejected valid: %v", err)
	}
}

func TestVerifyAbortEvidence_RejectsBadSignature(t *testing.T) {
	e := &AbortEvidence{
		Kind:      ComplaintBadDelivery,
		Accuser:   NodeID{1},
		Accused:   NodeID{2},
		Epoch:     1,
		Evidence:  []byte("ev"),
		Signature: []byte("forged"),
	}
	transcript := TranscriptForComplaint(e)
	// stub accepts only signatures that PREFIX the transcript;
	// "forged" does not match transcript[:6] in general
	v := &stubVerifier{acceptPrefix: transcript[:1]}
	err := VerifyAbortEvidence(e, v)
	if err != ErrComplaintNoSig {
		t.Fatalf("forged signature not rejected: %v", err)
	}
}

func TestVerifyAbortEvidence_RejectsNilVerifier(t *testing.T) {
	e := &AbortEvidence{
		Kind:      ComplaintBadDelivery,
		Accuser:   NodeID{1},
		Accused:   NodeID{2},
		Epoch:     1,
		Evidence:  []byte("ev"),
		Signature: []byte("sig"),
	}
	if err := VerifyAbortEvidence(e, nil); err != ErrComplaintNoSig {
		t.Fatalf("nil verifier not rejected: %v", err)
	}
}

func TestComplaintKind_String(t *testing.T) {
	for _, tc := range []struct {
		k    ComplaintKind
		want string
	}{
		{ComplaintEquivocation, "equivocation"},
		{ComplaintBadDelivery, "bad-delivery"},
		{ComplaintMACFailure, "mac-failure"},
		{ComplaintRangeFailure, "range-failure"},
		{ComplaintKind(99), "unknown"},
	} {
		if got := tc.k.String(); got != tc.want {
			t.Fatalf("kind %d: got %q want %q", tc.k, got, tc.want)
		}
	}
}
