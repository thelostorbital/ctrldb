// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestEnvelopeSealParseRoundTripIsCanonical(t *testing.T) {
	t.Parallel()
	envelope := fixtureEnvelope(t)
	encoded, err := envelope.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error: %v", err)
	}
	parsed, err := ParseBootstrapEnvelope(encoded)
	if err != nil {
		t.Fatalf("ParseBootstrapEnvelope() error: %v", err)
	}
	reencoded, err := parsed.CanonicalJSON()
	if err != nil || !bytes.Equal(reencoded, encoded) || parsed.SHA256() != envelope.SHA256() {
		t.Fatalf("round trip changed the envelope (err=%v)", err)
	}
	if parsed.OperationID() != fixtureOperationID || parsed.AuditBucket() == parsed.ControlBucket() ||
		parsed.AuditBucketLocation() != fixtureRegion || parsed.Plan().DocumentHash() != envelope.Plan().DocumentHash() ||
		parsed.FirstJournalEntry().Sequence != 1 || !strings.HasPrefix(parsed.FirstJournalObjectName().String(), "operations/disposable-test/"+fixtureOperationID+"/steps/00000000000000000001-state-discover.json") {
		t.Fatalf("parsed accessors = %#v", parsed.payload)
	}
	observations := parsed.ExpectedObservations()
	if len(observations) != len(parsed.Plan().DesiredResources()) {
		t.Fatalf("expected observations = %d", len(observations))
	}
	for _, observation := range observations {
		if observation.Expectation != ExpectationAbsent || observation.ProviderID == "" {
			t.Fatalf("observation = %#v", observation)
		}
	}
	// Second seal of the identical seed reproduces the identical hash.
	again, err := SealBootstrapEnvelope(fixtureSeed(t))
	if err != nil || again.SHA256() != envelope.SHA256() {
		t.Fatalf("seal is not deterministic (err=%v)", err)
	}
	// No credential-shaped field names or provider output are present.
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"token", "password", "secret", "authorization", "selflink", "argv", "command\"", "gcloud"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("envelope contains forbidden material %q", forbidden)
		}
	}
}

func TestEnvelopeParseRejectsTamperingAndAmbiguity(t *testing.T) {
	t.Parallel()
	envelope := fixtureEnvelope(t)
	encoded, _ := envelope.CanonicalJSON()

	flipped := append([]byte(nil), encoded...)
	index := bytes.Index(flipped, []byte(`"auditBucket":"`)) + len(`"auditBucket":"`)
	flipped[index] ^= 0x01
	hashIndex := bytes.LastIndex(encoded, []byte(`"envelopeSha256":"`)) + len(`"envelopeSha256":"`)
	hashFlipped := append([]byte(nil), encoded...)
	if hashFlipped[hashIndex] == '0' {
		hashFlipped[hashIndex] = '1'
	} else {
		hashFlipped[hashIndex] = '0'
	}
	duplicate := bytes.Replace(encoded, []byte(`"envelope":{`), []byte(`"envelope":{"workflowId":"WF-TEST-01",`), 1)
	unknown := bytes.Replace(encoded, []byte(`"schemaVersion":`), []byte(`"extra":1,"schemaVersion":`), 1)
	spaced := bytes.Replace(encoded, []byte(`"schemaVersion":`), []byte(`"schemaVersion": `), 1)
	tests := map[string][]byte{
		"empty": nil, "null": []byte("null"), "trailing": append(append([]byte(nil), encoded...), '\n', '{', '}'),
		"payload byte flipped": flipped, "hash flipped": hashFlipped, "duplicate key": duplicate,
		"unknown field": unknown, "noncanonical whitespace": spaced, "oversized": bytes.Repeat([]byte("["), MaxEnvelopeBytes+1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseBootstrapEnvelope(input); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("ParseBootstrapEnvelope() error = %v, want ErrInvalidEnvelope", err)
			}
		})
	}
}

func TestEnvelopeSealRejectsCrossBindingFailures(t *testing.T) {
	t.Parallel()
	base := fixtureSeed(t)
	tests := []struct {
		name   string
		mutate func(seed *EnvelopeSeed)
		want   error
	}{
		{"operation id", func(seed *EnvelopeSeed) { seed.OperationID = "op-XYZ" }, ErrInvalidEnvelope},
		{"journal operation mismatch", func(seed *EnvelopeSeed) { seed.FirstJournalEntry.OperationID = "op-fedcba9876543210" }, ErrInvalidEnvelope},
		{"journal contract mismatch", func(seed *EnvelopeSeed) { seed.FirstJournalEntry.ContractHash = repeatHex("b") }, ErrInvalidEnvelope},
		{"journal not first", func(seed *EnvelopeSeed) { seed.FirstJournalEntry.Sequence = 2 }, ErrInvalidEnvelope},
		{"journal not discover", func(seed *EnvelopeSeed) { seed.FirstJournalEntry.OperationState = domain.OperationValidate }, ErrInvalidEnvelope},
		{"journal after seal", func(seed *EnvelopeSeed) { seed.FirstJournalEntry.RecordedAt = seed.SealedAt.Add(time.Second) }, ErrInvalidEnvelope},
		{"seal before plan", func(seed *EnvelopeSeed) { seed.SealedAt = fixtureNow.Add(-time.Second) }, ErrInvalidEnvelope},
		{"seal after approval expiry", func(seed *EnvelopeSeed) { seed.SealedAt = seed.Approval.ValidUntil }, ErrInvalidEnvelope},
		{"seal not UTC", func(seed *EnvelopeSeed) { seed.SealedAt = seed.SealedAt.In(time.FixedZone("X", 3600)) }, ErrInvalidEnvelope},
		{"approval plan hash", func(seed *EnvelopeSeed) { seed.Approval.PlanV1Hash = repeatHex("c") }, ErrInvalidApprovalProof},
		{"approval document hash", func(seed *EnvelopeSeed) { seed.Approval.PlanDocumentSHA256 = repeatHex("c") }, ErrInvalidApprovalProof},
		{"approval account", func(seed *EnvelopeSeed) { seed.Approval.ApprovedBy = "other@example.invalid" }, ErrInvalidApprovalProof},
		{"approval class", func(seed *EnvelopeSeed) { seed.Approval.ApprovalClass = domain.ApprovalRead }, ErrInvalidApprovalProof},
		{"approval proof hash", func(seed *EnvelopeSeed) { seed.Approval.ProofSHA256 = repeatHex("d") }, ErrInvalidApprovalProof},
		{"approval after plan expiry", func(seed *EnvelopeSeed) { seed.Approval.ValidUntil = fixtureNow.Add(2 * time.Hour) }, ErrInvalidApprovalProof},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			seed := base
			test.mutate(&seed)
			if _, err := SealBootstrapEnvelope(seed); !errors.Is(err, test.want) {
				t.Fatalf("SealBootstrapEnvelope() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewApprovalProofRejectsWindowsOutsidePlan(t *testing.T) {
	t.Parallel()
	plan := fixturePlan(t)
	if _, err := NewApprovalProof(plan, fixtureAccount, fixtureNow.Add(-time.Second), fixtureNow.Add(time.Minute)); !errors.Is(err, ErrInvalidApprovalProof) {
		t.Fatalf("approval before plan creation accepted: %v", err)
	}
	if _, err := NewApprovalProof(plan, "someone-else@example.invalid", fixtureNow, fixtureNow.Add(time.Minute)); !errors.Is(err, ErrInvalidApprovalProof) {
		t.Fatalf("approval by a non-principal accepted: %v", err)
	}
	proof, err := NewApprovalProof(plan, fixtureAccount, fixtureNow, fixtureNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewApprovalProof() error: %v", err)
	}
	encoded, _ := json.Marshal(proof)
	if !strings.Contains(string(encoded), `"approvalClass":"security-sensitive"`) && !strings.Contains(string(encoded), `"approvalClass":"`) {
		t.Fatalf("approval encoding = %s", encoded)
	}
}
