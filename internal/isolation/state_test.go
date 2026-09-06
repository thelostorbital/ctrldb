// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

func TestHarnessStateCanonicalRoundTripAndDetachedAccessors(t *testing.T) {
	t.Parallel()

	state := validPendingHarnessState(t)
	encoded, err := state.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() unexpected error: %v", err)
	}
	parsed, err := isolation.ParseHarnessStateV1(encoded)
	if err != nil {
		t.Fatalf("ParseHarnessStateV1() unexpected error: %v", err)
	}
	reencoded, err := parsed.CanonicalJSON()
	if err != nil || !bytes.Equal(encoded, reencoded) {
		t.Fatalf("canonical round trip changed bytes: error=%v", err)
	}
	if parsed.BootstrapPhase() != isolation.BootstrapPhasePending || parsed.TestUsability() != isolation.TestUsabilityUnusable ||
		parsed.EnvironmentClass() != "disposable" || parsed.IntegritySHA256() == "" {
		t.Fatal("parsed state lost its pending disposable binding")
	}
	capabilities := parsed.CleanupCapabilities()
	capabilities[0] = "changed"
	if parsed.CleanupCapabilities()[0] != isolation.CleanupComputeDisks {
		t.Fatal("CleanupCapabilities() exposed mutable state")
	}
}

func TestHarnessStateRejectsMalformedTamperedAndNoncanonicalJSON(t *testing.T) {
	t.Parallel()

	state := validPendingHarnessState(t)
	encoded, _ := state.CanonicalJSON()

	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("json.Unmarshal() unexpected error: %v", err)
	}
	tampered := cloneJSONDocument(t, document)
	tamperedState := tampered["state"].(map[string]any)
	tamperedState["projectId"] = "other-project"
	tamperedBytes, _ := json.Marshal(tampered)

	unknown := cloneJSONDocument(t, document)
	unknown["unexpected"] = true
	unknownBytes, _ := json.Marshal(unknown)

	tests := [][]byte{
		nil,
		append(append([]byte(nil), encoded...), '\n'),
		append(append([]byte(nil), encoded...), []byte(`{}`)...),
		tamperedBytes,
		unknownBytes,
		[]byte(`{"schemaVersion":"unknown"}`),
	}
	for _, input := range tests {
		if _, err := isolation.ParseHarnessStateV1(input); !errors.Is(err, isolation.ErrInvalidHarnessState) {
			t.Fatalf("ParseHarnessStateV1(%q) error = %v; want ErrInvalidHarnessState", input, err)
		}
	}
}

func TestHarnessStateFirstT8TransitionIsMonotonic(t *testing.T) {
	t.Parallel()

	pending := validPendingHarnessState(t)
	open, err := pending.OpenAfterT8(validT8Evidence(), validT8BoundaryNow())
	if err != nil {
		t.Fatalf("OpenAfterT8() unexpected error: %v", err)
	}
	if open.BootstrapPhase() != isolation.BootstrapPhaseOpen || open.TestUsability() != isolation.TestUsabilityUsable {
		t.Fatal("OpenAfterT8() did not open a usable harness")
	}
	if _, err := open.OpenAfterT8(validT8Evidence(), validT8BoundaryNow()); !errors.Is(err, isolation.ErrHarnessStateMismatch) {
		t.Fatalf("second OpenAfterT8() error = %v; want ErrHarnessStateMismatch", err)
	}

	drift := validDriftEvidence()
	drifted, err := open.MarkTestsUnusable(drift)
	if err != nil {
		t.Fatalf("MarkTestsUnusable() unexpected error: %v", err)
	}
	if drifted.BootstrapPhase() != isolation.BootstrapPhaseOpen || drifted.TestUsability() != isolation.TestUsabilityUnusable {
		t.Fatal("drift recreated the pending global bootstrap blockade")
	}

	newEvidence := validT8Evidence()
	newEvidence.ObservedAt = validHarnessStateSeed().ApprovalValidUntil.Add(time.Hour)
	newEvidence.ValidUntil = newEvidence.ObservedAt.Add(30 * time.Minute)
	newEvidence.Revision = strings.Repeat("d", 64)
	restored, err := drifted.RestoreTestsUsable(newEvidence, newEvidence.ObservedAt.Add(time.Minute))
	if err != nil || restored.BootstrapPhase() != isolation.BootstrapPhaseOpen || restored.TestUsability() != isolation.TestUsabilityUsable {
		t.Fatalf("RestoreTestsUsable() did not preserve open and restore usable: state=%v error=%v", restored.TestUsability(), err)
	}
	older := newEvidence
	older.ObservedAt = drift.DetectedAt
	older.ValidUntil = older.ObservedAt.Add(30 * time.Minute)
	if _, err := drifted.RestoreTestsUsable(older, older.ObservedAt.Add(time.Minute)); !errors.Is(err, isolation.ErrHarnessStateStale) {
		t.Fatalf("RestoreTestsUsable(older) error = %v; want ErrHarnessStateStale", err)
	}
	equalDrift := drift
	equalDrift.DetectedAt = validT8Evidence().ObservedAt
	if _, err := open.MarkTestsUnusable(equalDrift); !errors.Is(err, isolation.ErrInvalidHarnessState) {
		t.Fatalf("MarkTestsUnusable(equal T8 time) error = %v; want ErrInvalidHarnessState", err)
	}
}

func TestHarnessStateRenewsFreshT8WithoutFabricatedDrift(t *testing.T) {
	t.Parallel()

	open, err := validPendingHarnessState(t).OpenAfterT8(validT8Evidence(), validT8BoundaryNow())
	if err != nil {
		t.Fatalf("OpenAfterT8() unexpected error: %v", err)
	}
	renewal := validT8Evidence()
	renewal.Revision = strings.Repeat("9", 64)
	renewal.ObservedAt = renewal.ObservedAt.Add(20 * time.Minute)
	renewal.ValidUntil = renewal.ObservedAt.Add(30 * time.Minute)
	renewed, err := open.RenewT8(renewal, renewal.ObservedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("RenewT8() unexpected error: %v", err)
	}
	if renewed.T8ObservationRevision() != renewal.Revision || renewed.TestUsability() != isolation.TestUsabilityUsable {
		t.Fatal("RenewT8() did not preserve a usable harness with the replacement revision")
	}
	if _, err := open.RenewT8(validT8Evidence(), validT8BoundaryNow()); !errors.Is(err, isolation.ErrHarnessStateStale) {
		t.Fatalf("RenewT8(replayed evidence) error = %v; want ErrHarnessStateStale", err)
	}
	drifted, err := open.MarkTestsUnusable(validDriftEvidence())
	if err != nil {
		t.Fatalf("MarkTestsUnusable() unexpected error: %v", err)
	}
	if _, err := drifted.RenewT8(renewal, renewal.ObservedAt.Add(time.Minute)); !errors.Is(err, isolation.ErrHarnessStateMismatch) {
		t.Fatalf("RenewT8(drifted harness) error = %v; want ErrHarnessStateMismatch", err)
	}
}

func TestHarnessStateRejectsIncompleteOrBypassableBindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*isolation.HarnessStateSeed)
	}{
		{name: "cross class", mutate: func(value *isolation.HarnessStateSeed) { value.EnvironmentClass = "production" }},
		{name: "missing project", mutate: func(value *isolation.HarnessStateSeed) { value.ProjectID = "" }},
		{name: "missing manifest", mutate: func(value *isolation.HarnessStateSeed) { value.ManifestHash = "" }},
		{name: "missing generation", mutate: func(value *isolation.HarnessStateSeed) { value.ControlRecordGeneration = 0 }},
		{name: "missing resource", mutate: func(value *isolation.HarnessStateSeed) { value.Resources.Network = "" }},
		{name: "missing capability", mutate: func(value *isolation.HarnessStateSeed) { value.CleanupCapabilities = value.CleanupCapabilities[:2] }},
		{name: "unknown capability", mutate: func(value *isolation.HarnessStateSeed) { value.CleanupCapabilities[1] = "compute.snapshots" }},
		{name: "reordered capability", mutate: func(value *isolation.HarnessStateSeed) {
			value.CleanupCapabilities[0], value.CleanupCapabilities[1] = value.CleanupCapabilities[1], value.CleanupCapabilities[0]
		}},
		{name: "unsorted steps", mutate: func(value *isolation.HarnessStateSeed) { value.BootstrapSteps = []string{"step-b", "step-a"} }},
		{name: "missing rollback", mutate: func(value *isolation.HarnessStateSeed) { value.RollbackSteps = nil }},
		{name: "expired approval", mutate: func(value *isolation.HarnessStateSeed) { value.ApprovalValidUntil = value.ApprovedAt }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			seed := validHarnessStateSeed()
			test.mutate(&seed)
			if _, err := isolation.NewPendingHarnessStateV1(seed); !errors.Is(err, isolation.ErrInvalidHarnessState) {
				t.Fatalf("NewPendingHarnessStateV1() error = %v; want ErrInvalidHarnessState", err)
			}
		})
	}
}

func TestHarnessStateRejectsStaleOrInvalidT8(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*isolation.T8Evidence)
	}{
		{name: "missing revision", mutate: func(value *isolation.T8Evidence) { value.Revision = "" }},
		{name: "too long", mutate: func(value *isolation.T8Evidence) {
			value.ValidUntil = value.ObservedAt.Add(isolation.MaxT8EvidenceLifetime + time.Second)
		}},
		{name: "before approval", mutate: func(value *isolation.T8Evidence) {
			value.ObservedAt = validHarnessStateSeed().ApprovedAt.Add(-time.Second)
			value.ValidUntil = value.ObservedAt.Add(time.Minute)
		}},
		{name: "after approval", mutate: func(value *isolation.T8Evidence) {
			value.ObservedAt = validHarnessStateSeed().ApprovalValidUntil.Add(time.Second)
			value.ValidUntil = value.ObservedAt.Add(time.Minute)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			evidence := validT8Evidence()
			test.mutate(&evidence)
			if _, err := validPendingHarnessState(t).OpenAfterT8(evidence, evidence.ObservedAt); !errors.Is(err, isolation.ErrHarnessStateStale) {
				t.Fatalf("OpenAfterT8() error = %v; want ErrHarnessStateStale", err)
			}
		})
	}
}

func TestOpenAfterT8RequiresCurrentExclusiveApprovalBoundary(t *testing.T) {
	t.Parallel()

	pending := validPendingHarnessState(t)
	evidence := validT8Evidence()
	tests := []struct {
		name string
		now  time.Time
	}{
		{name: "archived evidence", now: evidence.ValidUntil},
		{name: "expired approval", now: validHarnessStateSeed().ApprovalValidUntil},
		{name: "before observation", now: evidence.ObservedAt.Add(-time.Second)},
		{name: "non UTC", now: validT8BoundaryNow().In(time.FixedZone("offset", 60))},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := pending.OpenAfterT8(evidence, test.now); !errors.Is(err, isolation.ErrHarnessStateStale) {
				t.Fatalf("OpenAfterT8() error = %v; want ErrHarnessStateStale", err)
			}
		})
	}

	deadlineEvidence := evidence
	deadlineEvidence.ObservedAt = validHarnessStateSeed().ApprovalValidUntil
	deadlineEvidence.ValidUntil = deadlineEvidence.ObservedAt.Add(time.Minute)
	if _, err := pending.OpenAfterT8(deadlineEvidence, deadlineEvidence.ObservedAt); !errors.Is(err, isolation.ErrHarnessStateStale) {
		t.Fatalf("OpenAfterT8(deadline observation) error = %v; want ErrHarnessStateStale", err)
	}
}

func TestParsedOpenStateMustRetainApprovalWindowInvariant(t *testing.T) {
	t.Parallel()

	open, err := validPendingHarnessState(t).OpenAfterT8(validT8Evidence(), validT8BoundaryNow())
	if err != nil {
		t.Fatalf("OpenAfterT8() unexpected error: %v", err)
	}
	encoded, err := open.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() unexpected error: %v", err)
	}
	type wireDocument struct {
		SchemaVersion   string          `json:"schemaVersion"`
		State           json.RawMessage `json:"state"`
		IntegritySHA256 string          `json:"integritySha256"`
	}
	var wire wireDocument
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("json.Unmarshal(wire) unexpected error: %v", err)
	}
	original := []byte(`"bootstrapOpenedAt":"` + validT8Evidence().ObservedAt.Format(time.RFC3339Nano) + `"`)
	replacement := []byte(`"bootstrapOpenedAt":"` + validHarnessStateSeed().ApprovalValidUntil.Format(time.RFC3339Nano) + `"`)
	if !bytes.Contains(wire.State, original) {
		t.Fatal("canonical state omitted the bootstrap-open timestamp")
	}
	wire.State = bytes.Replace(wire.State, original, replacement, 1)
	digest := sha256.Sum256(wire.State)
	wire.IntegritySHA256 = hex.EncodeToString(digest[:])
	forged, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal(wire) unexpected error: %v", err)
	}
	if _, err := isolation.ParseHarnessStateV1(forged); !errors.Is(err, isolation.ErrInvalidHarnessState) {
		t.Fatalf("ParseHarnessStateV1(forged approval) error = %v; want ErrInvalidHarnessState", err)
	}
}

func validPendingHarnessState(t *testing.T) isolation.HarnessStateV1 {
	t.Helper()
	state, err := isolation.NewPendingHarnessStateV1(validHarnessStateSeed())
	if err != nil {
		t.Fatalf("NewPendingHarnessStateV1() unexpected error: %v", err)
	}
	return state
}

func validHarnessStateSeed() isolation.HarnessStateSeed {
	approvedAt := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	return isolation.HarnessStateSeed{
		ProjectID: "example-test-project", Environment: "disposable-test", EnvironmentClass: "disposable",
		ManifestHash: strings.Repeat("a", 64),
		ApprovedPlan: isolation.PlanIdentity{ID: "plan-0123456789abcdef", Hash: strings.Repeat("b", 64)},
		OperationID:  "op-0123456789abcdef", BootstrapEnvelopeHash: strings.Repeat("c", 64),
		ControlRecordGeneration: 1,
		Resources: isolation.HarnessResourceFingerprints{
			Network: strings.Repeat("1", 64), RoleBindings: strings.Repeat("2", 64),
			ServiceAccounts: strings.Repeat("3", 64), WipeJob: strings.Repeat("4", 64),
			Scheduler: strings.Repeat("5", 64), Image: strings.Repeat("6", 64),
		},
		CleanupCapabilities: isolation.InitialCleanupCapabilities(),
		BootstrapSteps:      []string{"create-audit", "create-network", "run-t8"},
		RollbackSteps:       []string{"rollback-network"},
		ApprovedAt:          approvedAt, ApprovalValidUntil: approvedAt.Add(2 * time.Hour),
	}
}

func validT8Evidence() isolation.T8Evidence {
	observedAt := time.Date(2026, 9, 6, 11, 0, 0, 0, time.UTC)
	return isolation.T8Evidence{Revision: strings.Repeat("7", 64), ObservedAt: observedAt, ValidUntil: observedAt.Add(30 * time.Minute)}
}

func validT8BoundaryNow() time.Time {
	return validT8Evidence().ObservedAt.Add(time.Minute)
}

func validDriftEvidence() isolation.HarnessDriftEvidence {
	return isolation.HarnessDriftEvidence{
		Revision: strings.Repeat("8", 64), DetectedAt: validT8Evidence().ObservedAt.Add(5 * time.Minute),
	}
}

func cloneJSONDocument(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatalf("json.Unmarshal() unexpected error: %v", err)
	}
	return result
}
