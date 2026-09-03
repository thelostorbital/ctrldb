// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

func TestJournalEntryEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	want := validStepEntry()
	encoded, err := workflow.EncodeJournalEntry(want)
	if err != nil {
		t.Fatalf("EncodeJournalEntry() returned an error: %v", err)
	}
	got, err := workflow.DecodeJournalEntry(encoded)
	if err != nil {
		t.Fatalf("DecodeJournalEntry() returned an error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded entry = %#v, want %#v", got, want)
	}
}

func TestJournalEntryDecodeResanitizesResult(t *testing.T) {
	t.Parallel()

	encoded, err := workflow.EncodeJournalEntry(validStepEntry())
	if err != nil {
		t.Fatalf("EncodeJournalEntry() returned an error: %v", err)
	}
	encoded = bytes.Replace(
		encoded,
		[]byte(`"resultSummary":"healthy"`),
		[]byte(`"resultSummary":"password=SECRET_MARKER_JOURNAL"`),
		1,
	)

	decoded, err := workflow.DecodeJournalEntry(encoded)
	if err != nil {
		t.Fatalf("DecodeJournalEntry() returned an error: %v", err)
	}
	if got := decoded.Step.ResultSummary.String(); got != "password=[redacted]" {
		t.Fatalf("result summary = %q, want redacted text", got)
	}
}

func TestJournalEntryDecodeRejectsOpenOrMalformedJSON(t *testing.T) {
	t.Parallel()

	encoded, err := workflow.EncodeJournalEntry(validStepEntry())
	if err != nil {
		t.Fatalf("EncodeJournalEntry() returned an error: %v", err)
	}
	tests := map[string][]byte{
		"unknown top-level field": bytes.Replace(encoded, []byte(`{"schema"`), []byte(`{"extra":true,"schema"`), 1),
		"unknown nested field": bytes.Replace(
			encoded,
			[]byte(`"step":{"id"`),
			[]byte(`"step":{"extra":true,"id"`),
			1,
		),
		"trailing value": append(append([]byte(nil), encoded...), []byte(` {}`)...),
		"malformed":      []byte(`{"schema":`),
	}

	for name, input := range tests {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := workflow.DecodeJournalEntry(input); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
				t.Fatalf("DecodeJournalEntry() error = %v", err)
			}
		})
	}
}

func TestJournalEntryValidationRejectsUnsafeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*domain.JournalEntry)
	}{
		{name: "schema", mutate: func(entry *domain.JournalEntry) { entry.Schema = "JournalEntryV2" }},
		{name: "operation id", mutate: func(entry *domain.JournalEntry) { entry.OperationID = "operation-1" }},
		{name: "plan id", mutate: func(entry *domain.JournalEntry) { entry.PlanID = "plan-production" }},
		{name: "sequence", mutate: func(entry *domain.JournalEntry) { entry.Sequence = 0 }},
		{name: "kind", mutate: func(entry *domain.JournalEntry) { entry.Kind = "event" }},
		{name: "recorded time", mutate: func(entry *domain.JournalEntry) { entry.RecordedAt = time.Time{} }},
		{name: "recorded time zone", mutate: func(entry *domain.JournalEntry) {
			entry.RecordedAt = time.Date(2026, 9, 3, 12, 0, 3, 0, time.FixedZone("offset", 3600))
		}},
		{name: "operation state", mutate: func(entry *domain.JournalEntry) { entry.OperationState = "RUNNING" }},
		{name: "missing step", mutate: func(entry *domain.JournalEntry) { entry.Step = nil }},
		{name: "step id", mutate: func(entry *domain.JournalEntry) { entry.Step.ID = "unsafe/id" }},
		{name: "outcome", mutate: func(entry *domain.JournalEntry) { entry.Step.Outcome = "RUNNING" }},
		{name: "identity", mutate: func(entry *domain.JournalEntry) { entry.Step.ExecutingIdentity = "root" }},
		{name: "attempt", mutate: func(entry *domain.JournalEntry) { entry.Step.Attempt = 0 }},
		{name: "started time", mutate: func(entry *domain.JournalEntry) { entry.Step.StartedAt = time.Time{} }},
		{name: "started time zone", mutate: func(entry *domain.JournalEntry) {
			entry.Step.StartedAt = time.Date(2026, 9, 3, 12, 0, 1, 0, time.FixedZone("offset", 3600))
		}},
		{name: "recorded before start", mutate: func(entry *domain.JournalEntry) {
			entry.RecordedAt = entry.Step.StartedAt.Add(-time.Second)
		}},
		{name: "missing end", mutate: func(entry *domain.JournalEntry) { entry.Step.EndedAt = nil }},
		{name: "zero end", mutate: func(entry *domain.JournalEntry) {
			value := time.Time{}
			entry.Step.EndedAt = &value
		}},
		{name: "end time zone", mutate: func(entry *domain.JournalEntry) {
			value := time.Date(2026, 9, 3, 12, 0, 2, 0, time.FixedZone("offset", 3600))
			entry.Step.EndedAt = &value
		}},
		{name: "end before start", mutate: func(entry *domain.JournalEntry) {
			value := entry.Step.StartedAt.Add(-time.Second)
			entry.Step.EndedAt = &value
		}},
		{name: "recorded before end", mutate: func(entry *domain.JournalEntry) {
			entry.RecordedAt = entry.Step.EndedAt.Add(-time.Nanosecond)
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			entry := validStepEntry()
			test.mutate(&entry)
			if err := workflow.ValidateJournalEntry(entry); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
				t.Fatalf("ValidateJournalEntry() error = %v", err)
			}
			if _, err := workflow.EncodeJournalEntry(entry); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
				t.Fatalf("EncodeJournalEntry() error = %v", err)
			}
		})
	}
}

func TestJournalTransitionForbidsStep(t *testing.T) {
	t.Parallel()

	entry := validTransitionEntry(1, domain.OperationDiscover)
	entry.Step = validStepEntry().Step
	if err := workflow.ValidateJournalEntry(entry); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("ValidateJournalEntry() error = %v", err)
	}
}

func TestJournalUnknownStepMayHaveNoEnd(t *testing.T) {
	t.Parallel()

	entry := validStepEntry()
	entry.Step.Outcome = domain.StepUnknown
	entry.Step.EndedAt = nil
	if err := workflow.ValidateJournalEntry(entry); err != nil {
		t.Fatalf("ValidateJournalEntry() returned an error: %v", err)
	}
}

func TestJournalValidatesCompleteHistory(t *testing.T) {
	t.Parallel()

	entries := validJournal()
	if err := workflow.ValidateJournal(entries); err != nil {
		t.Fatalf("ValidateJournal() returned an error: %v", err)
	}
}

func TestJournalRejectsInconsistentHistory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func([]domain.JournalEntry) []domain.JournalEntry
	}{
		{name: "empty", mutate: func([]domain.JournalEntry) []domain.JournalEntry { return nil }},
		{name: "invalid entry", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[2].Schema = "JournalEntryV2"
			return entries
		}},
		{name: "sequence gap", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[2].Sequence++
			return entries
		}},
		{name: "operation change", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[2].OperationID = "op-fedcba9876543210"
			return entries
		}},
		{name: "plan change", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[2].PlanID = "plan-fedcba9876543210"
			return entries
		}},
		{name: "time reversal", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[2].RecordedAt = entries[1].RecordedAt.Add(-time.Second)
			return entries
		}},
		{name: "first state", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[0].OperationState = domain.OperationValidate
			return entries
		}},
		{name: "step before state", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[0] = validStepEntry()
			entries[0].Sequence = 1
			return entries
		}},
		{name: "illegal transition", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[1].OperationState = domain.OperationExecute
			return entries
		}},
		{name: "step state mismatch", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[5].OperationState = domain.OperationProtect
			return entries
		}},
		{name: "step starts before state", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[5].Step.StartedAt = entries[4].RecordedAt.Add(-time.Nanosecond)
			return entries
		}},
		{name: "attempt gap", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			entries[5].Step.Attempt = 2
			return entries
		}},
		{name: "attempt after done", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			extra := validStepEntry()
			extra.Sequence = 7
			extra.Step.Attempt = 2
			extra.Step.StartedAt = entries[5].RecordedAt
			endedAt := extra.Step.StartedAt.Add(time.Second)
			extra.Step.EndedAt = &endedAt
			extra.RecordedAt = endedAt
			return append(entries[:6], extra)
		}},
		{name: "terminal followed", mutate: func(entries []domain.JournalEntry) []domain.JournalEntry {
			extra := validTransitionEntry(10, domain.OperationFailed)
			extra.RecordedAt = entries[len(entries)-1].RecordedAt.Add(time.Second)
			return append(entries, extra)
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			entries := test.mutate(validJournal())
			if err := workflow.ValidateJournal(entries); !errors.Is(err, workflow.ErrInvalidJournalStream) {
				t.Fatalf("ValidateJournal() error = %v", err)
			}
		})
	}
}

func TestJournalObjectNamesSortBySequence(t *testing.T) {
	t.Parallel()

	transition := validTransitionEntry(7, domain.OperationCompleteWithDocumentationError)
	got, err := workflow.JournalObjectName(transition)
	if err != nil {
		t.Fatalf("JournalObjectName() returned an error: %v", err)
	}
	if want := "00000000000000000007-state-complete-with-documentation-error.json"; got != want {
		t.Fatalf("JournalObjectName() = %q, want %q", got, want)
	}

	step := validStepEntry()
	step.Sequence = 42
	got, err = workflow.JournalObjectName(step)
	if err != nil {
		t.Fatalf("JournalObjectName() returned an error: %v", err)
	}
	if want := "00000000000000000042-check-health.json"; got != want {
		t.Fatalf("JournalObjectName() = %q, want %q", got, want)
	}
}

func validJournal() []domain.JournalEntry {
	entries := []domain.JournalEntry{
		validTransitionEntry(1, domain.OperationDiscover),
		validTransitionEntry(2, domain.OperationValidate),
		validTransitionEntry(3, domain.OperationPlan),
		validTransitionEntry(4, domain.OperationLock),
		validTransitionEntry(5, domain.OperationExecute),
		validStepEntry(),
		validTransitionEntry(7, domain.OperationVerify),
		validTransitionEntry(8, domain.OperationDocument),
		validTransitionEntry(9, domain.OperationComplete),
	}
	for index := range entries {
		entries[index].RecordedAt = time.Date(2026, 9, 3, 12, 0, index, 0, time.UTC)
	}
	entries[5].Step.StartedAt = entries[4].RecordedAt
	endedAt := entries[5].RecordedAt.Add(-time.Second)
	entries[5].Step.EndedAt = &endedAt

	return entries
}

func validTransitionEntry(sequence uint64, state domain.OperationState) domain.JournalEntry {
	return domain.JournalEntry{
		Schema:         domain.JournalSchemaV1,
		OperationID:    "op-0123456789abcdef",
		PlanID:         "plan-0123456789abcdef",
		Sequence:       sequence,
		Kind:           domain.JournalEntryTransition,
		RecordedAt:     time.Date(2026, 9, 3, 12, 0, int(sequence), 0, time.UTC),
		OperationState: state,
	}
}

func validStepEntry() domain.JournalEntry {
	startedAt := time.Date(2026, 9, 3, 12, 0, 1, 0, time.UTC)
	endedAt := startedAt.Add(time.Second)

	return domain.JournalEntry{
		Schema:         domain.JournalSchemaV1,
		OperationID:    "op-0123456789abcdef",
		PlanID:         "plan-0123456789abcdef",
		Sequence:       6,
		Kind:           domain.JournalEntryStep,
		RecordedAt:     endedAt.Add(time.Second),
		OperationState: domain.OperationExecute,
		Step: &domain.JournalStep{
			ID:                "check-health",
			Outcome:           domain.StepDone,
			ExecutingIdentity: domain.IdentityOperator,
			Attempt:           1,
			StartedAt:         startedAt,
			EndedAt:           &endedAt,
			MutationOccurred:  false,
			ResultSummary:     redact.Sanitize("healthy"),
		},
	}
}
