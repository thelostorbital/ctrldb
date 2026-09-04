// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
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

func TestJournalEntryDecodeRequiresCanonicalBytes(t *testing.T) {
	t.Parallel()

	encoded := mustEncodeJournalEntry(t, validStepEntry())
	if _, err := workflow.DecodeJournalEntry(append([]byte{'\n'}, encoded...)); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("DecodeJournalEntry(whitespace) error = %v, want ErrInvalidJournalEntry", err)
	}
	timeAlias := bytes.Replace(
		encoded, []byte(`"recordedAt":"2026-09-03T12:00:03Z"`),
		[]byte(`"recordedAt":"2026-09-03T12:00:03+00:00"`), 1,
	)
	if bytes.Equal(timeAlias, encoded) {
		t.Fatal("time alias fixture did not change")
	}
	if _, err := workflow.DecodeJournalEntry(timeAlias); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("DecodeJournalEntry(time alias) error = %v, want ErrInvalidJournalEntry", err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("json.Unmarshal() returned an error: %v", err)
	}
	reordered, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal() returned an error: %v", err)
	}
	if bytes.Equal(encoded, reordered) {
		t.Fatal("map encoding unexpectedly retained struct field order")
	}
	if _, err := workflow.DecodeJournalEntry(reordered); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("DecodeJournalEntry(reordered) error = %v, want ErrInvalidJournalEntry", err)
	}
}

func TestJournalEntryDecodeRejectsNoncanonicalResultWithoutDisclosure(t *testing.T) {
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

	_, err = workflow.DecodeJournalEntry(encoded)
	if !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("DecodeJournalEntry() error = %v, want ErrInvalidJournalEntry", err)
	}
	if strings.Contains(err.Error(), "SECRET_MARKER") {
		t.Fatalf("DecodeJournalEntry() disclosed hostile input: %v", err)
	}
}

func TestJournalEntryDecodeDoesNotDiscloseHostileScalarValues(t *testing.T) {
	t.Parallel()

	encoded := mustEncodeJournalEntry(t, validStepEntry())
	hostile := bytes.Replace(
		encoded, []byte(`"recordedAt":"2026-09-03T12:00:03Z"`),
		[]byte(`"recordedAt":"SECRET_MARKER_HOSTILE_TIME"`), 1,
	)
	_, err := workflow.DecodeJournalEntry(hostile)
	if !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("DecodeJournalEntry() error = %v, want ErrInvalidJournalEntry", err)
	}
	if strings.Contains(err.Error(), "SECRET_MARKER") {
		t.Fatalf("DecodeJournalEntry() disclosed hostile scalar: %v", err)
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
		"nested key at top level": bytes.Replace(encoded, []byte(`{"schema"`), []byte(`{"id":"wrong-level","schema"`), 1),
		"unknown nested field": bytes.Replace(
			encoded,
			[]byte(`"step":{"id"`),
			[]byte(`"step":{"extra":true,"id"`),
			1,
		),
		"top-level key nested": bytes.Replace(
			encoded,
			[]byte(`"step":{"id"`),
			[]byte(`"step":{"schema":"JournalEntryV1","id"`),
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

func TestJournalEntryDecodeRejectsDuplicateKeysWithoutDisclosure(t *testing.T) {
	t.Parallel()

	step, err := workflow.EncodeJournalEntry(validStepEntry())
	if err != nil {
		t.Fatalf("EncodeJournalEntry(step) returned an error: %v", err)
	}
	pause, err := workflow.EncodeJournalEntry(validPausedEntry())
	if err != nil {
		t.Fatalf("EncodeJournalEntry(pause) returned an error: %v", err)
	}

	tests := []struct {
		name       string
		encoded    []byte
		unique     string
		duplicated string
	}{
		{
			name:       "top level",
			encoded:    step,
			unique:     `"schema":"JournalEntryV1"`,
			duplicated: `"schema":"JournalEntryV2","schema":"JournalEntryV1"`,
		},
		{
			name:       "case-folded top level",
			encoded:    step,
			unique:     `"schema":"JournalEntryV1"`,
			duplicated: `"SCHEMA":"JournalEntryV2","schema":"JournalEntryV1"`,
		},
		{
			name:       "nested step",
			encoded:    step,
			unique:     `"attempt":1`,
			duplicated: `"attempt":2,"attempt":1`,
		},
		{
			name:       "nested pause",
			encoded:    pause,
			unique:     `"reapprovalRequired":true`,
			duplicated: `"reapprovalRequired":false,"reapprovalRequired":true`,
		},
		{
			name:       "nested cancellation",
			encoded:    mustEncodeJournalEntry(t, validCancellationEntry()),
			unique:     `"requiredRoute":"ROLLBACK"`,
			duplicated: `"requiredRoute":"CANCELLED","requiredRoute":"ROLLBACK"`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := bytes.Replace(test.encoded, []byte(test.unique), []byte(test.duplicated), 1)
			if bytes.Equal(input, test.encoded) {
				t.Fatalf("test fixture did not contain %q", test.unique)
			}
			if _, err := workflow.DecodeJournalEntry(input); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
				t.Fatalf("DecodeJournalEntry() error = %v", err)
			}
		})
	}

	hostile := []byte("{\"\\u001b[31mSECRET_MARKER_HOSTILE\":false," +
		"\"\\u001b[31mSECRET_MARKER_HOSTILE\":true}")
	_, err = workflow.DecodeJournalEntry(hostile)
	if !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("DecodeJournalEntry(hostile) error = %v", err)
	}
	if strings.Contains(err.Error(), "SECRET_MARKER_HOSTILE") || strings.ContainsRune(err.Error(), '\x1b') {
		t.Fatalf("DecodeJournalEntry() error disclosed hostile key: %q", err)
	}

	withoutMutation := bytes.Replace(step, []byte(`,"mutationOccurred":false`), nil, 1)
	if bytes.Equal(withoutMutation, step) {
		t.Fatal("step fixture did not contain mutationOccurred")
	}
	if _, err := workflow.DecodeJournalEntry(withoutMutation); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("DecodeJournalEntry(missing mutationOccurred) error = %v", err)
	}

	noncanonical := bytes.Replace(step, []byte(`"resultSummary"`), []byte(`"RESULTSUMMARY"`), 1)
	if _, err := workflow.DecodeJournalEntry(noncanonical); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("DecodeJournalEntry(noncanonical key) error = %v", err)
	}
	unicodeFold := bytes.Replace(step, []byte(`"mutationOccurred"`), []byte(`"mutationOccurrеd"`), 1)
	_, err = workflow.DecodeJournalEntry(unicodeFold)
	if !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("DecodeJournalEntry(unicode-folded key) error = %v", err)
	}
	if strings.Contains(err.Error(), "mutationOccurrеd") {
		t.Fatalf("DecodeJournalEntry() error disclosed Unicode-folded key: %q", err)
	}
}

func TestCancellationJournalEntryRequiresCompleteDurableRecord(t *testing.T) {
	t.Parallel()

	entry := validCancellationEntry()
	encoded := mustEncodeJournalEntry(t, entry)
	decoded, err := workflow.DecodeJournalEntry(encoded)
	if err != nil || !reflect.DeepEqual(decoded, entry) {
		t.Fatalf("DecodeJournalEntry() = (%#v, %v), want %#v", decoded, err, entry)
	}
	for _, mutate := range []func(*domain.JournalEntry){
		func(entry *domain.JournalEntry) { entry.Cancellation = nil },
		func(entry *domain.JournalEntry) { entry.Cancellation.CurrentStepID = "unsafe/id" },
		func(entry *domain.JournalEntry) { entry.Cancellation.ExecutionContractHash = "not-a-digest" },
		func(entry *domain.JournalEntry) { entry.Cancellation.MutationObservation = "maybe" },
		func(entry *domain.JournalEntry) { entry.Cancellation.RequiredRoute = domain.OperationCancelled },
		func(entry *domain.JournalEntry) {
			entry.Cancellation.RequestedAt = entry.RecordedAt.Add(-time.Nanosecond)
		},
	} {
		changed := validCancellationEntry()
		mutate(&changed)
		if err := workflow.ValidateJournalEntry(changed); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
			t.Fatalf("ValidateJournalEntry() error = %v, want ErrInvalidJournalEntry", err)
		}
	}
	for _, field := range []string{
		"requestedAt", "currentStepId", "executionContractHash", "mutationObservation", "requiredRoute",
	} {
		var document map[string]any
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatalf("json.Unmarshal() returned an error: %v", err)
		}
		delete(document["cancellation"].(map[string]any), field)
		without, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("json.Marshal() returned an error: %v", err)
		}
		if _, err := workflow.DecodeJournalEntry(without); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
			t.Fatalf("DecodeJournalEntry(missing %s) error = %v, want ErrInvalidJournalEntry", field, err)
		}
	}
}

func TestJournalStepDecodeRequiresEveryNonOptionalField(t *testing.T) {
	t.Parallel()

	encoded := mustEncodeJournalEntry(t, validStepEntry())
	for _, field := range []string{
		"id", "outcome", "executingIdentity", "attempt", "startedAt", "mutationOccurred", "resultSummary", "endedAt",
	} {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			var document map[string]any
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatalf("json.Unmarshal() returned an error: %v", err)
			}
			delete(document["step"].(map[string]any), field)
			without, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("json.Marshal() returned an error: %v", err)
			}
			if _, err := workflow.DecodeJournalEntry(without); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
				t.Fatalf("DecodeJournalEntry() error = %v, want ErrInvalidJournalEntry", err)
			}
		})
	}

	emptySummary := validStepEntry()
	emptySummary.Step.ResultSummary = redact.Sanitize("")
	decoded, err := workflow.DecodeJournalEntry(mustEncodeJournalEntry(t, emptySummary))
	if err != nil {
		t.Fatalf("explicit empty resultSummary returned an error: %v", err)
	}
	if decoded.Step.ResultSummary.String() != "" {
		t.Fatalf("resultSummary = %q, want explicit empty value", decoded.Step.ResultSummary.String())
	}
}

func TestJournalDecodeRejectsNullAndWrongTypesAtEveryEncodedPosition(t *testing.T) {
	t.Parallel()

	for name, entry := range map[string]domain.JournalEntry{
		"step":         validStepEntry(),
		"pause":        validPausedEntry(),
		"cancellation": validCancellationEntry(),
	} {
		name, entry := name, entry
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded := mustEncodeJournalEntry(t, entry)
			var document any
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatalf("json.Unmarshal() returned an error: %v", err)
			}
			assertEveryJournalValueReplacementRejected(t, document, document, name, nil)
			assertEveryJournalValueReplacementRejected(t, document, document, name, map[string]any{})
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
		{name: "contract hash", mutate: func(entry *domain.JournalEntry) { entry.ContractHash = "" }},
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

func TestPausedJournalRequiresCompleteMetadata(t *testing.T) {
	t.Parallel()

	entry := validPausedEntry()
	encoded, err := workflow.EncodeJournalEntry(entry)
	if err != nil {
		t.Fatalf("EncodeJournalEntry() returned an error: %v", err)
	}
	decoded, err := workflow.DecodeJournalEntry(encoded)
	if err != nil {
		t.Fatalf("DecodeJournalEntry() returned an error: %v", err)
	}
	if !reflect.DeepEqual(decoded, entry) {
		t.Fatalf("decoded pause = %#v, want %#v", decoded, entry)
	}

	for _, field := range []string{"pausedAt", "pauseReason", "mutationOccurred", "resumeBy", "reapprovalRequired"} {
		field := field
		t.Run("missing "+field, func(t *testing.T) {
			needle := []byte(`"` + field + `":`)
			start := bytes.Index(encoded, needle)
			if start < 0 {
				t.Fatalf("encoded pause omitted %s", field)
			}
			end := start + len(needle)
			inString := false
			for end < len(encoded) {
				if encoded[end] == '"' && (end == 0 || encoded[end-1] != '\\') {
					inString = !inString
				}
				if !inString && (encoded[end] == ',' || encoded[end] == '}') {
					break
				}
				end++
			}
			if end < len(encoded) && encoded[end] == ',' {
				end++
			} else if start > 0 && encoded[start-1] == ',' {
				start--
			}
			without := append(append([]byte(nil), encoded[:start]...), encoded[end:]...)
			if _, err := workflow.DecodeJournalEntry(without); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
				t.Fatalf("DecodeJournalEntry() error = %v, want ErrInvalidJournalEntry", err)
			}
		})
	}
}

func TestPausedJournalRejectsInvalidMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*domain.JournalEntry)
	}{
		{name: "missing pause", mutate: func(entry *domain.JournalEntry) { entry.Pause = nil }},
		{name: "recorded before pausedAt", mutate: func(entry *domain.JournalEntry) { entry.Pause.PausedAt = entry.RecordedAt.Add(time.Second) }},
		{name: "empty reason", mutate: func(entry *domain.JournalEntry) { entry.Pause.PauseReason = redact.Sanitize("") }},
		{name: "zero resumeBy", mutate: func(entry *domain.JournalEntry) { entry.Pause.ResumeBy = time.Time{} }},
		{name: "expired resumeBy", mutate: func(entry *domain.JournalEntry) { entry.Pause.ResumeBy = entry.Pause.PausedAt }},
		{name: "pause on non-paused transition", mutate: func(entry *domain.JournalEntry) { entry.OperationState = domain.OperationExecute }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			entry := validPausedEntry()
			test.mutate(&entry)
			if err := workflow.ValidateJournalEntry(entry); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
				t.Fatalf("ValidateJournalEntry() error = %v, want ErrInvalidJournalEntry", err)
			}
		})
	}

	step := validStepEntry()
	step.Pause = validPausedEntry().Pause
	if err := workflow.ValidateJournalEntry(step); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
		t.Fatalf("step with pause error = %v, want ErrInvalidJournalEntry", err)
	}
}

func TestJournalValidatesCompleteHistory(t *testing.T) {
	t.Parallel()

	entries := validJournal()
	if err := workflow.ValidateJournal(entries); err != nil {
		t.Fatalf("ValidateJournal() returned an error: %v", err)
	}
}

func TestJournalBindsContractHashFromTheFirstEntry(t *testing.T) {
	t.Parallel()

	entries := validJournal()
	changed := append([]domain.JournalEntry(nil), entries...)
	changed[0].ContractHash = strings.Repeat("b", 64)
	if err := workflow.ValidateJournal(changed); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("ValidateJournal(first hash mismatch) error = %v, want ErrInvalidJournalStream", err)
	}
	changed = append([]domain.JournalEntry(nil), entries...)
	changed[len(changed)-1].ContractHash = strings.Repeat("b", 64)
	if err := workflow.ValidateJournal(changed); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("ValidateJournal(later hash mismatch) error = %v, want ErrInvalidJournalStream", err)
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

func TestJournalCancellationRequiresRollbackAfterPossibleMutation(t *testing.T) {
	t.Parallel()

	beforeMutation := validJournal()[:6]
	cancelled := validTransitionEntry(7, domain.OperationCancelled)
	cancelled.RecordedAt = beforeMutation[len(beforeMutation)-1].RecordedAt.Add(time.Second)
	beforeMutation = append(beforeMutation, cancelled)
	if err := workflow.ValidateJournal(beforeMutation); err != nil {
		t.Fatalf("pre-mutation CANCELLED journal returned an error: %v", err)
	}

	for _, mutate := range []func(*domain.JournalEntry){
		func(entry *domain.JournalEntry) { entry.Step.MutationOccurred = true },
		func(entry *domain.JournalEntry) {
			entry.Step.Outcome = domain.StepUnknown
			entry.Step.EndedAt = nil
		},
	} {
		entries := validJournal()[:6]
		mutate(&entries[5])
		cancelled := validTransitionEntry(7, domain.OperationCancelled)
		cancelled.RecordedAt = entries[5].RecordedAt.Add(time.Second)
		entries = append(entries, cancelled)
		if err := workflow.ValidateJournal(entries); !errors.Is(err, workflow.ErrInvalidJournalStream) {
			t.Fatalf("possibly mutated CANCELLED journal error = %v, want ErrInvalidJournalStream", err)
		}
	}

	afterRollback := validJournal()[:6]
	afterRollback[5].Step.MutationOccurred = true
	rollback := validTransitionEntry(7, domain.OperationRollback)
	rollback.RecordedAt = afterRollback[5].RecordedAt.Add(time.Second)
	cancelled = validTransitionEntry(8, domain.OperationCancelled)
	cancelled.RecordedAt = rollback.RecordedAt.Add(time.Second)
	unsafeTerminal := append(afterRollback, rollback, cancelled)
	if err := workflow.ValidateJournal(unsafeTerminal); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("ROLLBACK -> CANCELLED error = %v, want ErrInvalidJournalStream", err)
	}
	verified := validTransitionEntry(8, domain.OperationVerifiedRollback)
	verified.RecordedAt = rollback.RecordedAt.Add(time.Second)
	afterRollback = append(afterRollback, rollback, verified)
	if err := workflow.ValidateJournal(afterRollback); err != nil {
		t.Fatalf("ROLLBACK -> VERIFIED_ROLLBACK returned an error: %v", err)
	}
}

func TestJournalPauseCannotDiscardObservedMutation(t *testing.T) {
	t.Parallel()

	entries := validJournal()[:6]
	entries[5].Step.MutationOccurred = true
	pause := validPausedEntry()
	pause.RecordedAt = entries[5].RecordedAt.Add(time.Second)
	pause.Pause.PausedAt = pause.RecordedAt
	pause.Pause.ResumeBy = pause.RecordedAt.Add(time.Hour)
	entries = append(entries, pause)

	if err := workflow.ValidateJournal(entries); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("ValidateJournal() error = %v, want ErrInvalidJournalStream", err)
	}
}

func TestJournalResumeEnforcesPauseDeadlineAndReapproval(t *testing.T) {
	t.Parallel()

	makePaused := func() []domain.JournalEntry {
		entries := validJournal()[:6]
		pause := validPausedEntry()
		pause.RecordedAt = entries[5].RecordedAt.Add(time.Second)
		pause.Pause.PausedAt = pause.RecordedAt
		pause.Pause.ResumeBy = pause.RecordedAt.Add(time.Hour)
		return append(entries, pause)
	}

	valid := makePaused()
	valid[6].Pause.ReapprovalRequired = false
	resume := validTransitionEntry(8, domain.OperationDiscover)
	resume.RecordedAt = valid[6].Pause.ResumeBy.Add(-time.Nanosecond)
	if err := workflow.ValidateJournal(append(valid, resume)); err != nil {
		t.Fatalf("fresh resume returned an error: %v", err)
	}

	expired := makePaused()
	expired[6].Pause.ReapprovalRequired = false
	resume.RecordedAt = expired[6].Pause.ResumeBy
	if err := workflow.ValidateJournal(append(expired, resume)); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("expired resume error = %v, want ErrInvalidJournalStream", err)
	}

	reapproval := makePaused()
	resume.RecordedAt = reapproval[6].Pause.ResumeBy.Add(-time.Second)
	if err := workflow.ValidateJournal(append(reapproval, resume)); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("resume without typed reapproval error = %v, want ErrInvalidJournalStream", err)
	}

	expiredRecovery := makePaused()
	expiredRecovery[6].Pause.MutationOccurred = true
	rollback := validTransitionEntry(8, domain.OperationRollback)
	rollback.RecordedAt = expiredRecovery[6].Pause.ResumeBy
	if err := workflow.ValidateJournal(append(expiredRecovery, rollback)); err != nil {
		t.Fatalf("expired pause rollback returned an error: %v", err)
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

	cancellation := validCancellationEntry()
	got, err = workflow.JournalObjectName(cancellation)
	if err != nil {
		t.Fatalf("JournalObjectName(cancellation) returned an error: %v", err)
	}
	if want := "00000000000000000006-cancellation-request.json"; got != want {
		t.Fatalf("JournalObjectName(cancellation) = %q, want %q", got, want)
	}
}

func mustEncodeJournalEntry(t *testing.T, entry domain.JournalEntry) []byte {
	t.Helper()
	encoded, err := workflow.EncodeJournalEntry(entry)
	if err != nil {
		t.Fatalf("EncodeJournalEntry() returned an error: %v", err)
	}

	return encoded
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
		ContractHash:   strings.Repeat("a", 64),
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
		ContractHash:   strings.Repeat("a", 64),
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

func validCancellationEntry() domain.JournalEntry {
	requestedAt := time.Date(2026, 9, 3, 12, 0, 5, 0, time.UTC)

	return domain.JournalEntry{
		Schema:         domain.JournalSchemaV1,
		OperationID:    "op-0123456789abcdef",
		PlanID:         "plan-0123456789abcdef",
		ContractHash:   strings.Repeat("a", 64),
		Sequence:       6,
		Kind:           domain.JournalEntryCancellationRequest,
		RecordedAt:     requestedAt,
		OperationState: domain.OperationExecute,
		Cancellation: &domain.JournalCancellationRequest{
			RequestedAt:           requestedAt,
			CurrentStepID:         "stop-instance",
			ExecutionContractHash: strings.Repeat("a", 64),
			MutationObservation:   domain.MutationUnknown,
			RequiredRoute:         domain.OperationRollback,
		},
	}
}

func validPausedEntry() domain.JournalEntry {
	pausedAt := time.Date(2026, 9, 3, 12, 0, 7, 0, time.UTC)

	return domain.JournalEntry{
		Schema:         domain.JournalSchemaV1,
		OperationID:    "op-0123456789abcdef",
		PlanID:         "plan-0123456789abcdef",
		ContractHash:   strings.Repeat("a", 64),
		Sequence:       7,
		Kind:           domain.JournalEntryTransition,
		RecordedAt:     pausedAt,
		OperationState: domain.OperationPaused,
		Pause: &domain.JournalPause{
			PausedAt:           pausedAt,
			PauseReason:        redact.Sanitize("credential expired"),
			MutationOccurred:   false,
			ResumeBy:           pausedAt.Add(24 * time.Hour),
			ReapprovalRequired: true,
		},
	}
}

func assertEveryJournalValueReplacementRejected(t *testing.T, root, document any, path string, replacement any) {
	t.Helper()
	object, ok := document.(map[string]any)
	if !ok {
		return
	}
	for key, child := range object {
		object[key] = replacement
		encoded, err := json.Marshal(root)
		if err != nil {
			t.Fatalf("json.Marshal(%s.%s) returned an error: %v", path, key, err)
		}
		if _, err := workflow.DecodeJournalEntry(encoded); !errors.Is(err, workflow.ErrInvalidJournalEntry) {
			t.Fatalf("DecodeJournalEntry(%s.%s replacement) error = %v", path, key, err)
		}
		object[key] = child
		if nested, nestedObject := child.(map[string]any); nestedObject {
			assertEveryJournalValueReplacementRejected(t, root, nested, path+"."+key, replacement)
		}
	}
}
