// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestJournalClosedEnumsJSONRoundTrip(t *testing.T) {
	t.Parallel()

	type document struct {
		Kind    domain.JournalEntryKind `json:"kind"`
		Outcome domain.StepOutcome      `json:"outcome"`
	}

	encoded, err := json.Marshal(document{Kind: domain.JournalEntryStep, Outcome: domain.StepUnknown})
	if err != nil {
		t.Fatalf("json.Marshal() returned an error: %v", err)
	}
	if string(encoded) != `{"kind":"step","outcome":"UNKNOWN"}` {
		t.Fatalf("json.Marshal() = %s", encoded)
	}

	var decoded document
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() returned an error: %v", err)
	}
	if decoded.Kind != domain.JournalEntryStep || decoded.Outcome != domain.StepUnknown {
		t.Fatalf("decoded value = %#v", decoded)
	}
}

func TestJournalClosedEnumsRejectUnknownValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "STEP", "event", " step"} {
		var kind domain.JournalEntryKind
		if err := json.Unmarshal([]byte(`"`+value+`"`), &kind); !errors.Is(err, domain.ErrInvalidJournalEntryKind) {
			t.Errorf("JournalEntryKind(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"", "done", "RUNNING", "UNKNOWN "} {
		var outcome domain.StepOutcome
		if err := json.Unmarshal([]byte(`"`+value+`"`), &outcome); !errors.Is(err, domain.ErrInvalidStepOutcome) {
			t.Errorf("StepOutcome(%q) error = %v", value, err)
		}
	}
}

func TestJournalClosedEnumsRejectInvalidMarshal(t *testing.T) {
	t.Parallel()

	if _, err := json.Marshal(domain.JournalEntryKind("event")); !errors.Is(err, domain.ErrInvalidJournalEntryKind) {
		t.Fatalf("invalid JournalEntryKind marshal error = %v", err)
	}
	if _, err := json.Marshal(domain.StepOutcome("RUNNING")); !errors.Is(err, domain.ErrInvalidStepOutcome) {
		t.Fatalf("invalid StepOutcome marshal error = %v", err)
	}

	var kind *domain.JournalEntryKind
	if err := kind.UnmarshalText([]byte("step")); !errors.Is(err, domain.ErrInvalidJournalEntryKind) {
		t.Fatalf("nil JournalEntryKind.UnmarshalText() error = %v", err)
	}
	var outcome *domain.StepOutcome
	if err := outcome.UnmarshalText([]byte("DONE")); !errors.Is(err, domain.ErrInvalidStepOutcome) {
		t.Fatalf("nil StepOutcome.UnmarshalText() error = %v", err)
	}
}
