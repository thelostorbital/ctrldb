// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"errors"
	"fmt"
	"time"

	"github.com/thelostorbital/ctrldb/internal/redact"
)

// JournalSchemaV1 is the first durable operation-journal schema.
const JournalSchemaV1 = "JournalEntryV1"

var (
	// ErrInvalidJournalEntryKind is returned for an unknown journal entry kind.
	ErrInvalidJournalEntryKind = errors.New("invalid journal entry kind")
	// ErrInvalidStepOutcome is returned for an unknown durable step outcome.
	ErrInvalidStepOutcome = errors.New("invalid step outcome")
)

// JournalEntryKind distinguishes lifecycle transitions from step outcomes.
type JournalEntryKind string

const (
	JournalEntryTransition JournalEntryKind = "transition"
	JournalEntryStep       JournalEntryKind = "step"
)

// Valid reports whether kind is part of the closed journal schema.
func (kind JournalEntryKind) Valid() bool {
	return kind == JournalEntryTransition || kind == JournalEntryStep
}

// MarshalText implements encoding.TextMarshaler.
func (kind JournalEntryKind) MarshalText() ([]byte, error) {
	if !kind.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidJournalEntryKind, kind)
	}

	return []byte(kind), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (kind *JournalEntryKind) UnmarshalText(text []byte) error {
	if kind == nil {
		return fmt.Errorf("%w: nil destination", ErrInvalidJournalEntryKind)
	}

	parsed := JournalEntryKind(text)
	if !parsed.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidJournalEntryKind, text)
	}
	*kind = parsed

	return nil
}

// StepOutcome is the observed result of one durable step attempt.
type StepOutcome string

const (
	StepDone    StepOutcome = "DONE"
	StepFailed  StepOutcome = "FAILED"
	StepUnknown StepOutcome = "UNKNOWN"
)

// Valid reports whether outcome is part of the closed journal schema.
func (outcome StepOutcome) Valid() bool {
	return outcome == StepDone || outcome == StepFailed || outcome == StepUnknown
}

// MarshalText implements encoding.TextMarshaler.
func (outcome StepOutcome) MarshalText() ([]byte, error) {
	if !outcome.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidStepOutcome, outcome)
	}

	return []byte(outcome), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (outcome *StepOutcome) UnmarshalText(text []byte) error {
	if outcome == nil {
		return fmt.Errorf("%w: nil destination", ErrInvalidStepOutcome)
	}

	parsed := StepOutcome(text)
	if !parsed.Valid() {
		return fmt.Errorf("%w: %q", ErrInvalidStepOutcome, text)
	}
	*outcome = parsed

	return nil
}

// JournalEntry is one immutable boundary record in an operation stream.
type JournalEntry struct {
	Schema         string           `json:"schema"`
	OperationID    string           `json:"operationId"`
	PlanID         string           `json:"planId"`
	Sequence       uint64           `json:"sequence"`
	Kind           JournalEntryKind `json:"kind"`
	RecordedAt     time.Time        `json:"recordedAt"`
	OperationState OperationState   `json:"operationState"`
	Step           *JournalStep     `json:"step,omitempty"`
}

// JournalStep records one observed attempt without persisting raw output.
type JournalStep struct {
	ID                string            `json:"id"`
	Outcome           StepOutcome       `json:"outcome"`
	ExecutingIdentity ExecutionIdentity `json:"executingIdentity"`
	Attempt           uint32            `json:"attempt"`
	StartedAt         time.Time         `json:"startedAt"`
	EndedAt           *time.Time        `json:"endedAt,omitempty"`
	MutationOccurred  bool              `json:"mutationOccurred"`
	ResultSummary     redact.Text       `json:"resultSummary"`
}
