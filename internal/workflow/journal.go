// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

var (
	// ErrInvalidJournalEntry is returned when one durable entry is malformed.
	ErrInvalidJournalEntry = errors.New("invalid journal entry")
	// ErrInvalidJournalStream is returned when valid entries do not form one
	// contiguous, internally consistent operation history.
	ErrInvalidJournalStream = errors.New("invalid journal stream")
)

var (
	operationIDPattern   = regexp.MustCompile(`^op-[0-9a-f]{16}$`)
	journalPlanIDPattern = regexp.MustCompile(`^plan-[0-9a-f]{16}$`)
	stepIDPattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// EncodeJournalEntry validates entry and returns its compact JSON encoding.
func EncodeJournalEntry(entry domain.JournalEntry) ([]byte, error) {
	if err := ValidateJournalEntry(entry); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(entry)
	if err != nil {
		return nil, journalEntryError("encode", err.Error())
	}

	return encoded, nil
}

// DecodeJournalEntry strictly decodes one entry and sanitizes persisted result
// text through redact.Text's JSON boundary.
func DecodeJournalEntry(encoded []byte) (domain.JournalEntry, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	var entry domain.JournalEntry
	if err := decoder.Decode(&entry); err != nil {
		return domain.JournalEntry{}, journalEntryError("decode", err.Error())
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return domain.JournalEntry{}, journalEntryError("decode", "trailing JSON value")
	}

	if err := ValidateJournalEntry(entry); err != nil {
		return domain.JournalEntry{}, err
	}

	return entry, nil
}

// ValidateJournalEntry checks the closed JournalEntryV1 invariants.
func ValidateJournalEntry(entry domain.JournalEntry) error {
	if entry.Schema != domain.JournalSchemaV1 {
		return journalEntryError("schema", "must be JournalEntryV1")
	}
	if !operationIDPattern.MatchString(entry.OperationID) {
		return journalEntryError("operationId", "must match op-<16 lowercase hex>")
	}
	if !journalPlanIDPattern.MatchString(entry.PlanID) {
		return journalEntryError("planId", "must match plan-<16 lowercase hex>")
	}
	if entry.Sequence == 0 {
		return journalEntryError("sequence", "must start at 1")
	}
	if !entry.Kind.Valid() {
		return journalEntryError("kind", "unknown value")
	}
	if err := validateJournalTime("recordedAt", entry.RecordedAt); err != nil {
		return err
	}
	if !entry.OperationState.Valid() {
		return journalEntryError("operationState", "unknown value")
	}

	switch entry.Kind {
	case domain.JournalEntryTransition:
		if entry.Step != nil {
			return journalEntryError("step", "must be absent for a transition")
		}
	case domain.JournalEntryStep:
		if entry.Step == nil {
			return journalEntryError("step", "is required for a step entry")
		}
		if err := validateJournalStep(*entry.Step, entry.RecordedAt); err != nil {
			return err
		}
	}

	return nil
}

// ValidateJournal validates one complete operation history in object-name
// order. It never treats journal claims as proof that a step remains complete;
// live-state verification is required by the resume engine.
func ValidateJournal(entries []domain.JournalEntry) error {
	if len(entries) == 0 {
		return journalStreamError(0, "must contain the initial DISCOVER transition")
	}

	operationID := entries[0].OperationID
	planID := entries[0].PlanID
	var machine *Machine
	var previousTime time.Time
	attempts := make(map[string]uint32)
	completed := make(map[string]struct{})

	for index, entry := range entries {
		if err := ValidateJournalEntry(entry); err != nil {
			return fmt.Errorf("%w: entry %d: %v", ErrInvalidJournalStream, index+1, err)
		}
		if entry.Sequence != uint64(index+1) {
			return journalStreamError(index+1, "sequence must be contiguous and start at 1")
		}
		if entry.OperationID != operationID || entry.PlanID != planID {
			return journalStreamError(index+1, "operationId and planId must remain constant")
		}
		priorTime := previousTime
		if !priorTime.IsZero() && entry.RecordedAt.Before(priorTime) {
			return journalStreamError(index+1, "recordedAt must not move backwards")
		}
		previousTime = entry.RecordedAt

		if machine != nil && machine.State().Terminal() {
			return journalStreamError(index+1, "entry follows a terminal transition")
		}

		if entry.Kind == domain.JournalEntryTransition {
			if machine == nil {
				if entry.OperationState != domain.OperationDiscover {
					return journalStreamError(index+1, "first transition must be DISCOVER")
				}
				machine = NewMachine()
				continue
			}
			if err := machine.Transition(entry.OperationState); err != nil {
				return fmt.Errorf("%w: entry %d: %v", ErrInvalidJournalStream, index+1, err)
			}
			continue
		}

		if machine == nil {
			return journalStreamError(index+1, "step precedes the initial transition")
		}
		if entry.OperationState != machine.State() {
			return journalStreamError(index+1, "step operationState does not match the current state")
		}
		if entry.Step.StartedAt.Before(priorTime) {
			return journalStreamError(index+1, "step started before the current journal boundary")
		}
		if _, exists := completed[entry.Step.ID]; exists {
			return journalStreamError(index+1, "step attempt follows a DONE outcome")
		}

		wantAttempt := attempts[entry.Step.ID] + 1
		if entry.Step.Attempt != wantAttempt {
			return journalStreamError(index+1, "step attempts must start at 1 and increment without gaps")
		}
		attempts[entry.Step.ID] = entry.Step.Attempt
		if entry.Step.Outcome == domain.StepDone {
			completed[entry.Step.ID] = struct{}{}
		}
	}

	return nil
}

// JournalObjectName returns the lexically sortable immutable object filename
// for entry.
func JournalObjectName(entry domain.JournalEntry) (string, error) {
	if err := ValidateJournalEntry(entry); err != nil {
		return "", err
	}

	entryID := "state-" + strings.ToLower(strings.ReplaceAll(string(entry.OperationState), "_", "-"))
	if entry.Kind == domain.JournalEntryStep {
		entryID = entry.Step.ID
	}

	return fmt.Sprintf("%020d-%s.json", entry.Sequence, entryID), nil
}

func validateJournalStep(step domain.JournalStep, recordedAt time.Time) error {
	if !stepIDPattern.MatchString(step.ID) {
		return journalEntryError("step.id", "must match [a-z][a-z0-9-]{0,63}")
	}
	if !step.Outcome.Valid() {
		return journalEntryError("step.outcome", "unknown value")
	}
	if !step.ExecutingIdentity.Valid() {
		return journalEntryError("step.executingIdentity", "unknown value")
	}
	if step.Attempt == 0 {
		return journalEntryError("step.attempt", "must start at 1")
	}
	if err := validateJournalTime("step.startedAt", step.StartedAt); err != nil {
		return err
	}
	if recordedAt.Before(step.StartedAt) {
		return journalEntryError("recordedAt", "must not precede step.startedAt")
	}
	if step.EndedAt == nil {
		if step.Outcome != domain.StepUnknown {
			return journalEntryError("step.endedAt", "is required for DONE and FAILED")
		}
		return nil
	}
	if err := validateJournalTime("step.endedAt", *step.EndedAt); err != nil {
		return err
	}
	if step.EndedAt.Before(step.StartedAt) {
		return journalEntryError("step.endedAt", "must not precede step.startedAt")
	}
	if recordedAt.Before(*step.EndedAt) {
		return journalEntryError("recordedAt", "must not precede step.endedAt")
	}

	return nil
}

func validateJournalTime(path string, value time.Time) error {
	if value.IsZero() {
		return journalEntryError(path, "must not be zero")
	}
	_, offset := value.Zone()
	if offset != 0 {
		return journalEntryError(path, "must be UTC")
	}

	return nil
}

func journalEntryError(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidJournalEntry, path, reason)
}

func journalStreamError(index int, reason string) error {
	return fmt.Errorf("%w: entry %d %s", ErrInvalidJournalStream, index, reason)
}
