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

type journalJSONSchema struct {
	fields map[string]*journalJSONSchema
}

var (
	journalJSONScalar = &journalJSONSchema{}
	journalJSONRoot   = journalJSONObject(map[string]*journalJSONSchema{
		"schema": journalJSONScalar, "operationId": journalJSONScalar, "planId": journalJSONScalar,
		"sequence": journalJSONScalar, "kind": journalJSONScalar, "recordedAt": journalJSONScalar,
		"operationState": journalJSONScalar,
		"step": journalJSONObject(map[string]*journalJSONSchema{
			"id": journalJSONScalar, "outcome": journalJSONScalar, "executingIdentity": journalJSONScalar,
			"attempt": journalJSONScalar, "startedAt": journalJSONScalar, "endedAt": journalJSONScalar,
			"mutationOccurred": journalJSONScalar, "resultSummary": journalJSONScalar,
		}),
		"pause": journalJSONObject(map[string]*journalJSONSchema{
			"pausedAt": journalJSONScalar, "pauseReason": journalJSONScalar,
			"mutationOccurred": journalJSONScalar, "resumeBy": journalJSONScalar,
			"reapprovalRequired": journalJSONScalar,
		}),
		"cancellation": journalJSONObject(map[string]*journalJSONSchema{
			"requestedAt": journalJSONScalar, "currentStepId": journalJSONScalar,
			"mutationObservation": journalJSONScalar, "requiredRoute": journalJSONScalar,
		}),
	})
)

func journalJSONObject(fields map[string]*journalJSONSchema) *journalJSONSchema {
	return &journalJSONSchema{fields: fields}
}

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
	if err := rejectDuplicateJournalJSONKeys(encoded); err != nil {
		return domain.JournalEntry{}, err
	}

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
	if err := validateRequiredJournalJSON(encoded, entry); err != nil {
		return domain.JournalEntry{}, err
	}

	if err := ValidateJournalEntry(entry); err != nil {
		return domain.JournalEntry{}, err
	}

	return entry, nil
}

func rejectDuplicateJournalJSONKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := consumeUniqueJournalJSONValue(decoder, journalJSONRoot); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return journalEntryError("decode", "trailing JSON value")
	}

	return nil
}

func consumeUniqueJournalJSONValue(decoder *json.Decoder, schema *journalJSONSchema) error {
	token, err := decoder.Token()
	if err != nil {
		return journalEntryError("decode", err.Error())
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}

	switch delimiter {
	case '{':
		if schema == nil || schema.fields == nil {
			return journalEntryError("decode", "object is not allowed at this schema position")
		}
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return journalEntryError("decode", err.Error())
			}
			key, ok := keyToken.(string)
			if !ok {
				return journalEntryError("decode", "object key must be a string")
			}
			childSchema, canonical := schema.fields[key]
			if !canonical {
				return journalEntryError("decode", "object contains a noncanonical key")
			}
			if _, duplicate := seen[key]; duplicate {
				return journalEntryError("decode", "object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJournalJSONValue(decoder, childSchema); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return journalEntryError("decode", err.Error())
		}
	case '[':
		return journalEntryError("decode", "array is not allowed at this schema position")
	default:
		return journalEntryError("decode", "contains an unexpected delimiter")
	}

	return nil
}

func validateRequiredJournalJSON(encoded []byte, entry domain.JournalEntry) error {
	if (entry.OperationState != domain.OperationPaused || entry.Pause == nil) &&
		(entry.Kind != domain.JournalEntryStep || entry.Step == nil) &&
		(entry.Kind != domain.JournalEntryCancellationRequest || entry.Cancellation == nil) {
		return nil
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return journalEntryError("decode", err.Error())
	}
	if entry.OperationState == domain.OperationPaused && entry.Pause != nil {
		var pause map[string]json.RawMessage
		if err := json.Unmarshal(document["pause"], &pause); err != nil {
			return journalEntryError("pause", "must be an object")
		}
		for _, field := range []string{"pausedAt", "pauseReason", "mutationOccurred", "resumeBy", "reapprovalRequired"} {
			if _, exists := pause[field]; !exists {
				return journalEntryError("pause."+field, "is required")
			}
		}
	}
	if entry.Kind == domain.JournalEntryStep && entry.Step != nil {
		var step map[string]json.RawMessage
		if err := json.Unmarshal(document["step"], &step); err != nil {
			return journalEntryError("step", "must be an object")
		}
		if _, exists := step["mutationOccurred"]; !exists {
			return journalEntryError("step.mutationOccurred", "is required")
		}
	}
	if entry.Kind == domain.JournalEntryCancellationRequest && entry.Cancellation != nil {
		var cancellation map[string]json.RawMessage
		if err := json.Unmarshal(document["cancellation"], &cancellation); err != nil {
			return journalEntryError("cancellation", "must be an object")
		}
		for _, field := range []string{"requestedAt", "currentStepId", "mutationObservation", "requiredRoute"} {
			if _, exists := cancellation[field]; !exists {
				return journalEntryError("cancellation."+field, "is required")
			}
		}
	}

	return nil
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
		if entry.OperationState == domain.OperationPaused {
			if entry.Pause == nil {
				return journalEntryError("pause", "is required for a PAUSED transition")
			}
			if err := validateJournalPause(*entry.Pause, entry.RecordedAt); err != nil {
				return err
			}
		} else if entry.Pause != nil {
			return journalEntryError("pause", "is allowed only for a PAUSED transition")
		}
		if entry.Cancellation != nil {
			return journalEntryError("cancellation", "must be absent for a transition")
		}
	case domain.JournalEntryStep:
		if entry.Step == nil {
			return journalEntryError("step", "is required for a step entry")
		}
		if entry.Pause != nil {
			return journalEntryError("pause", "must be absent for a step entry")
		}
		if entry.Cancellation != nil {
			return journalEntryError("cancellation", "must be absent for a step entry")
		}
		if err := validateJournalStep(*entry.Step, entry.RecordedAt); err != nil {
			return err
		}
	case domain.JournalEntryCancellationRequest:
		if entry.Step != nil || entry.Pause != nil {
			return journalEntryError("cancellation", "request must not contain step or pause data")
		}
		if entry.Cancellation == nil {
			return journalEntryError("cancellation", "is required for a cancellation request")
		}
		if err := validateJournalCancellation(*entry.Cancellation, entry.RecordedAt); err != nil {
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
	mutationMayHaveOccurred := false
	var paused *domain.JournalPause
	var pendingCancellation domain.OperationState
	var pendingCurrentStepID string
	var pendingStepStartBoundary time.Time
	var pendingRequestedAt time.Time

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

		if entry.Kind == domain.JournalEntryCancellationRequest {
			if machine == nil {
				return journalStreamError(index+1, "cancellation request precedes the initial transition")
			}
			if entry.OperationState != machine.State() {
				return journalStreamError(index+1, "cancellation request state does not match the current state")
			}
			if pendingCancellation != "" {
				return journalStreamError(index+1, "multiple pending cancellation requests are ambiguous")
			}
			if mutationMayHaveOccurred && entry.Cancellation.MutationObservation == domain.MutationNotOccurred {
				return journalStreamError(index+1, "cancellation request discards observed mutation")
			}
			mutationMayHaveOccurred = mutationMayHaveOccurred ||
				entry.Cancellation.MutationObservation != domain.MutationNotOccurred
			pendingCancellation = entry.Cancellation.RequiredRoute
			pendingCurrentStepID = entry.Cancellation.CurrentStepID
			pendingStepStartBoundary = priorTime
			pendingRequestedAt = entry.Cancellation.RequestedAt
			if !cancellationRouteReachable(machine.State(), pendingCancellation) {
				return journalStreamError(index+1, "cancellation request has no reachable route")
			}
			continue
		}

		if entry.Kind == domain.JournalEntryTransition {
			if machine == nil {
				if entry.OperationState != domain.OperationDiscover {
					return journalStreamError(index+1, "first transition must be DISCOVER")
				}
				var err error
				machine, err = NewMachine(operationID, planID)
				if err != nil {
					return journalStreamError(index+1, "initial transition has an invalid machine binding")
				}
				continue
			}
			if pendingCancellation != "" && CanTransition(machine.State(), pendingCancellation) &&
				entry.OperationState != pendingCancellation {
				return journalStreamError(index+1, "pending cancellation was not honored at the first compatible boundary")
			}
			if machine.State() == domain.OperationPaused {
				if paused == nil {
					return journalStreamError(index+1, "PAUSED state is missing its durable metadata")
				}
				if entry.OperationState == domain.OperationDiscover && !entry.RecordedAt.Before(paused.ResumeBy) {
					return journalStreamError(index+1, "transition leaves PAUSED at or after resumeBy")
				}
				if entry.OperationState == domain.OperationDiscover && paused.ReapprovalRequired {
					return journalStreamError(index+1, "resume requires fresh approval evidence from the future resume coordinator")
				}
			}
			if entry.OperationState == domain.OperationCancelled && mutationMayHaveOccurred {
				return journalStreamError(index+1, "CANCELLED after possible mutation must route through ROLLBACK")
			}
			var transitionErr error
			if entry.OperationState == domain.OperationCancelled {
				transitionErr = machine.transition(entry.OperationState, true)
			} else {
				transitionErr = machine.Transition(entry.OperationState)
			}
			if transitionErr != nil {
				return fmt.Errorf("%w: entry %d: %v", ErrInvalidJournalStream, index+1, transitionErr)
			}
			if entry.OperationState == pendingCancellation {
				pendingCancellation = ""
				pendingCurrentStepID = ""
				pendingStepStartBoundary = time.Time{}
				pendingRequestedAt = time.Time{}
			} else if pendingCancellation != "" && !cancellationRouteReachable(machine.State(), pendingCancellation) {
				return journalStreamError(index+1, "transition made the pending cancellation unreachable")
			} else if pendingCancellation != "" {
				pendingCurrentStepID = ""
				pendingStepStartBoundary = time.Time{}
				pendingRequestedAt = time.Time{}
			}
			if entry.Pause != nil {
				if mutationMayHaveOccurred && !entry.Pause.MutationOccurred {
					return journalStreamError(index+1, "PAUSED metadata must not discard observed mutation")
				}
				mutationMayHaveOccurred = mutationMayHaveOccurred || entry.Pause.MutationOccurred
				if pendingCancellation != "" && mutationMayHaveOccurred {
					pendingCancellation = domain.OperationRollback
				}
				pauseCopy := *entry.Pause
				paused = &pauseCopy
			} else {
				paused = nil
			}
			continue
		}

		if machine == nil {
			return journalStreamError(index+1, "step precedes the initial transition")
		}
		if machine.State() == domain.OperationPaused {
			return journalStreamError(index+1, "step entry cannot execute while PAUSED")
		}
		if entry.OperationState != machine.State() {
			return journalStreamError(index+1, "step operationState does not match the current state")
		}
		if pendingCancellation != "" {
			if pendingCurrentStepID == "" && CanTransition(machine.State(), pendingCancellation) {
				return journalStreamError(index+1, "step follows a cancellation-safe boundary")
			}
			if pendingCurrentStepID != "" && entry.Step.ID != pendingCurrentStepID {
				return journalStreamError(index+1, "cancellation request does not match the in-flight step")
			}
			if pendingCurrentStepID != "" && entry.Step.StartedAt.After(pendingRequestedAt) {
				return journalStreamError(index+1, "matched step started after the cancellation request")
			}
		}
		stepStartBoundary := priorTime
		if pendingCurrentStepID != "" {
			stepStartBoundary = pendingStepStartBoundary
		}
		pendingCurrentStepID = ""
		pendingStepStartBoundary = time.Time{}
		pendingRequestedAt = time.Time{}
		if entry.Step.StartedAt.Before(stepStartBoundary) {
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
		mutationMayHaveOccurred = mutationMayHaveOccurred ||
			entry.Step.MutationOccurred || entry.Step.Outcome == domain.StepUnknown
		if pendingCancellation != "" && mutationMayHaveOccurred {
			pendingCancellation = domain.OperationRollback
		}
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
	switch entry.Kind {
	case domain.JournalEntryStep:
		entryID = entry.Step.ID
	case domain.JournalEntryCancellationRequest:
		entryID = "cancellation-request"
	}

	return fmt.Sprintf("%020d-%s.json", entry.Sequence, entryID), nil
}

func validateJournalCancellation(request domain.JournalCancellationRequest, recordedAt time.Time) error {
	if err := validateJournalTime("cancellation.requestedAt", request.RequestedAt); err != nil {
		return err
	}
	if !request.RequestedAt.Equal(recordedAt) {
		return journalEntryError("cancellation.requestedAt", "must equal recordedAt")
	}
	if !stepIDPattern.MatchString(request.CurrentStepID) {
		return journalEntryError("cancellation.currentStepId", "must be a canonical step identifier")
	}
	if !request.MutationObservation.Valid() {
		return journalEntryError("cancellation.mutationObservation", "unknown value")
	}
	wantRoute := domain.OperationCancelled
	if request.MutationObservation != domain.MutationNotOccurred {
		wantRoute = domain.OperationRollback
	}
	if request.RequiredRoute != wantRoute {
		return journalEntryError("cancellation.requiredRoute", "does not match the mutation observation")
	}

	return nil
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

func validateJournalPause(pause domain.JournalPause, recordedAt time.Time) error {
	if err := validateJournalTime("pause.pausedAt", pause.PausedAt); err != nil {
		return err
	}
	if recordedAt.Before(pause.PausedAt) {
		return journalEntryError("recordedAt", "must not precede pause.pausedAt")
	}
	if pause.PauseReason.String() == "" {
		return journalEntryError("pause.pauseReason", "must not be empty")
	}
	if err := validateJournalTime("pause.resumeBy", pause.ResumeBy); err != nil {
		return err
	}
	if !pause.ResumeBy.After(pause.PausedAt) {
		return journalEntryError("pause.resumeBy", "must be later than pausedAt")
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
