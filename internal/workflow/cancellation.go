// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"errors"
	"fmt"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

// ErrInvalidCancellation is returned when a cancellation decision cannot be
// represented safely by the operation state machine.
var ErrInvalidCancellation = errors.New("invalid cancellation decision")

// CancellationAction is the pure engine action chosen for a request.
type CancellationAction string

const (
	CancellationNone     CancellationAction = "none"
	CancellationPersist  CancellationAction = "persist-request"
	CancellationCancel   CancellationAction = "cancel"
	CancellationRollback CancellationAction = "rollback"
)

const (
	cancellationAvailableUI   = "Cancellation is available at this safe boundary."
	cancellationUnavailableUI = "Cancellation requires a durable request before the next safe boundary."
	cancellationNoRouteUI     = "Cancellation is unavailable in this operation state."
	cancellationQueuedUI      = "Cancellation queued; operation will stop at the next safe boundary."
	cancellationCancelUI      = "Cancellation accepted; no mutation may have occurred."
	cancellationRollbackUI    = "Cancellation accepted; rollback and independent verification are required."
)

// CancellationController is immutable request state. Methods return the next
// value and a decision, making cancellation deterministic and side-effect free.
type CancellationController struct {
	queued bool
	target domain.OperationState
}

// CancellationRequest contains the complete data needed to construct the
// durable journal record for a request made during an unsafe in-flight step.
type CancellationRequest struct {
	OperationID         string
	PlanID              string
	Sequence            uint64
	RequestedAt         time.Time
	OperationState      domain.OperationState
	CurrentStepID       string
	MutationObservation domain.MutationObservation
}

// CancellationDecision tells the engine whether to queue or transition.
type CancellationDecision struct {
	Action        CancellationAction
	Target        domain.OperationState
	JournalEntry  *domain.JournalEntry
	UIState       string
	authorization *cancellationAuthorization
}

type cancellationAuthorization struct {
	from   domain.OperationState
	target domain.OperationState
}

// Pending reports whether a cancellation waits for a safe boundary.
func (controller CancellationController) Pending() bool { return controller.queued }

// UIState returns the stable operator-facing state for the current boundary.
func (controller CancellationController) UIState(current domain.OperationState, cancelSafe, mutationMayHaveOccurred bool) string {
	target := cancellationTarget(mutationMayHaveOccurred)
	if controller.queued && controller.target == domain.OperationRollback {
		target = domain.OperationRollback
	}
	if !current.Valid() || current.Terminal() ||
		(cancelSafe && !CanTransition(current, target)) ||
		(!cancelSafe && !cancellationRouteReachable(current, target)) {
		return cancellationNoRouteUI
	}
	if controller.queued {
		return cancellationQueuedUI
	}
	if !cancelSafe {
		return cancellationUnavailableUI
	}

	return cancellationAvailableUI
}

// Request returns a durable record to persist during unsafe in-flight work or
// immediately routes a safe boundary according to observed mutation state.
func (controller CancellationController) Request(request CancellationRequest, cancelSafe bool) (CancellationController, CancellationDecision, error) {
	current := request.OperationState
	if controller.queued {
		return controller, CancellationDecision{}, fmt.Errorf("%w: cancellation request already recorded", ErrInvalidCancellation)
	}
	if !current.Valid() || current.Terminal() {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q cannot accept cancellation", ErrInvalidCancellation, current)
	}
	if !request.MutationObservation.Valid() {
		return controller, CancellationDecision{}, fmt.Errorf("%w: invalid mutation observation", ErrInvalidCancellation)
	}
	mutationMayHaveOccurred := request.MutationObservation != domain.MutationNotOccurred
	target := cancellationTarget(mutationMayHaveOccurred)
	if !cancellationRouteReachable(current, target) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q has no safe cancellation route", ErrInvalidCancellation, current)
	}
	if !cancelSafe {
		entry := domain.JournalEntry{
			Schema:         domain.JournalSchemaV1,
			OperationID:    request.OperationID,
			PlanID:         request.PlanID,
			Sequence:       request.Sequence,
			Kind:           domain.JournalEntryCancellationRequest,
			RecordedAt:     request.RequestedAt,
			OperationState: request.OperationState,
			Cancellation: &domain.JournalCancellationRequest{
				RequestedAt:         request.RequestedAt,
				CurrentStepID:       request.CurrentStepID,
				MutationObservation: request.MutationObservation,
				RequiredRoute:       target,
			},
		}
		if err := ValidateJournalEntry(entry); err != nil {
			return controller, CancellationDecision{}, fmt.Errorf("%w: invalid durable request", ErrInvalidCancellation)
		}

		return controller, CancellationDecision{
			Action:       CancellationPersist,
			JournalEntry: &entry,
			UIState:      cancellationUnavailableUI,
		}, nil
	}

	return routeCancellation(controller, current, mutationMayHaveOccurred)
}

// AtBoundary honours a queued request. With no queued request it produces no
// transition and leaves the controller unchanged.
func (controller CancellationController) AtBoundary(current domain.OperationState, mutationMayHaveOccurred bool) (CancellationController, CancellationDecision, error) {
	if !current.Valid() || current.Terminal() {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q cannot reach a cancellation boundary", ErrInvalidCancellation, current)
	}
	target := cancellationTarget(mutationMayHaveOccurred)
	if controller.queued && controller.target == domain.OperationRollback {
		target = domain.OperationRollback
	}
	if !CanTransition(current, target) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q has no safe cancellation route", ErrInvalidCancellation, current)
	}
	if !controller.queued {
		return controller, CancellationDecision{Action: CancellationNone, UIState: cancellationAvailableUI}, nil
	}

	return routeCancellationTo(controller, current, target)
}

// ApplyCancellation advances machine only for a decision produced for its
// exact current state by CancellationController.
func (machine *Machine) ApplyCancellation(decision CancellationDecision) error {
	if machine == nil || decision.authorization == nil || decision.authorization.from != machine.State() ||
		decision.authorization.target != decision.Target ||
		(decision.Action != CancellationCancel && decision.Action != CancellationRollback) {
		return fmt.Errorf("%w: missing or mismatched authorization", ErrInvalidCancellation)
	}

	return machine.transition(decision.Target, true)
}

func routeCancellation(controller CancellationController, current domain.OperationState, mutationMayHaveOccurred bool) (CancellationController, CancellationDecision, error) {
	return routeCancellationTo(controller, current, cancellationTarget(mutationMayHaveOccurred))
}

func routeCancellationTo(controller CancellationController, current, target domain.OperationState) (CancellationController, CancellationDecision, error) {
	action := CancellationCancel
	uiState := cancellationCancelUI
	if target == domain.OperationRollback {
		action = CancellationRollback
		uiState = cancellationRollbackUI
	}
	if !CanTransition(current, target) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: %s cannot route to %s", ErrInvalidCancellation, current, target)
	}

	return CancellationController{}, CancellationDecision{
		Action:        action,
		Target:        target,
		UIState:       uiState,
		authorization: &cancellationAuthorization{from: current, target: target},
	}, nil
}

// RestoreCancellationController validates a complete journal and reconstructs
// only a cancellation request that was durably recorded but not yet routed.
func RestoreCancellationController(entries []domain.JournalEntry, operationID, planID string) (CancellationController, error) {
	if err := ValidateJournal(entries); err != nil {
		return CancellationController{}, fmt.Errorf("%w: invalid journal", ErrInvalidCancellation)
	}
	if len(entries) == 0 || entries[0].OperationID != operationID || entries[0].PlanID != planID {
		return CancellationController{}, fmt.Errorf("%w: journal binding mismatch", ErrInvalidCancellation)
	}

	var target domain.OperationState
	for _, entry := range entries {
		if entry.Kind == domain.JournalEntryCancellationRequest {
			target = entry.Cancellation.RequiredRoute
			continue
		}
		if target != "" && entry.Kind == domain.JournalEntryStep &&
			(entry.Step.MutationOccurred || entry.Step.Outcome == domain.StepUnknown) {
			target = domain.OperationRollback
		}
		if target != "" && entry.Kind == domain.JournalEntryTransition && entry.OperationState == target {
			target = ""
		}
	}

	return CancellationController{queued: target != "", target: target}, nil
}

func cancellationTarget(mutationMayHaveOccurred bool) domain.OperationState {
	if mutationMayHaveOccurred {
		return domain.OperationRollback
	}

	return domain.OperationCancelled
}

func cancellationRouteReachable(current, target domain.OperationState) bool {
	visited := map[domain.OperationState]bool{current: true}
	pending := []domain.OperationState{current}
	for len(pending) != 0 {
		state := pending[0]
		pending = pending[1:]
		if CanTransition(state, target) {
			return true
		}
		for next := range transitions[state] {
			if !next.Terminal() && !visited[next] {
				visited[next] = true
				pending = append(pending, next)
			}
		}
	}

	return false
}
