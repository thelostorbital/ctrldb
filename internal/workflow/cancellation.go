// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"errors"
	"fmt"
	"sync/atomic"
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

// CancellationController is durable request state. Methods return the next
// value and a decision; the transition capability in a routed decision is a
// shared one-shot value across all decision copies.
type CancellationController struct {
	queued  bool
	target  domain.OperationState
	binding cancellationBinding
}

type cancellationBinding struct {
	operationID string
	planID      string
	sequence    uint64
	requestedAt time.Time
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
	machine    *Machine
	generation uint64
	from       domain.OperationState
	target     domain.OperationState
	binding    cancellationBinding
	used       atomic.Bool
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
func (controller CancellationController) Request(
	machine *Machine,
	request CancellationRequest,
	cancelSafe bool,
) (CancellationController, CancellationDecision, error) {
	if machine == nil {
		return controller, CancellationDecision{}, fmt.Errorf("%w: nil machine", ErrInvalidCancellation)
	}
	current := machine.State()
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
	if request.OperationState != current {
		return controller, CancellationDecision{}, fmt.Errorf("%w: request state does not match machine", ErrInvalidCancellation)
	}
	entry := cancellationJournalEntry(request, target)
	if err := ValidateJournalEntry(entry); err != nil {
		return controller, CancellationDecision{}, fmt.Errorf("%w: invalid request identity or boundary", ErrInvalidCancellation)
	}
	if !cancellationRouteReachable(current, target) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q has no safe cancellation route", ErrInvalidCancellation, current)
	}
	if !cancelSafe {
		return controller, CancellationDecision{
			Action:       CancellationPersist,
			JournalEntry: &entry,
			UIState:      cancellationUnavailableUI,
		}, nil
	}

	return routeCancellation(controller, machine, mutationMayHaveOccurred, cancellationBinding{
		operationID: request.OperationID,
		planID:      request.PlanID,
		sequence:    request.Sequence,
		requestedAt: request.RequestedAt,
	})
}

// AtBoundary honours a queued request. With no queued request it produces no
// transition and leaves the controller unchanged.
func (controller CancellationController) AtBoundary(
	machine *Machine,
	mutationMayHaveOccurred bool,
) (CancellationController, CancellationDecision, error) {
	if machine == nil {
		return controller, CancellationDecision{}, fmt.Errorf("%w: nil machine", ErrInvalidCancellation)
	}
	current := machine.State()
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

	return routeCancellationTo(controller, machine, target, controller.binding)
}

// ApplyCancellation advances machine only for a decision produced for its
// exact current state by CancellationController.
func (machine *Machine) ApplyCancellation(decision CancellationDecision) error {
	if machine == nil || decision.authorization == nil || decision.authorization.machine != machine ||
		decision.authorization.target != decision.Target ||
		decision.authorization.binding.operationID == "" || decision.authorization.binding.planID == "" ||
		decision.authorization.binding.sequence == 0 || decision.authorization.binding.requestedAt.IsZero() ||
		!cancellationActionMatchesTarget(decision.Action, decision.Target) {
		return fmt.Errorf("%w: missing or mismatched authorization", ErrInvalidCancellation)
	}
	if !decision.authorization.used.CompareAndSwap(false, true) {
		return fmt.Errorf("%w: cancellation authorization already consumed", ErrInvalidCancellation)
	}
	if decision.authorization.generation != machine.generation || decision.authorization.from != machine.State() {
		return fmt.Errorf("%w: cancellation boundary changed", ErrInvalidCancellation)
	}

	return machine.transition(decision.Target, true)
}

func cancellationActionMatchesTarget(action CancellationAction, target domain.OperationState) bool {
	return action == CancellationCancel && target == domain.OperationCancelled ||
		action == CancellationRollback && target == domain.OperationRollback
}

func routeCancellation(
	controller CancellationController,
	machine *Machine,
	mutationMayHaveOccurred bool,
	binding cancellationBinding,
) (CancellationController, CancellationDecision, error) {
	return routeCancellationTo(controller, machine, cancellationTarget(mutationMayHaveOccurred), binding)
}

func routeCancellationTo(
	controller CancellationController,
	machine *Machine,
	target domain.OperationState,
	binding cancellationBinding,
) (CancellationController, CancellationDecision, error) {
	current := machine.State()
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
		Action:  action,
		Target:  target,
		UIState: uiState,
		authorization: &cancellationAuthorization{
			machine: machine, generation: machine.generation, from: current, target: target, binding: binding,
		},
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
	var binding cancellationBinding
	for _, entry := range entries {
		if entry.Kind == domain.JournalEntryCancellationRequest {
			target = entry.Cancellation.RequiredRoute
			binding = cancellationBinding{
				operationID: entry.OperationID,
				planID:      entry.PlanID,
				sequence:    entry.Sequence,
				requestedAt: entry.Cancellation.RequestedAt,
			}
			continue
		}
		if target != "" && entry.Kind == domain.JournalEntryStep &&
			(entry.Step.MutationOccurred || entry.Step.Outcome == domain.StepUnknown) {
			target = domain.OperationRollback
		}
		if target != "" && entry.Kind == domain.JournalEntryTransition && entry.OperationState == target {
			target = ""
			binding = cancellationBinding{}
		}
	}

	return CancellationController{queued: target != "", target: target, binding: binding}, nil
}

func cancellationJournalEntry(request CancellationRequest, target domain.OperationState) domain.JournalEntry {
	return domain.JournalEntry{
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
