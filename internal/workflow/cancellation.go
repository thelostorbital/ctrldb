// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"errors"
	"fmt"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

// ErrInvalidCancellation is returned when a cancellation decision cannot be
// represented safely by the operation state machine.
var ErrInvalidCancellation = errors.New("invalid cancellation decision")

// CancellationAction is the pure engine action chosen for a request.
type CancellationAction string

const (
	CancellationNone     CancellationAction = "none"
	CancellationQueued   CancellationAction = "queued"
	CancellationCancel   CancellationAction = "cancel"
	CancellationRollback CancellationAction = "rollback"
)

const (
	cancellationAvailableUI   = "Cancellation is available at this safe boundary."
	cancellationUnavailableUI = "Cancellation is unavailable during this step; a request will be queued."
	cancellationNoRouteUI     = "Cancellation is unavailable in this operation state."
	cancellationQueuedUI      = "Cancellation queued; operation will stop at the next safe boundary."
	cancellationCancelUI      = "Cancellation accepted; no mutation may have occurred."
	cancellationRollbackUI    = "Cancellation accepted; rollback and independent verification are required."
)

// CancellationController is immutable request state. Methods return the next
// value and a decision, making cancellation deterministic and side-effect free.
type CancellationController struct {
	queued bool
}

// CancellationDecision tells the engine whether to queue or transition.
type CancellationDecision struct {
	Action  CancellationAction
	Target  domain.OperationState
	UIState string
}

// Pending reports whether a cancellation waits for a safe boundary.
func (controller CancellationController) Pending() bool { return controller.queued }

// UIState returns the stable operator-facing state for the current boundary.
func (controller CancellationController) UIState(current domain.OperationState, cancelSafe, mutationMayHaveOccurred bool) string {
	target := cancellationTarget(mutationMayHaveOccurred)
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

// Request queues cancellation during unsafe in-flight work or immediately
// routes a safe boundary according to whether mutation may have occurred.
func (controller CancellationController) Request(current domain.OperationState, cancelSafe, mutationMayHaveOccurred bool) (CancellationController, CancellationDecision, error) {
	if !current.Valid() || current.Terminal() {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q cannot accept cancellation", ErrInvalidCancellation, current)
	}
	target := cancellationTarget(mutationMayHaveOccurred)
	if !cancellationRouteReachable(current, target) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q has no safe cancellation route", ErrInvalidCancellation, current)
	}
	if !cancelSafe {
		return CancellationController{queued: true}, CancellationDecision{
			Action:  CancellationQueued,
			UIState: cancellationQueuedUI,
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
	if !CanTransition(current, cancellationTarget(mutationMayHaveOccurred)) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q has no safe cancellation route", ErrInvalidCancellation, current)
	}
	if !controller.queued {
		return controller, CancellationDecision{Action: CancellationNone, UIState: cancellationAvailableUI}, nil
	}

	return routeCancellation(controller, current, mutationMayHaveOccurred)
}

func routeCancellation(controller CancellationController, current domain.OperationState, mutationMayHaveOccurred bool) (CancellationController, CancellationDecision, error) {
	target := cancellationTarget(mutationMayHaveOccurred)
	action := CancellationCancel
	uiState := cancellationCancelUI
	if mutationMayHaveOccurred {
		action = CancellationRollback
		uiState = cancellationRollbackUI
	}
	if !CanTransition(current, target) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: %s cannot route to %s", ErrInvalidCancellation, current, target)
	}

	return CancellationController{}, CancellationDecision{Action: action, Target: target, UIState: uiState}, nil
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
