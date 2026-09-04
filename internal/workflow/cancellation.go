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
func (controller CancellationController) UIState(cancelSafe bool) string {
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
	if !controller.queued {
		return controller, CancellationDecision{Action: CancellationNone, UIState: cancellationAvailableUI}, nil
	}

	return routeCancellation(controller, current, mutationMayHaveOccurred)
}

func routeCancellation(controller CancellationController, current domain.OperationState, mutationMayHaveOccurred bool) (CancellationController, CancellationDecision, error) {
	target := domain.OperationCancelled
	action := CancellationCancel
	uiState := cancellationCancelUI
	if mutationMayHaveOccurred {
		target = domain.OperationRollback
		action = CancellationRollback
		uiState = cancellationRollbackUI
	}
	if !CanTransition(current, target) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: %s cannot route to %s", ErrInvalidCancellation, current, target)
	}

	return CancellationController{}, CancellationDecision{Action: action, Target: target, UIState: uiState}, nil
}
