// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

func TestCancellationQueuesUntilSafeBoundary_TEST_U_PLAN_05(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	next, decision, err := controller.Request(domain.OperationExecute, false, true)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	if !next.Pending() || decision.Action != workflow.CancellationQueued || decision.Target != "" {
		t.Fatalf("unsafe cancellation decision = %#v, pending=%t", decision, next.Pending())
	}
	if decision.UIState != next.UIState(domain.OperationExecute, false, true) || !strings.Contains(decision.UIState, "queued") {
		t.Fatalf("queued UI state mismatch: %q / %q", decision.UIState, next.UIState(domain.OperationExecute, false, true))
	}

	cleared, decision, err := next.AtBoundary(domain.OperationExecute, true)
	if err != nil {
		t.Fatalf("AtBoundary() returned an error: %v", err)
	}
	if cleared.Pending() || decision.Action != workflow.CancellationRollback || decision.Target != domain.OperationRollback {
		t.Fatalf("mutated boundary decision = %#v, pending=%t", decision, cleared.Pending())
	}
}

func TestCancellationRoutesPreMutationDirectlyToCancelled(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	next, decision, err := controller.Request(domain.OperationLock, true, false)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	if next.Pending() || decision.Action != workflow.CancellationCancel || decision.Target != domain.OperationCancelled {
		t.Fatalf("pre-mutation decision = %#v, pending=%t", decision, next.Pending())
	}
}

func TestCancellationFailsClosedOnUnsafeRoutes(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	if _, _, err := controller.Request(domain.OperationComplete, true, false); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("terminal Request() error = %v, want ErrInvalidCancellation", err)
	}
	if _, decision, err := controller.Request(domain.OperationExecute, true, false); err != nil || decision.Target != domain.OperationCancelled {
		t.Fatalf("EXECUTE pre-mutation cancellation = (%#v, %v), want CANCELLED", decision, err)
	}
	if _, _, err := controller.Request(domain.OperationLock, true, true); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("LOCK rollback error = %v, want ErrInvalidCancellation", err)
	}
	if _, _, err := controller.Request(domain.OperationDocument, false, false); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("unreachable queued cancellation error = %v, want ErrInvalidCancellation", err)
	}
	if _, _, err := controller.AtBoundary(domain.OperationDocument, false); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("unreachable boundary cancellation error = %v, want ErrInvalidCancellation", err)
	}
	if state := controller.UIState(domain.OperationDocument, true, false); !strings.Contains(state, "unavailable") {
		t.Fatalf("DOCUMENT UI state = %q, want unavailable", state)
	}
	if _, _, err := controller.Request(domain.OperationVerify, false, false); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("VERIFY pre-mutation queued cancellation error = %v, want ErrInvalidCancellation", err)
	}
	if state := controller.UIState(domain.OperationVerify, false, false); !strings.Contains(state, "unavailable") {
		t.Fatalf("VERIFY pre-mutation UI state = %q, want unavailable", state)
	}
}
