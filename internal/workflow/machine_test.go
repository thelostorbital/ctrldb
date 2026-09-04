// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow_test

import (
	"errors"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

func TestMachineHappyPath(t *testing.T) {
	t.Parallel()

	machine := workflow.NewMachine()
	transitionThrough(t, machine,
		domain.OperationValidate,
		domain.OperationPlan,
		domain.OperationApprovedWaiting,
		domain.OperationLock,
		domain.OperationProtect,
		domain.OperationExecute,
		domain.OperationVerify,
		domain.OperationDocument,
		domain.OperationComplete,
	)
}

func TestMachinePermitsSafeWriteToSkipProtection(t *testing.T) {
	t.Parallel()

	machine := workflow.NewMachine()
	transitionThrough(t, machine,
		domain.OperationValidate,
		domain.OperationPlan,
		domain.OperationLock,
		domain.OperationExecute,
		domain.OperationVerify,
		domain.OperationDocument,
		domain.OperationComplete,
	)
}

func TestPausedOperationMustRediscoverBeforeContinuing(t *testing.T) {
	t.Parallel()

	machine := machineAt(t, domain.OperationExecute)
	transitionThrough(t, machine, domain.OperationPaused)

	err := machine.Transition(domain.OperationExecute)
	if !errors.Is(err, workflow.ErrInvalidTransition) {
		t.Fatalf("Transition(PAUSED -> EXECUTE) error = %v, want ErrInvalidTransition", err)
	}
	if machine.State() != domain.OperationPaused {
		t.Fatalf("state changed after rejected transition: got %q", machine.State())
	}

	transitionThrough(t, machine, domain.OperationDiscover)
}

func TestMachineFailureBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		start domain.OperationState
		path  []domain.OperationState
	}{
		{
			name:  "failure before mutation",
			start: domain.OperationLock,
			path:  []domain.OperationState{domain.OperationFailed},
		},
		{
			name:  "verified rollback",
			start: domain.OperationExecute,
			path:  []domain.OperationState{domain.OperationRollback, domain.OperationVerifiedRollback},
		},
		{
			name:  "rollback cleanup failure",
			start: domain.OperationRollback,
			path:  []domain.OperationState{domain.OperationFailedCleanup},
		},
		{
			name:  "cancel before mutation",
			start: domain.OperationExecute,
			path:  []domain.OperationState{domain.OperationCancelled},
		},
		{
			name:  "failed verification",
			start: domain.OperationVerify,
			path:  []domain.OperationState{domain.OperationCompleteWithFailedVerification},
		},
		{
			name:  "documentation failure",
			start: domain.OperationDocument,
			path:  []domain.OperationState{domain.OperationCompleteWithDocumentationError},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			machine := machineAt(t, test.start)
			transitionThrough(t, machine, test.path...)
		})
	}
}

func TestTerminalStatesCannotTransition(t *testing.T) {
	t.Parallel()

	terminal := []domain.OperationState{
		domain.OperationComplete,
		domain.OperationCompleteWithFailedVerification,
		domain.OperationCompleteWithDocumentationError,
		domain.OperationVerifiedRollback,
		domain.OperationCancelled,
		domain.OperationFailed,
		domain.OperationFailedCleanup,
	}

	for _, state := range terminal {
		machine := machineAt(t, state)
		err := machine.Transition(domain.OperationDiscover)
		if !errors.Is(err, workflow.ErrInvalidTransition) {
			t.Errorf("Transition(%s -> DISCOVER) error = %v, want ErrInvalidTransition", state, err)
		}
		if machine.State() != state {
			t.Errorf("terminal state changed after rejected transition: got %q, want %q", machine.State(), state)
		}
	}
}

func TestMachineRejectsUnknownState(t *testing.T) {
	t.Parallel()

	unknown := domain.OperationState("UNKNOWN")
	if _, err := workflow.RestoreMachine(unknown); !errors.Is(err, domain.ErrInvalidOperationState) {
		t.Fatalf("RestoreMachine() error = %v, want ErrInvalidOperationState", err)
	}

	machine := workflow.NewMachine()
	if err := machine.Transition(unknown); !errors.Is(err, domain.ErrInvalidOperationState) {
		t.Fatalf("Transition() error = %v, want ErrInvalidOperationState", err)
	}
	if machine.State() != domain.OperationDiscover {
		t.Fatalf("state changed after rejected transition: got %q", machine.State())
	}
}

func machineAt(t *testing.T, state domain.OperationState) *workflow.Machine {
	t.Helper()

	machine, err := workflow.RestoreMachine(state)
	if err != nil {
		t.Fatalf("RestoreMachine(%q) returned an error: %v", state, err)
	}

	return machine
}

func transitionThrough(t *testing.T, machine *workflow.Machine, states ...domain.OperationState) {
	t.Helper()

	for _, state := range states {
		if err := machine.Transition(state); err != nil {
			t.Fatalf("Transition(%q -> %q) returned an error: %v", machine.State(), state, err)
		}
	}
}
