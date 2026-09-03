// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package workflow implements the generic, resource-independent workflow engine.
package workflow

import (
	"errors"
	"fmt"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

// ErrInvalidTransition is returned when a workflow attempts an undefined state
// transition. The current state is unchanged when this error is returned.
var ErrInvalidTransition = errors.New("invalid operation transition")

var transitions = map[domain.OperationState]map[domain.OperationState]struct{}{
	domain.OperationDiscover: {
		domain.OperationValidate: {},
		domain.OperationFailed:   {},
	},
	domain.OperationValidate: {
		domain.OperationPlan:   {},
		domain.OperationFailed: {},
	},
	domain.OperationPlan: {
		domain.OperationApprovedWaiting: {},
		domain.OperationLock:            {},
		domain.OperationFailed:          {},
	},
	domain.OperationApprovedWaiting: {
		domain.OperationLock: {},
	},
	domain.OperationLock: {
		domain.OperationProtect: {},
		domain.OperationExecute: {},
		domain.OperationFailed:  {},
	},
	domain.OperationProtect: {
		domain.OperationExecute:  {},
		domain.OperationPaused:   {},
		domain.OperationRollback: {},
		domain.OperationFailed:   {},
	},
	domain.OperationExecute: {
		domain.OperationPaused:   {},
		domain.OperationVerify:   {},
		domain.OperationRollback: {},
		domain.OperationFailed:   {},
	},
	domain.OperationPaused: {
		domain.OperationDiscover: {},
		domain.OperationRollback: {},
		domain.OperationFailed:   {},
	},
	domain.OperationVerify: {
		domain.OperationDocument:                       {},
		domain.OperationCompleteWithFailedVerification: {},
		domain.OperationRollback:                       {},
	},
	domain.OperationDocument: {
		domain.OperationComplete:                       {},
		domain.OperationCompleteWithDocumentationError: {},
	},
	domain.OperationRollback: {
		domain.OperationVerifiedRollback: {},
		domain.OperationFailedCleanup:    {},
	},
}

// Machine validates durable operation-state transitions. Persistence and
// side-effects are deliberately owned by higher-level engine components.
type Machine struct {
	state domain.OperationState
}

// NewMachine creates a workflow at its mandatory discovery boundary.
func NewMachine() *Machine {
	return &Machine{state: domain.OperationDiscover}
}

// RestoreMachine validates and restores a previously journaled state.
func RestoreMachine(state domain.OperationState) (*Machine, error) {
	if !state.Valid() {
		return nil, fmt.Errorf("%w: restore %q", domain.ErrInvalidOperationState, state)
	}

	return &Machine{state: state}, nil
}

// State returns the current durable operation state.
func (machine *Machine) State() domain.OperationState {
	return machine.state
}

// CanTransition reports whether from may transition directly to to.
func CanTransition(from, to domain.OperationState) bool {
	if !from.Valid() || !to.Valid() {
		return false
	}

	_, ok := transitions[from][to]

	return ok
}

// Transition advances the machine if the transition is allowed.
func (machine *Machine) Transition(next domain.OperationState) error {
	if machine == nil {
		return fmt.Errorf("%w: nil machine", ErrInvalidTransition)
	}
	if !next.Valid() {
		return fmt.Errorf("%w: %q", domain.ErrInvalidOperationState, next)
	}
	if !CanTransition(machine.state, next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, machine.state, next)
	}

	machine.state = next

	return nil
}
