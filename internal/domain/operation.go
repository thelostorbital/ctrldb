// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"errors"
	"fmt"
)

// ErrInvalidOperationState is returned when an operation state is unknown.
var ErrInvalidOperationState = errors.New("invalid operation state")

// OperationState is a durable state in the workflow lifecycle.
type OperationState string

const (
	OperationDiscover                       OperationState = "DISCOVER"
	OperationValidate                       OperationState = "VALIDATE"
	OperationPlan                           OperationState = "PLAN"
	OperationApprovedWaiting                OperationState = "APPROVED_WAITING"
	OperationLock                           OperationState = "LOCK"
	OperationProtect                        OperationState = "PROTECT"
	OperationExecute                        OperationState = "EXECUTE"
	OperationPaused                         OperationState = "PAUSED"
	OperationVerify                         OperationState = "VERIFY"
	OperationDocument                       OperationState = "DOCUMENT"
	OperationRollback                       OperationState = "ROLLBACK"
	OperationComplete                       OperationState = "COMPLETE"
	OperationCompleteWithFailedVerification OperationState = "COMPLETE_WITH_FAILED_VERIFICATION"
	OperationCompleteWithDocumentationError OperationState = "COMPLETE_WITH_DOCUMENTATION_ERROR"
	OperationVerifiedRollback               OperationState = "VERIFIED_ROLLBACK"
	OperationCancelled                      OperationState = "CANCELLED"
	OperationFailed                         OperationState = "FAILED"
	OperationFailedCleanup                  OperationState = "FAILED_CLEANUP"
)

var operationStates = [...]OperationState{
	OperationDiscover,
	OperationValidate,
	OperationPlan,
	OperationApprovedWaiting,
	OperationLock,
	OperationProtect,
	OperationExecute,
	OperationPaused,
	OperationVerify,
	OperationDocument,
	OperationRollback,
	OperationComplete,
	OperationCompleteWithFailedVerification,
	OperationCompleteWithDocumentationError,
	OperationVerifiedRollback,
	OperationCancelled,
	OperationFailed,
	OperationFailedCleanup,
}

var terminalOperationStates = map[OperationState]struct{}{
	OperationComplete:                       {},
	OperationCompleteWithFailedVerification: {},
	OperationCompleteWithDocumentationError: {},
	OperationVerifiedRollback:               {},
	OperationCancelled:                      {},
	OperationFailed:                         {},
	OperationFailedCleanup:                  {},
}

// ParseOperationState parses the stable serialized name of an operation state.
func ParseOperationState(value string) (OperationState, error) {
	state := OperationState(value)
	if !state.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidOperationState, value)
	}

	return state, nil
}

// Valid reports whether state is a canonical operation state.
func (state OperationState) Valid() bool {
	for _, candidate := range operationStates {
		if state == candidate {
			return true
		}
	}

	return false
}

// Terminal reports whether no transition may leave state.
func (state OperationState) Terminal() bool {
	_, ok := terminalOperationStates[state]

	return ok
}

// MarshalText implements encoding.TextMarshaler.
func (state OperationState) MarshalText() ([]byte, error) {
	if !state.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidOperationState, state)
	}

	return []byte(state), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (state *OperationState) UnmarshalText(text []byte) error {
	if state == nil {
		return fmt.Errorf("%w: nil destination", ErrInvalidOperationState)
	}

	parsed, err := ParseOperationState(string(text))
	if err != nil {
		return err
	}

	*state = parsed

	return nil
}
