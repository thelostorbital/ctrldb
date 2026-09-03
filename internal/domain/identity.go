// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"errors"
	"fmt"
)

// ErrInvalidExecutionIdentity is returned when a serialized execution identity
// is not part of the closed plan and audit registry.
var ErrInvalidExecutionIdentity = errors.New("invalid execution identity")

// ExecutionIdentity identifies the principal or execution context responsible
// for a workflow step. These names are stable persisted values.
type ExecutionIdentity string

const (
	IdentityHuman           ExecutionIdentity = "human"
	IdentityOperator        ExecutionIdentity = "operator"
	IdentityProvisioner     ExecutionIdentity = "provisioner"
	IdentityDestructive     ExecutionIdentity = "destructive"
	IdentityVM              ExecutionIdentity = "vm"
	IdentityReconciler      ExecutionIdentity = "reconciler"
	IdentityTransfer        ExecutionIdentity = "transfer"
	IdentityRestore         ExecutionIdentity = "restore"
	IdentityRecovery        ExecutionIdentity = "recovery"
	IdentityTestOperator    ExecutionIdentity = "test-operator"
	IdentityTestDestructive ExecutionIdentity = "test-destructive"
	IdentityHost            ExecutionIdentity = "host"
)

var executionIdentities = [...]ExecutionIdentity{
	IdentityHuman,
	IdentityOperator,
	IdentityProvisioner,
	IdentityDestructive,
	IdentityVM,
	IdentityReconciler,
	IdentityTransfer,
	IdentityRestore,
	IdentityRecovery,
	IdentityTestOperator,
	IdentityTestDestructive,
	IdentityHost,
}

// ExecutionIdentities returns a copy of the canonical identity registry.
func ExecutionIdentities() []ExecutionIdentity {
	identities := make([]ExecutionIdentity, len(executionIdentities))
	copy(identities, executionIdentities[:])

	return identities
}

// ParseExecutionIdentity parses a stable serialized execution identity.
func ParseExecutionIdentity(value string) (ExecutionIdentity, error) {
	identity := ExecutionIdentity(value)
	if !identity.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidExecutionIdentity, value)
	}

	return identity, nil
}

// Valid reports whether identity belongs to the canonical registry.
func (identity ExecutionIdentity) Valid() bool {
	for _, candidate := range executionIdentities {
		if identity == candidate {
			return true
		}
	}

	return false
}

// MarshalText implements encoding.TextMarshaler.
func (identity ExecutionIdentity) MarshalText() ([]byte, error) {
	if !identity.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidExecutionIdentity, identity)
	}

	return []byte(identity), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (identity *ExecutionIdentity) UnmarshalText(text []byte) error {
	if identity == nil {
		return fmt.Errorf("%w: nil destination", ErrInvalidExecutionIdentity)
	}

	parsed, err := ParseExecutionIdentity(string(text))
	if err != nil {
		return err
	}

	*identity = parsed

	return nil
}
