// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"errors"
	"fmt"
)

// ErrInvalidApprovalClass is returned when an approval class is unknown.
var ErrInvalidApprovalClass = errors.New("invalid approval class")

// ApprovalClass is the minimum operator interaction required for a plan.
// Higher values require stronger safeguards.
type ApprovalClass uint8

const (
	ApprovalRead ApprovalClass = iota
	ApprovalSafeWrite
	ApprovalProtected
	ApprovalSecuritySensitive
	ApprovalDestructive
	ApprovalDataDestructive
	approvalClassCount
)

var approvalClassNames = [...]string{
	"read",
	"safe-write",
	"protected",
	"security-sensitive",
	"destructive",
	"data-destructive",
}

// ParseApprovalClass parses the stable serialized name of an approval class.
// It deliberately rejects aliases and surrounding whitespace.
func ParseApprovalClass(value string) (ApprovalClass, error) {
	for class, name := range approvalClassNames {
		if value == name {
			return ApprovalClass(class), nil
		}
	}

	return 0, fmt.Errorf("%w: %q", ErrInvalidApprovalClass, value)
}

// Valid reports whether class is one of the defined approval classes.
func (class ApprovalClass) Valid() bool {
	return class < approvalClassCount
}

// String returns the stable serialized name of class.
func (class ApprovalClass) String() string {
	if !class.Valid() {
		return fmt.Sprintf("ApprovalClass(%d)", class)
	}

	return approvalClassNames[class]
}

// MarshalText implements encoding.TextMarshaler.
func (class ApprovalClass) MarshalText() ([]byte, error) {
	if !class.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrInvalidApprovalClass, class)
	}

	return []byte(class.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (class *ApprovalClass) UnmarshalText(text []byte) error {
	if class == nil {
		return fmt.Errorf("%w: nil destination", ErrInvalidApprovalClass)
	}

	parsed, err := ParseApprovalClass(string(text))
	if err != nil {
		return err
	}

	*class = parsed

	return nil
}

// MaxApprovalClass returns the strongest class in classes. Invalid values and
// an empty input are errors so classification can never silently weaken.
func MaxApprovalClass(classes ...ApprovalClass) (ApprovalClass, error) {
	if len(classes) == 0 {
		return 0, fmt.Errorf("%w: empty input", ErrInvalidApprovalClass)
	}

	strongest := ApprovalRead
	for _, class := range classes {
		if !class.Valid() {
			return 0, fmt.Errorf("%w: %d", ErrInvalidApprovalClass, class)
		}
		if class > strongest {
			strongest = class
		}
	}

	return strongest, nil
}
