// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"errors"
	"fmt"
)

// ErrInvalidEnvironmentClass is returned when an environment class is not in
// the closed manifest registry.
var ErrInvalidEnvironmentClass = errors.New("invalid environment class")

// EnvironmentClass selects the baseline safety policy for one environment.
type EnvironmentClass string

const (
	EnvironmentProduction EnvironmentClass = "production"
	EnvironmentStaging    EnvironmentClass = "staging"
	EnvironmentRehearsal  EnvironmentClass = "rehearsal"
	EnvironmentDisposable EnvironmentClass = "disposable"
)

var environmentClasses = [...]EnvironmentClass{
	EnvironmentProduction,
	EnvironmentStaging,
	EnvironmentRehearsal,
	EnvironmentDisposable,
}

// EnvironmentClasses returns a copy of the canonical class registry.
func EnvironmentClasses() []EnvironmentClass {
	classes := make([]EnvironmentClass, len(environmentClasses))
	copy(classes, environmentClasses[:])

	return classes
}

// ParseEnvironmentClass parses a stable serialized environment class.
func ParseEnvironmentClass(value string) (EnvironmentClass, error) {
	class := EnvironmentClass(value)
	if !class.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidEnvironmentClass, value)
	}

	return class, nil
}

// Valid reports whether class belongs to the canonical registry.
func (class EnvironmentClass) Valid() bool {
	for _, candidate := range environmentClasses {
		if class == candidate {
			return true
		}
	}

	return false
}

// MarshalText implements encoding.TextMarshaler.
func (class EnvironmentClass) MarshalText() ([]byte, error) {
	if !class.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidEnvironmentClass, class)
	}

	return []byte(class), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (class *EnvironmentClass) UnmarshalText(text []byte) error {
	if class == nil {
		return fmt.Errorf("%w: nil destination", ErrInvalidEnvironmentClass)
	}

	parsed, err := ParseEnvironmentClass(string(text))
	if err != nil {
		return err
	}

	*class = parsed

	return nil
}
