// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"errors"
	"fmt"
)

// ErrInvalidExposureDelta is returned when a plan contains an unknown network
// exposure classification.
var ErrInvalidExposureDelta = errors.New("invalid exposure delta")

// ExposureDelta describes how a plan changes network reachability.
type ExposureDelta string

const (
	ExposureNone     ExposureDelta = "none"
	ExposurePrivate  ExposureDelta = "private"
	ExposureTunnel   ExposureDelta = "tunnel"
	ExposureExternal ExposureDelta = "external"
)

var exposureDeltas = [...]ExposureDelta{
	ExposureNone,
	ExposurePrivate,
	ExposureTunnel,
	ExposureExternal,
}

// ParseExposureDelta parses a stable serialized exposure classification.
func ParseExposureDelta(value string) (ExposureDelta, error) {
	delta := ExposureDelta(value)
	if !delta.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidExposureDelta, value)
	}

	return delta, nil
}

// Valid reports whether delta is a canonical exposure classification.
func (delta ExposureDelta) Valid() bool {
	for _, candidate := range exposureDeltas {
		if delta == candidate {
			return true
		}
	}

	return false
}

// MarshalText implements encoding.TextMarshaler.
func (delta ExposureDelta) MarshalText() ([]byte, error) {
	if !delta.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidExposureDelta, delta)
	}

	return []byte(delta), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (delta *ExposureDelta) UnmarshalText(text []byte) error {
	if delta == nil {
		return fmt.Errorf("%w: nil destination", ErrInvalidExposureDelta)
	}

	parsed, err := ParseExposureDelta(string(text))
	if err != nil {
		return err
	}

	*delta = parsed

	return nil
}
