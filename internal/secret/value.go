// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package secret contains in-memory secret values with safe formatting defaults.
package secret

import (
	"encoding/json"
	"fmt"
	"io"
)

const redacted = "[redacted]"

// Value owns a mutable copy of secret bytes. Its formatting and serialization
// methods never reveal the underlying value.
//
// A Value must not be copied after first use and must not be used concurrently.
// Call Zero as soon as the secret is no longer needed.
type Value struct {
	bytes []byte
}

// New creates a Value that owns a copy of value.
func New(value []byte) *Value {
	owned := make([]byte, len(value))
	copy(owned, value)

	return &Value{bytes: owned}
}

// Zero overwrites the owned bytes and releases the slice. It is idempotent.
func (value *Value) Zero() {
	if value == nil {
		return
	}

	for index := range value.bytes {
		value.bytes[index] = 0
	}
	value.bytes = nil
}

// Empty reports whether value contains no secret bytes.
func (value *Value) Empty() bool {
	return value == nil || len(value.bytes) == 0
}

// String implements fmt.Stringer without revealing secret material.
func (*Value) String() string {
	return redacted
}

// GoString implements fmt.GoStringer without revealing secret material.
func (*Value) GoString() string {
	return redacted
}

// Format prevents all fmt verbs from revealing secret material.
func (*Value) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redacted)
}

// MarshalJSON implements json.Marshaler without revealing secret material.
func (*Value) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// MarshalText implements encoding.TextMarshaler without revealing secret material.
func (*Value) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}
