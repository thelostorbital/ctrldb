// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package secret_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/secret"
)

func TestValueNeverFormatsOrSerializesItsSecret(t *testing.T) {
	t.Parallel()

	value := secret.New([]byte("SECRET_MARKER_FORMAT_1"))
	t.Cleanup(value.Zero)

	formatted := []string{
		fmt.Sprint(value),
		fmt.Sprintf("%s", value),
		fmt.Sprintf("%q", value),
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%+v", value),
		fmt.Sprintf("%#v", value),
	}
	for _, output := range formatted {
		if output != "[redacted]" {
			t.Errorf("formatted Value = %q, want [redacted]", output)
		}
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() returned an error: %v", err)
	}
	if string(encoded) != `"[redacted]"` {
		t.Fatalf("json.Marshal() = %s, want a redaction marker", encoded)
	}

	text, err := value.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() returned an error: %v", err)
	}
	if string(text) != "[redacted]" {
		t.Fatalf("MarshalText() = %q, want [redacted]", text)
	}
}

func TestValueOwnsInputAndRevealReturnsACopy(t *testing.T) {
	t.Parallel()

	input := []byte("SECRET_MARKER_COPY_2")
	value := secret.New(input)
	t.Cleanup(value.Zero)

	input[0] = 'X'
	revealed := value.Reveal()
	t.Cleanup(func() { clear(revealed) })

	if string(revealed) != "SECRET_MARKER_COPY_2" {
		t.Fatalf("Reveal() = %q, want the original copied value", revealed)
	}

	revealed[0] = 'Y'
	second := value.Reveal()
	t.Cleanup(func() { clear(second) })
	if string(second) != "SECRET_MARKER_COPY_2" {
		t.Fatal("mutating revealed bytes changed the owned secret")
	}
}

func TestValueZeroIsIdempotent(t *testing.T) {
	t.Parallel()

	value := secret.New([]byte("SECRET_MARKER_ZERO_3"))
	value.Zero()
	value.Zero()

	if !value.Empty() {
		t.Fatal("Value.Empty() = false after Zero()")
	}
	if revealed := value.Reveal(); revealed != nil {
		t.Fatalf("Value.Reveal() after Zero() = %v, want nil", revealed)
	}
}

func TestNilValueIsSafe(t *testing.T) {
	t.Parallel()

	var value *secret.Value
	value.Zero()
	if !value.Empty() {
		t.Fatal("nil Value.Empty() = false, want true")
	}
	if !slices.Equal(value.Reveal(), nil) {
		t.Fatal("nil Value.Reveal() did not return nil")
	}
	if fmt.Sprint(value) != "[redacted]" {
		t.Fatal("nil Value formatting did not return [redacted]")
	}
}
