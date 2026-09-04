// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package secret_test

import (
	"encoding/json"
	"fmt"
	"reflect"
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

func TestValueZeroIsIdempotent(t *testing.T) {
	t.Parallel()

	value := secret.New([]byte("SECRET_MARKER_ZERO_3"))
	value.Zero()
	value.Zero()

	if !value.Empty() {
		t.Fatal("Value.Empty() = false after Zero()")
	}
}

func TestNilValueIsSafe(t *testing.T) {
	t.Parallel()

	var value *secret.Value
	value.Zero()
	if !value.Empty() {
		t.Fatal("nil Value.Empty() = false, want true")
	}
	if fmt.Sprint(value) != "[redacted]" {
		t.Fatal("nil Value formatting did not return [redacted]")
	}
}

func TestValuePublicMethodSurfaceIsRedactingOrNonRevealing(t *testing.T) {
	t.Parallel()

	valueType := reflect.TypeOf((*secret.Value)(nil))
	want := []string{"Empty", "Format", "GoString", "MarshalJSON", "MarshalText", "String", "Zero"}
	if valueType.NumMethod() != len(want) {
		t.Fatalf("public method count = %d, want %d", valueType.NumMethod(), len(want))
	}
	for index, name := range want {
		if method := valueType.Method(index); method.Name != name {
			t.Fatalf("public method %d = %q, want %q", index, method.Name, name)
		}
	}
}
