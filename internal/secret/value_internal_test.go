// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package secret

import "testing"

func TestValueOwnsInput(t *testing.T) {
	t.Parallel()

	input := []byte("SECRET_MARKER_COPY_2")
	value := New(input)
	t.Cleanup(value.Zero)

	input[0] = 'X'
	if string(value.bytes) != "SECRET_MARKER_COPY_2" {
		t.Fatalf("owned bytes = %q, want an independent copy", value.bytes)
	}
}

func TestValueZeroOverwritesOwnedBytes(t *testing.T) {
	t.Parallel()

	value := New([]byte("SECRET_MARKER_ZERO_4"))
	owned := value.bytes
	value.Zero()

	for index, element := range owned {
		if element != 0 {
			t.Fatalf("owned byte %d was not zeroed", index)
		}
	}
	if value.bytes != nil {
		t.Fatal("Value retained its byte slice after Zero")
	}
}
