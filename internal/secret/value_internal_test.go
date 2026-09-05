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
	value.access(func(owned *[]byte) {
		if string(*owned) != "SECRET_MARKER_COPY_2" {
			t.Fatalf("owned bytes = %q, want an independent copy", *owned)
		}
	})
}

func TestValueZeroOverwritesOwnedBytes(t *testing.T) {
	t.Parallel()

	value := New([]byte("SECRET_MARKER_ZERO_4"))
	var owned []byte
	value.access(func(stored *[]byte) {
		owned = *stored
	})
	value.Zero()

	for index, element := range owned {
		if element != 0 {
			t.Fatalf("owned byte %d was not zeroed", index)
		}
	}
	if value.access != nil {
		t.Fatal("Value retained its storage closure after Zero")
	}
}
