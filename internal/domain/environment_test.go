// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestEnvironmentClassRegistry(t *testing.T) {
	t.Parallel()

	want := []domain.EnvironmentClass{
		domain.EnvironmentProduction,
		domain.EnvironmentStaging,
		domain.EnvironmentRehearsal,
		domain.EnvironmentDisposable,
	}
	got := domain.EnvironmentClasses()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EnvironmentClasses() = %#v, want %#v", got, want)
	}

	got[0] = "modified"
	if reflect.DeepEqual(domain.EnvironmentClasses(), got) {
		t.Fatal("EnvironmentClasses() returned mutable registry storage")
	}

	for _, class := range want {
		if !class.Valid() {
			t.Errorf("%q.Valid() = false", class)
		}
		parsed, err := domain.ParseEnvironmentClass(string(class))
		if err != nil || parsed != class {
			t.Errorf("ParseEnvironmentClass(%q) = (%q, %v)", class, parsed, err)
		}
	}
}

func TestEnvironmentClassRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "prod", "Production", " production", "production "} {
		parsed, err := domain.ParseEnvironmentClass(value)
		if parsed != "" || !errors.Is(err, domain.ErrInvalidEnvironmentClass) {
			t.Errorf("ParseEnvironmentClass(%q) = (%q, %v)", value, parsed, err)
		}
	}

	invalid := domain.EnvironmentClass("unknown")
	if invalid.Valid() {
		t.Fatal("unknown environment class is valid")
	}
	if _, err := invalid.MarshalText(); !errors.Is(err, domain.ErrInvalidEnvironmentClass) {
		t.Fatalf("MarshalText() error = %v", err)
	}
}

func TestEnvironmentClassTextRoundTripAndNilDestination(t *testing.T) {
	t.Parallel()

	encoded, err := domain.EnvironmentStaging.MarshalText()
	if err != nil || string(encoded) != "staging" {
		t.Fatalf("MarshalText() = (%q, %v)", encoded, err)
	}

	var decoded domain.EnvironmentClass
	if err := decoded.UnmarshalText(encoded); err != nil || decoded != domain.EnvironmentStaging {
		t.Fatalf("UnmarshalText() = (%q, %v)", decoded, err)
	}

	var destination *domain.EnvironmentClass
	if err := destination.UnmarshalText([]byte("production")); !errors.Is(err, domain.ErrInvalidEnvironmentClass) {
		t.Fatalf("nil UnmarshalText() error = %v", err)
	}
}
