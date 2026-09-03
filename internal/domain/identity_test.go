// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestExecutionIdentityRegistry(t *testing.T) {
	t.Parallel()

	want := []domain.ExecutionIdentity{
		domain.IdentityHuman,
		domain.IdentityOperator,
		domain.IdentityProvisioner,
		domain.IdentityDestructive,
		domain.IdentityVM,
		domain.IdentityReconciler,
		domain.IdentityTransfer,
		domain.IdentityRestore,
		domain.IdentityRecovery,
		domain.IdentityTestOperator,
		domain.IdentityTestDestructive,
		domain.IdentityHost,
	}

	got := domain.ExecutionIdentities()
	if !slices.Equal(got, want) {
		t.Fatalf("ExecutionIdentities() = %v, want %v", got, want)
	}

	got[0] = "tampered"
	if domain.ExecutionIdentities()[0] != domain.IdentityHuman {
		t.Fatal("ExecutionIdentities() exposed its internal registry")
	}
}

func TestExecutionIdentityRoundTrip(t *testing.T) {
	t.Parallel()

	for _, identity := range domain.ExecutionIdentities() {
		identity := identity
		t.Run(string(identity), func(t *testing.T) {
			t.Parallel()

			parsed, err := domain.ParseExecutionIdentity(string(identity))
			if err != nil {
				t.Fatalf("ParseExecutionIdentity(%q) returned an error: %v", identity, err)
			}
			if parsed != identity {
				t.Fatalf("ParseExecutionIdentity(%q) = %q", identity, parsed)
			}

			encoded, err := json.Marshal(identity)
			if err != nil {
				t.Fatalf("json.Marshal(%q) returned an error: %v", identity, err)
			}

			var decoded domain.ExecutionIdentity
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("json.Unmarshal(%s) returned an error: %v", encoded, err)
			}
			if decoded != identity {
				t.Fatalf("decoded identity = %q, want %q", decoded, identity)
			}
		})
	}
}

func TestExecutionIdentityRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "operator ", "OPERATOR", "app", "root", "unknown"} {
		_, err := domain.ParseExecutionIdentity(value)
		if !errors.Is(err, domain.ErrInvalidExecutionIdentity) {
			t.Errorf("ParseExecutionIdentity(%q) error = %v, want ErrInvalidExecutionIdentity", value, err)
		}
	}

	var identity domain.ExecutionIdentity
	if err := json.Unmarshal([]byte(`"admin"`), &identity); !errors.Is(err, domain.ErrInvalidExecutionIdentity) {
		t.Fatalf("json.Unmarshal() error = %v, want ErrInvalidExecutionIdentity", err)
	}
}

func TestExecutionIdentityRejectsInvalidMarshalAndNilDestination(t *testing.T) {
	t.Parallel()

	invalid := domain.ExecutionIdentity("invalid")
	if _, err := invalid.MarshalText(); !errors.Is(err, domain.ErrInvalidExecutionIdentity) {
		t.Fatalf("MarshalText() error = %v, want ErrInvalidExecutionIdentity", err)
	}

	var destination *domain.ExecutionIdentity
	if err := destination.UnmarshalText([]byte("human")); !errors.Is(err, domain.ErrInvalidExecutionIdentity) {
		t.Fatalf("UnmarshalText() error = %v, want ErrInvalidExecutionIdentity", err)
	}
}
