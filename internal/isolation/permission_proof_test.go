// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

func TestTESTISO01PermissionProofMatchesCallerSuppliedTuplesExactly(t *testing.T) {
	t.Parallel()

	expected := validPermissionExpectations()
	observed := append([]isolation.PermissionObservation(nil), expected...)
	observed[0], observed[1] = observed[1], observed[0]
	if err := isolation.ValidatePermissionProof(permissionProofInput(expected, observed)); err != nil {
		t.Fatalf("ValidatePermissionProof() unexpected error: %v", err)
	}
}

func TestTESTISO09PermissionProofRejectsAmbiguousOrIncompleteEvidence(t *testing.T) {
	t.Parallel()

	expected := validPermissionExpectations()
	tests := []struct {
		name     string
		expected []isolation.PermissionObservation
		observed []isolation.PermissionObservation
	}{
		{name: "empty expected"},
		{name: "missing observation", expected: expected, observed: expected[:1]},
		{name: "duplicate expected", expected: append(expected, expected[0]), observed: expected},
		{name: "duplicate observed", expected: expected, observed: append(expected, expected[0])},
		{name: "unexpected observation", expected: expected, observed: append(expected, isolation.PermissionObservation{
			Identity: "test-operator", Resource: "production-member", Permission: "compute.instances.update", Granted: false,
		})},
		{name: "decision mismatch", expected: expected, observed: []isolation.PermissionObservation{
			expected[0], {Identity: expected[1].Identity, Resource: expected[1].Resource, Permission: expected[1].Permission, Granted: true},
		}},
		{name: "malformed expected tuple", expected: []isolation.PermissionObservation{{
			Identity: "test-operator", Resource: "production-member", Permission: "not a permission",
		}}, observed: expected},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := isolation.ValidatePermissionProof(permissionProofInput(test.expected, test.observed)); !errors.Is(err, isolation.ErrPermissionProof) {
				t.Fatalf("ValidatePermissionProof() error = %v; want ErrPermissionProof", err)
			}
		})
	}
}

func TestTESTISO09PermissionProofRejectsForbiddenServiceWrites(t *testing.T) {
	t.Parallel()

	permissions := []string{
		"monitoring.alertPolicies.create",
		"monitoring.notificationChannels.update",
		"monitoring.timeSeries.create",
		"cloudscheduler.jobs.pause",
		"cloudscheduler.jobs.update",
		"run.jobs.run",
		"run.jobs.update",
	}
	for _, permission := range permissions {
		permission := permission
		t.Run(permission, func(t *testing.T) {
			t.Parallel()
			observation := isolation.PermissionObservation{
				Identity: "test-operator", Resource: "production-resource", Permission: permission, Granted: true,
			}
			if err := isolation.ValidatePermissionProof(permissionProofInput(
				[]isolation.PermissionObservation{observation}, []isolation.PermissionObservation{observation},
			)); !errors.Is(err, isolation.ErrForbiddenPermission) {
				t.Fatalf("ValidatePermissionProof() error = %v; want ErrForbiddenPermission", err)
			}
		})
	}

	reads := []isolation.PermissionObservation{
		{Identity: "test-operator", Resource: "production-policy", Permission: "monitoring.alertPolicies.get", Granted: true},
		{Identity: "test-operator", Resource: "production-job", Permission: "cloudscheduler.jobs.list", Granted: true},
		{Identity: "test-operator", Resource: "production-service", Permission: "run.services.get", Granted: true},
	}
	if err := isolation.ValidatePermissionProof(permissionProofInput(reads, reads)); err != nil {
		t.Fatalf("ValidatePermissionProof(reads) unexpected error: %v", err)
	}
}

func TestPermissionProofErrorsDoNotExposeObservedValues(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-production-resource"
	expected := validPermissionExpectations()
	observed := append([]isolation.PermissionObservation(nil), expected...)
	observed[0].Resource = marker
	err := isolation.ValidatePermissionProof(permissionProofInput(expected, observed))
	if !errors.Is(err, isolation.ErrPermissionProof) {
		t.Fatalf("ValidatePermissionProof() error = %v; want ErrPermissionProof", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("permission proof error exposed an observed resource")
	}
}

func TestPermissionProofRequiresNamedVersionedCompleteInventory(t *testing.T) {
	t.Parallel()

	valid := validPermissionProofInput()
	tests := []struct {
		name   string
		mutate func(*isolation.PermissionProofInput)
	}{
		{name: "missing ID", mutate: func(input *isolation.PermissionProofInput) { input.Inventory.ID = "" }},
		{name: "missing version", mutate: func(input *isolation.PermissionProofInput) { input.Inventory.Version = "" }},
		{name: "missing fingerprint", mutate: func(input *isolation.PermissionProofInput) { input.Inventory.Fingerprint = "" }},
		{name: "ad hoc subset", mutate: func(input *isolation.PermissionProofInput) {
			input.Expected = input.Expected[:1]
			input.Observed = input.Observed[:1]
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := valid
			test.mutate(&input)
			if err := isolation.ValidatePermissionProof(input); !errors.Is(err, isolation.ErrPermissionProof) {
				t.Fatalf("ValidatePermissionProof() error = %v; want ErrPermissionProof", err)
			}
		})
	}
}

func validPermissionExpectations() []isolation.PermissionObservation {
	return []isolation.PermissionObservation{
		{Identity: "test-operator", Resource: "test-instance", Permission: "compute.instances.get", Granted: true},
		{Identity: "test-operator", Resource: "production-instance", Permission: "compute.instances.update", Granted: false},
	}
}

func validPermissionProofInput() isolation.PermissionProofInput {
	expected := validPermissionExpectations()
	return permissionProofInput(expected, append([]isolation.PermissionObservation(nil), expected...))
}

func permissionProofInput(expected, observed []isolation.PermissionObservation) isolation.PermissionProofInput {
	fingerprint, err := isolation.PermissionInventoryFingerprint(expected)
	if err != nil {
		fingerprint = strings.Repeat("0", 64)
	}
	return isolation.PermissionProofInput{
		Inventory: isolation.PermissionInventory{ID: "perm-test-operator", Version: "v1", Fingerprint: fingerprint},
		Expected:  expected,
		Observed:  observed,
	}
}
