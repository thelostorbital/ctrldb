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
	if err := isolation.ValidatePermissionProof(permissionPin(expected), permissionProofInput(expected, observed), operatorPrincipal()); err != nil {
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
			Identity: operatorPrincipal(), Resource: permissionResource("production-member"), Permission: "compute.instances.update", Granted: false,
		})},
		{name: "decision mismatch", expected: expected, observed: []isolation.PermissionObservation{
			expected[0], {Identity: expected[1].Identity, Resource: expected[1].Resource, Permission: expected[1].Permission, Granted: true},
		}},
		{name: "malformed expected tuple", expected: []isolation.PermissionObservation{{
			Identity: operatorPrincipal(), Resource: permissionResource("production-member"), Permission: "not a permission",
		}}, observed: expected},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := isolation.ValidatePermissionProof(permissionPin(test.expected), permissionProofInput(test.expected, test.observed), operatorPrincipal()); !errors.Is(err, isolation.ErrPermissionProof) {
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
				Identity: operatorPrincipal(), Resource: permissionResource("production-resource"), Permission: permission, Granted: true,
			}
			if err := isolation.ValidatePermissionProof(permissionPin([]isolation.PermissionObservation{observation}), permissionProofInput(
				[]isolation.PermissionObservation{observation}, []isolation.PermissionObservation{observation},
			), operatorPrincipal()); !errors.Is(err, isolation.ErrForbiddenPermission) {
				t.Fatalf("ValidatePermissionProof() error = %v; want ErrForbiddenPermission", err)
			}
		})
	}

	reads := []isolation.PermissionObservation{
		{Identity: operatorPrincipal(), Resource: permissionResource("production-policy"), Permission: "monitoring.alertPolicies.get", Granted: true},
		{Identity: operatorPrincipal(), Resource: permissionResource("production-metrics"), Permission: "monitoring.timeSeries.query", Granted: true},
		{Identity: operatorPrincipal(), Resource: permissionResource("production-job"), Permission: "cloudscheduler.jobs.list", Granted: true},
		{Identity: operatorPrincipal(), Resource: permissionResource("production-job-view"), Permission: "cloudscheduler.jobs.fullView", Granted: true},
		{Identity: operatorPrincipal(), Resource: permissionResource("production-service"), Permission: "run.services.get", Granted: true},
	}
	if err := isolation.ValidatePermissionProof(permissionPin(reads), permissionProofInput(reads, reads), operatorPrincipal()); err != nil {
		t.Fatalf("ValidatePermissionProof(reads) unexpected error: %v", err)
	}

	lookalikes := []string{
		"monitoring.alertPolicies.query",
		"monitoring.timeSeries.fullView",
		"cloudscheduler.jobs.query",
		"cloudscheduler.locations.fullView",
		"run.timeSeries.query",
		"run.jobs.fullView",
		"monitoring.timeSeries.read",
	}
	for _, permission := range lookalikes {
		permission := permission
		t.Run("reject "+permission, func(t *testing.T) {
			t.Parallel()
			observation := isolation.PermissionObservation{
				Identity: operatorPrincipal(), Resource: permissionResource("production-resource"), Permission: permission, Granted: true,
			}
			if err := isolation.ValidatePermissionProof(permissionPin([]isolation.PermissionObservation{observation}), permissionProofInput(
				[]isolation.PermissionObservation{observation}, []isolation.PermissionObservation{observation},
			), operatorPrincipal()); !errors.Is(err, isolation.ErrForbiddenPermission) {
				t.Fatalf("ValidatePermissionProof() error = %v; want ErrForbiddenPermission", err)
			}
		})
	}
}

func TestPermissionProofRejectsTwoComponentProtectedServicePermissions(t *testing.T) {
	t.Parallel()

	for _, permission := range []string{"monitoring.create", "cloudscheduler.update", "run.delete"} {
		permission := permission
		t.Run(permission, func(t *testing.T) {
			t.Parallel()
			observation := isolation.PermissionObservation{
				Identity: operatorPrincipal(), Resource: permissionResource("production-resource"), Permission: permission, Granted: true,
			}
			if err := isolation.ValidatePermissionProof(permissionPin([]isolation.PermissionObservation{observation}), permissionProofInput(
				[]isolation.PermissionObservation{observation}, []isolation.PermissionObservation{observation},
			), operatorPrincipal()); !errors.Is(err, isolation.ErrPermissionProof) {
				t.Fatalf("ValidatePermissionProof() error = %v; want ErrPermissionProof", err)
			}
		})
	}
}

func TestPermissionProofErrorsDoNotExposeObservedValues(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-production-resource"
	expected := validPermissionExpectations()
	observed := append([]isolation.PermissionObservation(nil), expected...)
	observed[0].Resource = permissionResource(marker)
	err := isolation.ValidatePermissionProof(permissionPin(expected), permissionProofInput(expected, observed), operatorPrincipal())
	if !errors.Is(err, isolation.ErrPermissionProof) {
		t.Fatalf("ValidatePermissionProof() error = %v; want ErrPermissionProof", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("permission proof error exposed an observed resource")
	}
}

func TestPermissionProofRejectsAmbiguousPrincipalAndResourceIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*isolation.PermissionObservation)
	}{
		{name: "bare principal", mutate: func(value *isolation.PermissionObservation) {
			value.Identity = isolation.Principal{Subject: "operator@example.test"}
		}},
		{name: "principal alias", mutate: func(value *isolation.PermissionObservation) {
			value.Identity.Subject = "user:" + value.Identity.Subject
		}},
		{name: "principal whitespace", mutate: func(value *isolation.PermissionObservation) {
			value.Identity.Subject += " "
		}},
		{name: "principal control", mutate: func(value *isolation.PermissionObservation) {
			value.Identity.Subject += "\n"
		}},
		{name: "bare resource", mutate: func(value *isolation.PermissionObservation) {
			value.Resource = isolation.ResourceIdentity{Name: "production-instance"}
		}},
		{name: "missing project", mutate: func(value *isolation.PermissionObservation) {
			value.Resource.Project = ""
		}},
		{name: "cross-project key mismatch", mutate: func(value *isolation.PermissionObservation) {
			value.Resource.Project = "other-test-project"
		}},
		{name: "resource control", mutate: func(value *isolation.PermissionObservation) {
			value.Resource.Name += "\n"
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			observation := validPermissionExpectations()[0]
			test.mutate(&observation)
			if err := isolation.ValidatePermissionProof(permissionPin([]isolation.PermissionObservation{observation}), permissionProofInput(
				[]isolation.PermissionObservation{observation}, []isolation.PermissionObservation{observation},
			), operatorPrincipal()); !errors.Is(err, isolation.ErrPermissionProof) {
				t.Fatalf("ValidatePermissionProof() error = %v; want ErrPermissionProof", err)
			}
		})
	}
}

func TestPermissionProofRequiresNamedVersionedCompleteInventory(t *testing.T) {
	t.Parallel()

	valid := validPermissionProofInput()
	validPin := permissionPin(valid.Expected)
	tests := []struct {
		name   string
		mutate func(*isolation.PolicyInventoryPin, *isolation.PermissionProofInput, *isolation.Principal)
	}{
		{name: "missing ID", mutate: func(pin *isolation.PolicyInventoryPin, _ *isolation.PermissionProofInput, _ *isolation.Principal) {
			pin.ID = ""
		}},
		{name: "missing version", mutate: func(pin *isolation.PolicyInventoryPin, _ *isolation.PermissionProofInput, _ *isolation.Principal) {
			pin.Version = ""
		}},
		{name: "missing fingerprint", mutate: func(pin *isolation.PolicyInventoryPin, _ *isolation.PermissionProofInput, _ *isolation.Principal) {
			pin.Fingerprint = ""
		}},
		{name: "ad hoc subset", mutate: func(_ *isolation.PolicyInventoryPin, input *isolation.PermissionProofInput, _ *isolation.Principal) {
			input.Expected = input.Expected[:1]
			input.Observed = input.Observed[:1]
		}},
		{name: "wrong mutation principal", mutate: func(_ *isolation.PolicyInventoryPin, _ *isolation.PermissionProofInput, principal *isolation.Principal) {
			*principal = isolation.Principal{Kind: isolation.PrincipalKindServiceAccount, Subject: "alternate-operator@example-test-project.iam.gserviceaccount.com"}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := valid
			pin := validPin
			principal := operatorPrincipal()
			test.mutate(&pin, &input, &principal)
			if err := isolation.ValidatePermissionProof(pin, input, principal); !errors.Is(err, isolation.ErrPermissionProof) {
				t.Fatalf("ValidatePermissionProof() error = %v; want ErrPermissionProof", err)
			}
		})
	}
}

func validPermissionExpectations() []isolation.PermissionObservation {
	project, err := isolation.ProjectAuthorizationResource("example-test-project")
	if err != nil {
		panic(err)
	}
	return []isolation.PermissionObservation{
		{Identity: operatorPrincipal(), Resource: permissionResource("ctrldb-test-run1-vm"), Permission: "compute.instances.get", Granted: true},
		{Identity: operatorPrincipal(), Resource: permissionResource("production-instance"), Permission: "compute.instances.update", Granted: false},
		{Identity: operatorPrincipal(), Resource: project, Permission: "compute.firewalls.create", Granted: true},
	}
}

func permissionResource(name string) isolation.ResourceIdentity {
	return testResourceIdentity(name, isolation.ComputeInstanceKind, isolation.ResourceScopeZone, "asia-south1-a")
}

func validPermissionProofInput() isolation.PermissionProofInput {
	expected := validPermissionExpectations()
	return permissionProofInput(expected, append([]isolation.PermissionObservation(nil), expected...))
}

func permissionProofInput(expected, observed []isolation.PermissionObservation) isolation.PermissionProofInput {
	return isolation.PermissionProofInput{Expected: expected, Observed: observed}
}

func permissionPin(expected []isolation.PermissionObservation) isolation.PolicyInventoryPin {
	fingerprint, err := isolation.PermissionInventoryFingerprint(expected)
	if err != nil {
		fingerprint = strings.Repeat("0", 64)
	}
	return isolation.PolicyInventoryPin{ID: "perm-test-operator", Version: "v1", Fingerprint: fingerprint}
}
