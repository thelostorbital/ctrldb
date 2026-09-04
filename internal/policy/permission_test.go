// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/policy"
)

func TestPermissionProbeBlocksPlanBeforeExecution_TEST_U_PLAN_03(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	plan.Preconditions = append(plan.Preconditions, domain.PlanPrecondition{ID: "quota-ready", OK: false})
	checks, err := policy.PermissionChecks(
		domain.IdentityProvisioner,
		[]string{"compute.instances.create", "compute.instances.get"},
		[]string{"compute.instances.get"},
	)
	if err != nil {
		t.Fatalf("PermissionChecks() returned an error: %v", err)
	}
	plan.Permissions = append(plan.Permissions, checks...)
	plan, err = policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}
	if _, err := policy.EncodePlan(plan); err != nil {
		t.Fatalf("blocked review artifact was not serializable: %v", err)
	}

	err = policy.ValidatePlanForExecutionAt(plan, plan.CreatedAt.Add(5))
	if !errors.Is(err, policy.ErrPlanBlocked) {
		t.Fatalf("ValidatePlanForExecutionAt() error = %v, want ErrPlanBlocked", err)
	}
	var blocked *policy.BlockedPlanError
	if !errors.As(err, &blocked) {
		t.Fatalf("error type = %T, want *BlockedPlanError", err)
	}
	if blocked.ExitCode() != 3 || blocked.PlanID() != plan.PlanID {
		t.Fatalf("blocked error metadata = exit %d, plan %q", blocked.ExitCode(), blocked.PlanID())
	}
	want := []policy.PlanBlocker{
		{Kind: policy.BlockerPrecondition, ID: "quota-ready"},
		{Kind: policy.BlockerPermission, ID: "compute.instances.create", Identity: domain.IdentityProvisioner},
	}
	if got := blocked.Blockers(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Blockers() = %#v, want %#v", got, want)
	}
	got := blocked.Blockers()
	got[0].ID = "changed"
	if reflect.DeepEqual(blocked.Blockers(), got) {
		t.Fatal("Blockers() exposed mutable error storage")
	}
}

func TestPermissionChecksRejectsAmbiguousProbeEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		identity domain.ExecutionIdentity
		required []string
		granted  []string
	}{
		{name: "unknown identity", identity: "root", required: []string{"compute.instances.get"}},
		{name: "empty required", identity: domain.IdentityOperator},
		{name: "malformed required", identity: domain.IdentityOperator, required: []string{"instances.get"}},
		{name: "duplicate required", identity: domain.IdentityOperator, required: []string{"compute.instances.get", "compute.instances.get"}},
		{name: "unexpected granted", identity: domain.IdentityOperator, required: []string{"compute.instances.get"}, granted: []string{"compute.instances.stop"}},
		{name: "duplicate granted", identity: domain.IdentityOperator, required: []string{"compute.instances.get"}, granted: []string{"compute.instances.get", "compute.instances.get"}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := policy.PermissionChecks(test.identity, test.required, test.granted); !errors.Is(err, policy.ErrInvalidPermissionProbe) {
				t.Fatalf("PermissionChecks() error = %v, want ErrInvalidPermissionProbe", err)
			}
		})
	}
}

func TestExecutionGateAcceptsSatisfiedChecks(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	if err := policy.ValidatePlanForExecutionAt(plan, plan.CreatedAt.Add(5)); err != nil {
		t.Fatalf("ValidatePlanForExecutionAt() returned an error: %v", err)
	}
}
