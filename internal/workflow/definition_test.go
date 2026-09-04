// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow_test

import (
	"errors"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

func TestWorkflowDefinitionsRequireBoundedExecutionContracts_TEST_U_PLAN_04(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*workflow.StepDefinition)
	}{
		{name: "missing id", mutate: func(step *workflow.StepDefinition) { step.ID = "" }},
		{name: "missing executor", mutate: func(step *workflow.StepDefinition) { step.Executor = "" }},
		{name: "missing identity", mutate: func(step *workflow.StepDefinition) { step.ExecutingIdentity = "" }},
		{name: "missing effect", mutate: func(step *workflow.StepDefinition) { step.Effect = "" }},
		{name: "mutation with read approval", mutate: func(step *workflow.StepDefinition) { step.MinimumApproval = domain.ApprovalRead }},
		{name: "missing target kinds", mutate: func(step *workflow.StepDefinition) { step.TargetKinds = nil }},
		{name: "missing permissions", mutate: func(step *workflow.StepDefinition) { step.RequiredPermissions = nil }},
		{name: "step-up below AP-4", mutate: func(step *workflow.StepDefinition) {
			step.MinimumApproval = domain.ApprovalProtected
			step.RequiresStepUp = true
		}},
		{name: "read step-up", mutate: func(step *workflow.StepDefinition) {
			step.Effect = domain.StepEffectRead
			step.MinimumApproval = domain.ApprovalDestructive
			step.RequiresStepUp = true
		}},
		{name: "recovery below AP-4", mutate: func(step *workflow.StepDefinition) {
			step.RequiresRecoveryAsset = true
		}},
		{name: "read recovery", mutate: func(step *workflow.StepDefinition) {
			step.Effect = domain.StepEffectRead
			step.MinimumApproval = domain.ApprovalDestructive
			step.RequiresRecoveryAsset = true
		}},
		{name: "AP-5 without recovery", mutate: func(step *workflow.StepDefinition) {
			step.MinimumApproval = domain.ApprovalDataDestructive
		}},
		{name: "zero attempts", mutate: func(step *workflow.StepDefinition) { step.Retry.MaxAttempts = 0 }},
		{name: "unbounded attempts", mutate: func(step *workflow.StepDefinition) { step.Retry.MaxAttempts = domain.MaxStepAttempts + 1 }},
		{name: "zero retry backoff", mutate: func(step *workflow.StepDefinition) { step.Retry.InitialBackoffSeconds = 0 }},
		{name: "zero timeout", mutate: func(step *workflow.StepDefinition) { step.TimeoutSeconds = 0 }},
		{name: "unbounded timeout", mutate: func(step *workflow.StepDefinition) { step.TimeoutSeconds = domain.MaxStepTimeoutSeconds + 1 }},
		{name: "missing success condition", mutate: func(step *workflow.StepDefinition) { step.SuccessCondition = redact.Sanitize("") }},
		{name: "missing failure behavior", mutate: func(step *workflow.StepDefinition) { step.FailureBehavior = "" }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			step := validDefinitionStep()
			test.mutate(&step)
			if _, err := workflow.NewDefinition(
				"WF-VM-02", "before-old-instance-delete", "stop-instance",
				domain.PointOfNoReturnStepComplete, []workflow.StepDefinition{step},
			); !errors.Is(err, workflow.ErrInvalidDefinition) {
				t.Fatalf("NewDefinition() error = %v, want ErrInvalidDefinition", err)
			}
		})
	}
}

func TestWorkflowDefinitionAllowsRequiredRecoveryForAP4AndRequiresItForAP5(t *testing.T) {
	t.Parallel()

	for _, approval := range []domain.ApprovalClass{domain.ApprovalDestructive, domain.ApprovalDataDestructive} {
		step := validDefinitionStep()
		step.MinimumApproval = approval
		step.RequiresRecoveryAsset = true
		definition, err := workflow.NewDefinition(
			"WF-VM-02", "before-old-instance-delete", step.ID,
			domain.PointOfNoReturnMutationObserved, []workflow.StepDefinition{step},
		)
		if err != nil {
			t.Fatalf("NewDefinition(%s) returned an error: %v", approval, err)
		}
		contractStep := definition.ExecutionContract().Steps()[0]
		if !contractStep.RequiresRecoveryAsset {
			t.Fatalf("NewDefinition(%s) lost recovery requirement", approval)
		}
	}
}

func TestWorkflowDefinitionRequiresPointOfNoReturnTriggerPairing(t *testing.T) {
	t.Parallel()

	step := validDefinitionStep()
	for _, test := range []struct {
		point   string
		trigger domain.PointOfNoReturnTrigger
	}{
		{point: step.ID},
		{trigger: domain.PointOfNoReturnStepStart},
		{point: step.ID, trigger: "at-some-time"},
	} {
		if _, err := workflow.NewDefinition(
			"WF-VM-02", "before-old-instance-delete", test.point, test.trigger,
			[]workflow.StepDefinition{step},
		); !errors.Is(err, workflow.ErrInvalidDefinition) {
			t.Fatalf("NewDefinition(point=%q trigger=%q) error = %v, want ErrInvalidDefinition", test.point, test.trigger, err)
		}
	}
}

func TestExecutionContractDigestBindsRollbackPointAndSteps(t *testing.T) {
	t.Parallel()

	step := validDefinitionStep()
	base, err := workflow.NewDefinition(
		"WF-VM-02", "before-old-instance-delete", step.ID,
		domain.PointOfNoReturnStepComplete, []workflow.StepDefinition{step},
	)
	if err != nil {
		t.Fatalf("NewDefinition(base) returned an error: %v", err)
	}
	baseDigest := base.ExecutionContract().Digest()
	if len(baseDigest) != 64 {
		t.Fatalf("Digest() = %q, want 64 lowercase hex characters", baseDigest)
	}
	for name, build := range map[string]func() (workflow.Definition, error){
		"rollback": func() (workflow.Definition, error) {
			return workflow.NewDefinition(
				"WF-VM-02", "before-replacement-delete", step.ID,
				domain.PointOfNoReturnStepComplete, []workflow.StepDefinition{step},
			)
		},
		"trigger": func() (workflow.Definition, error) {
			return workflow.NewDefinition(
				"WF-VM-02", "before-old-instance-delete", step.ID,
				domain.PointOfNoReturnMutationObserved, []workflow.StepDefinition{step},
			)
		},
		"step": func() (workflow.Definition, error) {
			changed := step
			changed.TimeoutSeconds++
			return workflow.NewDefinition(
				"WF-VM-02", "before-old-instance-delete", changed.ID,
				domain.PointOfNoReturnStepComplete, []workflow.StepDefinition{changed},
			)
		},
	} {
		definition, err := build()
		if err != nil {
			t.Fatalf("NewDefinition(%s) returned an error: %v", name, err)
		}
		if definition.ExecutionContract().Digest() == baseDigest {
			t.Fatalf("%s change did not change execution contract digest", name)
		}
	}
}

func TestWorkflowDefinitionAndRegistryAreImmutable(t *testing.T) {
	t.Parallel()

	steps := []workflow.StepDefinition{validDefinitionStep()}
	definition, err := workflow.NewDefinition(
		"WF-VM-02", "before-old-instance-delete", "stop-instance", domain.PointOfNoReturnStepComplete, steps,
	)
	if err != nil {
		t.Fatalf("NewDefinition() returned an error: %v", err)
	}
	steps[0].ID = "weakened"
	steps[0].TargetKinds[0] = "disk"
	steps[0].RequiredPermissions[0] = "compute.instances.get"
	if got := definition.Steps()[0].ID; got != "stop-instance" {
		t.Fatalf("definition aliased constructor storage: %q", got)
	}

	registry, err := workflow.NewRegistry(definition)
	if err != nil {
		t.Fatalf("NewRegistry() returned an error: %v", err)
	}
	got, ok := registry.Lookup("WF-VM-02")
	if !ok || registry.Len() != 1 {
		t.Fatalf("Lookup() = (%#v, %t), len=%d", got, ok, registry.Len())
	}
	copyOfSteps := got.Steps()
	copyOfSteps[0].TimeoutSeconds = 0
	again, _ := registry.Lookup("WF-VM-02")
	if again.Steps()[0].TimeoutSeconds == 0 {
		t.Fatal("registry lookup exposed mutable step storage")
	}
	contractSteps := definition.ExecutionContract().Steps()
	contractSteps[0].RequiredPermissions[0] = "compute.instances.get"
	if got := definition.ExecutionContract().Steps()[0].RequiredPermissions[0]; got != "compute.instances.stop" {
		t.Fatalf("execution contract exposed mutable permissions: %q", got)
	}

	empty, err := workflow.NewRegistry()
	if err != nil || empty.Len() != 0 {
		t.Fatalf("empty implemented-workflow registry = (%#v, %v)", empty, err)
	}
	if _, err := workflow.NewRegistry(workflow.Definition{}); !errors.Is(err, workflow.ErrInvalidDefinition) {
		t.Fatalf("placeholder registration error = %v, want ErrInvalidDefinition", err)
	}
	if _, err := workflow.NewRegistry(definition, definition); !errors.Is(err, workflow.ErrInvalidDefinition) {
		t.Fatalf("duplicate registration error = %v, want ErrInvalidDefinition", err)
	}
}

func TestWorkflowDefinitionRequiresCoherentRecoveryContract(t *testing.T) {
	t.Parallel()

	step := validDefinitionStep()
	for _, test := range []struct {
		name             string
		rollbackBoundary string
		pointOfNoReturn  string
	}{
		{name: "missing rollback boundary", pointOfNoReturn: step.ID},
		{name: "no rollback for mutation", rollbackBoundary: "none", pointOfNoReturn: step.ID},
		{name: "unknown point of no return", rollbackBoundary: "before-delete", pointOfNoReturn: "unknown-step"},
		{name: "noncanonical boundary", rollbackBoundary: "before delete", pointOfNoReturn: step.ID},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := workflow.NewDefinition(
				"WF-VM-02", test.rollbackBoundary, test.pointOfNoReturn,
				domain.PointOfNoReturnStepComplete, []workflow.StepDefinition{step},
			); !errors.Is(err, workflow.ErrInvalidDefinition) {
				t.Fatalf("NewDefinition() error = %v, want ErrInvalidDefinition", err)
			}
		})
	}
}

func validDefinitionStep() workflow.StepDefinition {
	return workflow.StepDefinition{
		ID:                  "stop-instance",
		Executor:            "compute-api",
		ExecutingIdentity:   domain.IdentityOperator,
		Effect:              domain.StepEffectMutation,
		MinimumApproval:     domain.ApprovalProtected,
		TargetKinds:         []string{"instance"},
		RequiredPermissions: []string{"compute.instances.stop"},
		Idempotent:          true,
		Retry: domain.RetryPolicy{
			MaxAttempts:           3,
			InitialBackoffSeconds: 2,
			MaxBackoffSeconds:     10,
		},
		CancelSafe:       false,
		TimeoutSeconds:   300,
		SuccessCondition: redact.Sanitize("instance is stopped"),
		FailureBehavior:  domain.FailureRollback,
	}
}
