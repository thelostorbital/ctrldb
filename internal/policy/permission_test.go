// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/policy"
	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

func TestPermissionProbeBlocksPlanBeforeExecution_TEST_U_PLAN_03(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	plan.Preconditions = append(plan.Preconditions, domain.PlanPrecondition{ID: "quota-ready", OK: false})
	checks, err := policy.PermissionChecks(policy.PermissionProbe{
		ProjectID: plan.ProjectID,
		StepID:    plan.Steps[0].ID,
		Identity:  domain.IdentityOperator,
		Resource:  plan.Resources[0],
		Required:  []string{"compute.instances.stop"},
		Granted:   nil,
	})
	if err != nil {
		t.Fatalf("PermissionChecks() returned an error: %v", err)
	}
	plan.Permissions = checks
	plan, err = policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}
	if _, err := policy.EncodePlan(plan); err != nil {
		t.Fatalf("blocked review artifact was not serializable: %v", err)
	}

	err = policy.ValidatePlanForExecution(plan, validExecutionEvidence(plan, plan.CreatedAt.Add(10*time.Minute)), validExecutionContract(t))
	if !errors.Is(err, policy.ErrPlanBlocked) {
		t.Fatalf("ValidatePlanForExecution() error = %v, want ErrPlanBlocked", err)
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
		{Kind: policy.BlockerPermission, ID: "compute.instances.stop", Identity: domain.IdentityOperator},
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

func TestExecutionGateAcceptsCompleteFreshEvidence(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	evidence := validExecutionEvidence(plan, plan.CreatedAt.Add(10*time.Minute))
	if err := policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)); err != nil {
		t.Fatalf("ValidatePlanForExecution() returned an error: %v", err)
	}
}

func TestExecutionGateRequiresTrustedRiskAndExactPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		kind   policy.PlanBlockerKind
		mutate func(*domain.Plan)
	}{
		{
			name: "mutation misclassified as read",
			kind: policy.BlockerContract,
			mutate: func(plan *domain.Plan) {
				plan.ApprovalClass = domain.ApprovalRead
			},
		},
		{
			name: "mutation has get instead of required permission",
			kind: policy.BlockerPermission,
			mutate: func(plan *domain.Plan) {
				plan.Permissions[0].Permission = "compute.instances.get"
			},
		},
		{
			name: "unexpected permission",
			kind: policy.BlockerPermission,
			mutate: func(plan *domain.Plan) {
				extra := plan.Permissions[0]
				extra.Permission = "compute.instances.get"
				plan.Permissions = append(plan.Permissions, extra)
			},
		},
		{
			name: "untrusted rollback boundary",
			kind: policy.BlockerContract,
			mutate: func(plan *domain.Plan) {
				plan.Rollback.Boundary = "after-last-recovery-point"
			},
		},
		{
			name: "omitted point of no return",
			kind: policy.BlockerContract,
			mutate: func(plan *domain.Plan) {
				plan.PointOfNoReturn = ""
				plan.PointOfNoReturnTrigger = ""
			},
		},
		{
			name: "mismatched point-of-no-return trigger",
			kind: policy.BlockerContract,
			mutate: func(plan *domain.Plan) {
				plan.PointOfNoReturnTrigger = domain.PointOfNoReturnMutationObserved
			},
		},
		{
			name: "untrusted command summary",
			kind: policy.BlockerContract,
			mutate: func(plan *domain.Plan) {
				plan.Steps[0].CommandRedacted = redact.Sanitize("a different reviewed action")
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan := validPlan()
			test.mutate(&plan)
			plan, err := policy.SealPlan(plan)
			if err != nil {
				t.Fatalf("SealPlan() returned an error: %v", err)
			}
			evidence := validExecutionEvidence(plan, plan.CreatedAt.Add(10*time.Minute))
			expectBlockedKind(t, policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)), test.kind)
		})
	}
}

func TestExecutionGateDerivesProductionAP4StepUpFromTrustedContract(t *testing.T) {
	t.Parallel()

	requiredPlan, requiredContract := ap4ExecutionPlan(t, "delete-disk", "disk", "compute.disks.delete", true)
	checkedAt := requiredPlan.CreatedAt.Add(10 * time.Minute)
	if err := policy.ValidatePlanForExecution(
		requiredPlan, validExecutionEvidence(requiredPlan, checkedAt), requiredContract,
	); err != nil {
		t.Fatalf("production AP-4 disk deletion with step-up returned an error: %v", err)
	}

	missingFlag := requiredPlan
	missingFlag.StepUpRequired = false
	missingFlag, err := policy.SealPlan(missingFlag)
	if err != nil {
		t.Fatalf("SealPlan() should defer the production AP-4 decision to the trusted contract: %v", err)
	}
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		missingFlag, validExecutionEvidence(missingFlag, checkedAt), requiredContract,
	), policy.BlockerStepUp)

	ordinaryPlan, ordinaryContract := ap4ExecutionPlan(
		t, "restart-instance", "instance", "compute.instances.reset", false,
	)
	if err := policy.ValidatePlanForExecution(
		ordinaryPlan, validExecutionEvidence(ordinaryPlan, checkedAt), ordinaryContract,
	); err != nil {
		t.Fatalf("ordinary production AP-4 plan without step-up returned an error: %v", err)
	}
	unexpectedFlag := ordinaryPlan
	unexpectedFlag.StepUpRequired = true
	unexpectedFlag, err = policy.SealPlan(unexpectedFlag)
	if err != nil {
		t.Fatalf("SealPlan() should defer the ordinary production AP-4 decision to the trusted contract: %v", err)
	}
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		unexpectedFlag, validExecutionEvidence(unexpectedFlag, checkedAt), ordinaryContract,
	), policy.BlockerStepUp)

	nonProduction := requiredPlan
	nonProduction.Environment = "staging"
	nonProduction.EnvironmentClass = domain.EnvironmentStaging
	nonProduction.StepUpRequired = false
	nonProduction, err = policy.SealPlan(nonProduction)
	if err != nil {
		t.Fatalf("SealPlan(non-production) returned an error: %v", err)
	}
	if err := policy.ValidatePlanForExecution(
		nonProduction, validExecutionEvidence(nonProduction, checkedAt), requiredContract,
	); err != nil {
		t.Fatalf("non-production trusted step-up plan returned an error: %v", err)
	}
}

func TestExecutionGateRequiresTrustedRecoveryAssetEvidence(t *testing.T) {
	t.Parallel()

	plan, _ := ap4ExecutionPlan(t, "delete-disk", "disk", "compute.disks.delete", true)
	definition, err := workflow.NewDefinition(
		plan.WorkflowID, plan.Rollback.Boundary, plan.PointOfNoReturn, plan.PointOfNoReturnTrigger,
		[]workflow.StepDefinition{{
			ID: plan.Steps[0].ID, Executor: plan.Steps[0].Executor,
			ExecutingIdentity: plan.Steps[0].ExecutingIdentity, CommandSummary: plan.Steps[0].CommandRedacted,
			Effect:          domain.StepEffectMutation,
			MinimumApproval: domain.ApprovalDestructive, TargetKinds: []string{"disk"},
			RequiredPermissions: []string{"compute.disks.delete"}, RequiresStepUp: true,
			RequiresRecoveryAsset: true, Idempotent: plan.Steps[0].Idempotent, Retry: plan.Steps[0].Retry,
			CancelSafe: plan.Steps[0].CancelSafe, TimeoutSeconds: plan.Steps[0].TimeoutSeconds,
			SuccessCondition: plan.Steps[0].SuccessCondition, FailureBehavior: plan.Steps[0].FailureBehavior,
		}},
	)
	if err != nil {
		t.Fatalf("NewDefinition() returned an error: %v", err)
	}
	checkedAt := plan.CreatedAt.Add(10 * time.Minute)
	evidence := validExecutionEvidence(plan, checkedAt)
	if err := policy.ValidatePlanForExecution(plan, evidence, definition.ExecutionContract()); err != nil {
		t.Fatalf("ValidatePlanForExecution() returned an error: %v", err)
	}

	evidence.RecoveryAssets[0].Resource.Fingerprint = "stale"
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		plan, evidence, definition.ExecutionContract(),
	), policy.BlockerRecovery)

	withoutAsset := plan
	withoutAsset.Rollback.Assets = nil
	withoutAsset, err = policy.SealPlan(withoutAsset)
	if err != nil {
		t.Fatalf("SealPlan(AP-4 without asset) returned an error: %v", err)
	}
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		withoutAsset, validExecutionEvidence(withoutAsset, checkedAt), definition.ExecutionContract(),
	), policy.BlockerRecovery)
}

func TestExecutionGateRequiresRecoveryCoverageForEveryTrustedTarget(t *testing.T) {
	t.Parallel()

	plan, _ := ap4ExecutionPlan(t, "delete-disk", "disk", "compute.disks.delete", true)
	second := plan.Resources[0]
	second.Name = "second-disk"
	second.Fingerprint = "generation-8"
	plan.Resources = append(plan.Resources, second)
	plan.Steps[0].Targets = append(plan.Steps[0].Targets, second)
	permission := plan.Permissions[0]
	permission.Resource = second
	plan.Permissions = append(plan.Permissions, permission)
	plan, err := policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}
	contract := executionContractForPlan(t, plan, domain.ApprovalDestructive, true, true)
	checkedAt := plan.CreatedAt.Add(10 * time.Minute)
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		plan, validExecutionEvidence(plan, checkedAt), contract,
	), policy.BlockerContract)

	plan.Rollback.Assets[0].Protects = append(plan.Rollback.Assets[0].Protects, second)
	plan, err = policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan(covered) returned an error: %v", err)
	}
	if err := policy.ValidatePlanForExecution(
		plan, validExecutionEvidence(plan, checkedAt), contract,
	); err != nil {
		t.Fatalf("ValidatePlanForExecution(covered) returned an error: %v", err)
	}
}

func TestExecutionGateBindsTrustedExposureRequirement(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	plan.ApprovalClass = domain.ApprovalSecuritySensitive
	plan.Exposure = domain.ExposureExternal
	plan.ExposureControls = validExposureControls(plan)
	plan, err := policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}
	contract := executionContractForPlan(t, plan, domain.ApprovalSecuritySensitive, false, false)
	checkedAt := plan.CreatedAt.Add(10 * time.Minute)
	if err := policy.ValidatePlanForExecution(plan, validExecutionEvidence(plan, checkedAt), contract); err != nil {
		t.Fatalf("ValidatePlanForExecution() returned an error: %v", err)
	}

	withoutTrustedRequirement := plan
	withoutTrustedRequirement.Exposure = domain.ExposureNone
	withoutTrustedRequirement.ExposureControls = nil
	withoutTrustedRequirement, err = policy.SealPlan(withoutTrustedRequirement)
	if err != nil {
		t.Fatalf("SealPlan(no exposure) returned an error: %v", err)
	}
	contractWithoutExposure := executionContractForPlan(
		t, withoutTrustedRequirement, domain.ApprovalSecuritySensitive, false, false,
	)
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		plan, validExecutionEvidence(plan, checkedAt), contractWithoutExposure,
	), policy.BlockerContract)
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		withoutTrustedRequirement, validExecutionEvidence(withoutTrustedRequirement, checkedAt), contract,
	), policy.BlockerContract)

	wrongProfile := plan
	wrongProfile.ExposureControls = cloneExposureControls(plan.ExposureControls)
	wrongProfile.ExposureControls.Profile = domain.ExposureProfileACC07
	wrongProfile, err = policy.SealPlan(wrongProfile)
	if err != nil {
		t.Fatalf("SealPlan(wrong profile) returned an error: %v", err)
	}
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		wrongProfile, validExecutionEvidence(wrongProfile, checkedAt), contract,
	), policy.BlockerContract)

	wrongSimulation := plan
	wrongSimulation.ExposureControls = cloneExposureControls(plan.ExposureControls)
	wrongSimulation.Preconditions = append(wrongSimulation.Preconditions, domain.PlanPrecondition{
		ID: "alternate-simulation", OK: true, Detail: redact.Sanitize("passed"),
	})
	wrongSimulation.ExposureControls.SimulationPreconditionID = "alternate-simulation"
	wrongSimulation, err = policy.SealPlan(wrongSimulation)
	if err != nil {
		t.Fatalf("SealPlan(wrong simulation) returned an error: %v", err)
	}
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		wrongSimulation, validExecutionEvidence(wrongSimulation, checkedAt), contract,
	), policy.BlockerContract)

	wrongTarget := plan
	wrongTarget.ExposureControls = cloneExposureControls(plan.ExposureControls)
	second := plan.Resources[0]
	second.Name = "second-instance"
	second.Fingerprint = "generation-8"
	wrongTarget.Resources = append(wrongTarget.Resources, second)
	wrongTarget.Steps[0].Targets = append(wrongTarget.Steps[0].Targets, second)
	permission := wrongTarget.Permissions[0]
	permission.Resource = second
	wrongTarget.Permissions = append(wrongTarget.Permissions, permission)
	wrongTarget.ExposureControls.Targets = []domain.PlanResource{second}
	wrongTarget, err = policy.SealPlan(wrongTarget)
	if err != nil {
		t.Fatalf("SealPlan(wrong target) returned an error: %v", err)
	}
	wrongTargetContract := executionContractForPlan(
		t, wrongTarget, domain.ApprovalSecuritySensitive, false, false,
	)
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		wrongTarget, validExecutionEvidence(wrongTarget, checkedAt), wrongTargetContract,
	), policy.BlockerContract)
}

func TestExecutionGateRevalidatesExposureLifetime(t *testing.T) {
	t.Parallel()

	expiryPlan := validPlan()
	expiryPlan.ApprovalClass = domain.ApprovalSecuritySensitive
	expiryPlan.ExpiresAt = expiryPlan.CreatedAt.Add(4 * time.Hour)
	expiryPlan.Exposure = domain.ExposureExternal
	expiryPlan.ExposureControls = validExposureControls(expiryPlan)
	expiryPlan.ExposureControls.ReviewAt = nil
	expiresAt := expiryPlan.CreatedAt.Add(2 * time.Hour)
	expiryPlan.ExposureControls.ExpiresAt = &expiresAt
	expiryPlan, err := policy.SealPlan(expiryPlan)
	if err != nil {
		t.Fatalf("SealPlan(expiry) returned an error: %v", err)
	}
	expiryContract := executionContractForPlan(t, expiryPlan, domain.ApprovalSecuritySensitive, false, false)
	justBefore := expiresAt.Add(-time.Nanosecond)
	if err := policy.ValidatePlanForExecution(
		expiryPlan, validExecutionEvidence(expiryPlan, justBefore), expiryContract,
	); err != nil {
		t.Fatalf("ValidatePlanForExecution(before expiry) returned an error: %v", err)
	}
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		expiryPlan, validExecutionEvidence(expiryPlan, expiresAt), expiryContract,
	), policy.BlockerExposure)

	reviewPlan := validPlan()
	reviewPlan.ApprovalClass = domain.ApprovalSecuritySensitive
	reviewPlan.ExpiresAt = reviewPlan.CreatedAt.Add(72 * time.Hour)
	reviewPlan.Exposure = domain.ExposureExternal
	reviewPlan.ExposureControls = validExposureControls(reviewPlan)
	reviewAt := reviewPlan.CreatedAt.Add(24 * time.Hour)
	reviewPlan.ExposureControls.ReviewAt = &reviewAt
	reviewPlan, err = policy.SealPlan(reviewPlan)
	if err != nil {
		t.Fatalf("SealPlan(review) returned an error: %v", err)
	}
	reviewContract := executionContractForPlan(t, reviewPlan, domain.ApprovalSecuritySensitive, false, false)
	sameUTCDate := time.Date(reviewAt.Year(), reviewAt.Month(), reviewAt.Day(), 23, 59, 59, 0, time.UTC)
	if err := policy.ValidatePlanForExecution(
		reviewPlan, validExecutionEvidence(reviewPlan, sameUTCDate), reviewContract,
	); err != nil {
		t.Fatalf("ValidatePlanForExecution(on review date) returned an error: %v", err)
	}
	nextUTCDate := sameUTCDate.Add(time.Second)
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		reviewPlan, validExecutionEvidence(reviewPlan, nextUTCDate), reviewContract,
	), policy.BlockerExposure)
}

func TestExecutionGateRejectsMissingStaleOrMismatchedEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		kind   policy.PlanBlockerKind
		mutate func(*domain.Plan, *policy.ExecutionEvidence)
	}{
		{name: "before plan creation", kind: policy.BlockerPlanTime, mutate: func(plan *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.CheckedAt = plan.CreatedAt.Add(-time.Second)
			evidence.ObservedAt = evidence.CheckedAt
		}},
		{name: "observation predates plan", kind: policy.BlockerPlanTime, mutate: func(plan *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.ObservedAt = plan.CreatedAt.Add(-time.Nanosecond)
		}},
		{name: "stale observation", kind: policy.BlockerPlanTime, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.ObservedAt = evidence.CheckedAt.Add(-10*time.Minute - time.Nanosecond)
		}},
		{name: "wrong project binding", kind: policy.BlockerPlanBinding, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.ProjectID = "ctrldb-other-123"
		}},
		{name: "wrong principal binding", kind: policy.BlockerPlanBinding, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.Principal = "other@example.com"
		}},
		{name: "missing approval", kind: policy.BlockerApproval, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.Approval = nil
		}},
		{name: "approval from another plan", kind: policy.BlockerApproval, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.Approval.PlanID = "plan-fedcba9876543210"
		}},
		{name: "approval from another project", kind: policy.BlockerApproval, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.Approval.ProjectID = "ctrldb-other-123"
		}},
		{name: "resource drift", kind: policy.BlockerResource, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.Resources[0].Fingerprint = "generation-8"
		}},
		{name: "resource scope drift", kind: policy.BlockerResource, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.Resources[0].Scope = "projects/ctrldb-prod-123/zones/us-central1-b"
		}},
		{name: "revoked permission", kind: policy.BlockerPermission, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.Permissions[0].Granted = false
		}},
		{name: "permission from another scope", kind: policy.BlockerPermission, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.Permissions[0].Resource.Scope = "projects/ctrldb-prod-123/zones/us-central1-b"
		}},
		{name: "false fresh precondition", kind: policy.BlockerPrecondition, mutate: func(_ *domain.Plan, evidence *policy.ExecutionEvidence) {
			evidence.Preconditions[0].OK = false
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan := validPlan()
			evidence := validExecutionEvidence(plan, plan.CreatedAt.Add(10*time.Minute))
			test.mutate(&plan, &evidence)
			expectBlockedKind(t, policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)), test.kind)
		})
	}
}

func TestExecutionEvidenceFreshnessBoundary(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	checkedAt := plan.CreatedAt.Add(30 * time.Minute)
	evidence := validExecutionEvidence(plan, checkedAt)
	evidence.Approval.ServerTimeCreated = checkedAt.Add(-20 * time.Minute)
	evidence.ObservedAt = checkedAt.Add(-10 * time.Minute)
	if err := policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)); err != nil {
		t.Fatalf("exact ten-minute evidence boundary returned an error: %v", err)
	}
	evidence.ObservedAt = checkedAt.Add(-10*time.Minute - time.Nanosecond)
	expectBlockedKind(t, policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)), policy.BlockerPlanTime)
}

func TestExecutionGateUsesServerApprovalTimeForCoolingOff(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	plan.CoolingOffSeconds = 600
	plan, err := policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}
	checkedAt := plan.CreatedAt.Add(30 * time.Minute)
	evidence := validExecutionEvidence(plan, checkedAt)
	evidence.Approval.ServerTimeCreated = checkedAt.Add(-5 * time.Minute)

	expectBlockedKind(t, policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)), policy.BlockerCoolingOff)
	evidence.Approval.ServerTimeCreated = checkedAt.Add(-10 * time.Minute)
	if err := policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)); err != nil {
		t.Fatalf("cooling boundary should use server approval time: %v", err)
	}
	evidence.ObservedAt = checkedAt.Add(-10*time.Minute - time.Nanosecond)
	expectBlockedKind(t, policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)), policy.BlockerCoolingOff)
}

func TestExecutionGateEnforcesIntentWindowAndBinding(t *testing.T) {
	t.Parallel()

	base := validPlan()
	base.ExpiresAt = base.CreatedAt.Add(4 * time.Hour)
	base.Intent = &domain.PlanIntent{
		WindowStart: base.CreatedAt.Add(time.Hour),
		ValidUntil:  base.CreatedAt.Add(3 * time.Hour),
	}
	plan, err := policy.SealPlan(base)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}

	for _, test := range []struct {
		name   string
		at     time.Time
		mutate func(*policy.ExecutionEvidence)
	}{
		{name: "before window", at: plan.Intent.WindowStart.Add(-time.Nanosecond)},
		{name: "after validity", at: plan.Intent.ValidUntil.Add(time.Nanosecond)},
		{name: "not sole active", at: plan.Intent.WindowStart, mutate: func(evidence *policy.ExecutionEvidence) {
			evidence.Intent.SoleActive = false
		}},
		{name: "wrong policy binding", at: plan.Intent.WindowStart, mutate: func(evidence *policy.ExecutionEvidence) {
			evidence.Intent.PolicyHash = "different"
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			evidence := validExecutionEvidence(plan, test.at)
			if test.mutate != nil {
				test.mutate(&evidence)
			}
			expectBlockedKind(t, policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)), policy.BlockerIntent)
		})
	}

	evidence := validExecutionEvidence(plan, plan.Intent.WindowStart)
	if err := policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)); err != nil {
		t.Fatalf("valid intent boundary returned an error: %v", err)
	}
}

func TestExecutionGateBlocksUnapprovedPolicy(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	plan.PolicyHash.Approved = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	plan.PolicyHash.Match = false
	plan, err := policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}
	evidence := validExecutionEvidence(plan, plan.CreatedAt.Add(10*time.Minute))

	expectBlockedKind(t, policy.ValidatePlanForExecution(plan, evidence, validExecutionContract(t)), policy.BlockerPolicy)
}

func TestExecutionGateRequiresFreshSamePlanStepUp(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	plan.ApprovalClass = domain.ApprovalDataDestructive
	plan.StepUpRequired = true
	plan.CoolingOffSeconds = 600
	plan, err := policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}
	contract := executionContractForPlan(t, plan, domain.ApprovalDataDestructive, true, true)
	checkedAt := plan.CreatedAt.Add(30 * time.Minute)
	evidence := validExecutionEvidence(plan, checkedAt)
	evidence.Approval.ServerTimeCreated = checkedAt.Add(-20 * time.Minute)
	evidence.ObservedAt = checkedAt.Add(-10 * time.Minute)
	evidence.StepUp.ServerTimeCreated = checkedAt.Add(-10*time.Minute + time.Nanosecond)
	if err := policy.ValidatePlanForExecution(plan, evidence, contract); err != nil {
		t.Fatalf("fresh step-up returned an error: %v", err)
	}

	for _, mutate := range []func(*policy.ExecutionEvidence){
		func(evidence *policy.ExecutionEvidence) { evidence.StepUp = nil },
		func(evidence *policy.ExecutionEvidence) {
			evidence.ObservedAt = checkedAt.Add(-10 * time.Minute)
			evidence.StepUp.ServerTimeCreated = checkedAt.Add(-10 * time.Minute)
		},
		func(evidence *policy.ExecutionEvidence) { evidence.StepUp.PlanID = "plan-fedcba9876543210" },
		func(evidence *policy.ExecutionEvidence) { evidence.StepUp.ProjectID = "ctrldb-other-123" },
		func(evidence *policy.ExecutionEvidence) { evidence.StepUp.Principal = "other@example.com" },
		func(evidence *policy.ExecutionEvidence) {
			evidence.StepUp.ServerTimeCreated = evidence.ObservedAt.Add(-time.Nanosecond)
		},
		func(evidence *policy.ExecutionEvidence) {
			evidence.ObservedAt = checkedAt.Add(-10*time.Minute - time.Nanosecond)
			evidence.StepUp.ServerTimeCreated = evidence.ObservedAt
		},
	} {
		changed := validExecutionEvidence(plan, checkedAt)
		changed.Approval.ServerTimeCreated = checkedAt.Add(-20 * time.Minute)
		mutate(&changed)
		expectBlockedKind(t, policy.ValidatePlanForExecution(plan, changed, contract), policy.BlockerStepUp)
	}
}

func TestExecutionGateDerivesStepUpOnlyFromTrustedSteps(t *testing.T) {
	t.Parallel()

	dataPlan := validPlan()
	dataPlan.ApprovalClass = domain.ApprovalDataDestructive
	dataPlan.StepUpRequired = false
	dataPlan, err := policy.SealPlan(dataPlan)
	if err != nil {
		t.Fatalf("SealPlan(data) returned an error: %v", err)
	}
	dataContract := executionContractForPlan(t, dataPlan, domain.ApprovalDataDestructive, true, true)
	checkedAt := dataPlan.CreatedAt.Add(10 * time.Minute)
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		dataPlan, validExecutionEvidence(dataPlan, checkedAt), dataContract,
	), policy.BlockerStepUp)

	dataPlan.StepUpRequired = true
	dataPlan, err = policy.SealPlan(dataPlan)
	if err != nil {
		t.Fatalf("SealPlan(data with step-up) returned an error: %v", err)
	}
	dataContract = executionContractForPlan(t, dataPlan, domain.ApprovalDataDestructive, true, true)
	if err := policy.ValidatePlanForExecution(
		dataPlan, validExecutionEvidence(dataPlan, checkedAt), dataContract,
	); err != nil {
		t.Fatalf("data-destructive AP-5 gate returned an error: %v", err)
	}
	withoutRequirement := executionContractForPlan(t, dataPlan, domain.ApprovalDataDestructive, false, true)
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		dataPlan, validExecutionEvidence(dataPlan, checkedAt), withoutRequirement,
	), policy.BlockerStepUp)

	exposurePlan := validPlan()
	exposurePlan.ApprovalClass = domain.ApprovalDataDestructive
	exposurePlan.Exposure = domain.ExposureExternal
	exposurePlan.ExposureControls = validExposureControls(exposurePlan)
	exposurePlan.ExposureControls.Profile = domain.ExposureProfileACC08
	exposurePlan.ExposureControls.Sources[0].Value = "0.0.0.0/0"
	exposurePlan.ExposureControls.InternetWide = true
	exposurePlan.ExposureControls.ReviewAt = nil
	expiresAt := exposurePlan.CreatedAt.Add(time.Hour)
	exposurePlan.ExposureControls.ExpiresAt = &expiresAt
	exposurePlan.StepUpRequired = false
	exposurePlan, err = policy.SealPlan(exposurePlan)
	if err != nil {
		t.Fatalf("SealPlan(internet-wide) returned an error: %v", err)
	}
	exposureContract := executionContractForPlan(
		t, exposurePlan, domain.ApprovalDataDestructive, false, true,
	)
	if err := policy.ValidatePlanForExecution(
		exposurePlan, validExecutionEvidence(exposurePlan, checkedAt), exposureContract,
	); err != nil {
		t.Fatalf("internet-wide AP-5 without step-up returned an error: %v", err)
	}
	exposurePlan.StepUpRequired = true
	exposurePlan, err = policy.SealPlan(exposurePlan)
	if err != nil {
		t.Fatalf("SealPlan(internet-wide forged step-up) returned an error: %v", err)
	}
	expectBlockedKind(t, policy.ValidatePlanForExecution(
		exposurePlan, validExecutionEvidence(exposurePlan, checkedAt), exposureContract,
	), policy.BlockerStepUp)
}

func TestPermissionChecksRejectsAmbiguousProbeEvidence(t *testing.T) {
	t.Parallel()

	valid := policy.PermissionProbe{
		ProjectID: "ctrldb-prod-123",
		StepID:    "stop-instance",
		Identity:  domain.IdentityOperator,
		Resource: domain.PlanResource{
			Kind:        "instance",
			Scope:       "projects/ctrldb-prod-123/zones/us-central1-a",
			Name:        "example-instance",
			Fingerprint: "generation-7",
		},
		Required: []string{"compute.instances.get"},
		Granted:  []string{"compute.instances.get"},
	}
	tests := []struct {
		name   string
		mutate func(*policy.PermissionProbe)
	}{
		{name: "missing project", mutate: func(probe *policy.PermissionProbe) { probe.ProjectID = "" }},
		{name: "missing step", mutate: func(probe *policy.PermissionProbe) { probe.StepID = "" }},
		{name: "unknown identity", mutate: func(probe *policy.PermissionProbe) { probe.Identity = "root" }},
		{name: "missing resource", mutate: func(probe *policy.PermissionProbe) { probe.Resource.Fingerprint = "" }},
		{name: "foreign resource scope", mutate: func(probe *policy.PermissionProbe) {
			probe.Resource.Scope = "projects/ctrldb-other-123/zones/us-central1-a"
		}},
		{name: "empty required", mutate: func(probe *policy.PermissionProbe) { probe.Required = nil; probe.Granted = nil }},
		{name: "malformed required", mutate: func(probe *policy.PermissionProbe) { probe.Required = []string{"instances.get"}; probe.Granted = nil }},
		{name: "duplicate required", mutate: func(probe *policy.PermissionProbe) {
			probe.Required = []string{"compute.instances.get", "compute.instances.get"}
		}},
		{name: "unexpected granted", mutate: func(probe *policy.PermissionProbe) { probe.Granted = []string{"compute.instances.stop"} }},
		{name: "duplicate granted", mutate: func(probe *policy.PermissionProbe) {
			probe.Granted = []string{"compute.instances.get", "compute.instances.get"}
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			probe := valid
			test.mutate(&probe)
			if _, err := policy.PermissionChecks(probe); !errors.Is(err, policy.ErrInvalidPermissionProbe) {
				t.Fatalf("PermissionChecks() error = %v, want ErrInvalidPermissionProbe", err)
			}
		})
	}
}

func TestPlanPermissionCoverageIncludesEveryStepIdentityAndResource(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	secondResource := domain.PlanResource{
		Kind:        "disk",
		Scope:       "projects/ctrldb-prod-123/zones/us-central1-a",
		Name:        "example-disk",
		Fingerprint: "generation-2",
	}
	plan.Resources = append(plan.Resources, secondResource)
	plan.Steps[0].Targets = append(plan.Steps[0].Targets, secondResource)
	if _, err := policy.SealPlan(plan); !errors.Is(err, policy.ErrInvalidPlan) {
		t.Fatalf("SealPlan() missing resource permission error = %v, want ErrInvalidPlan", err)
	}
	plan.Permissions = append(plan.Permissions, domain.PlanPermission{
		StepID:     plan.Steps[0].ID,
		Identity:   plan.Steps[0].ExecutingIdentity,
		Permission: "compute.disks.use",
		Resource:   secondResource,
		Granted:    true,
	})
	if _, err := policy.SealPlan(plan); err != nil {
		t.Fatalf("SealPlan() complete resource coverage returned an error: %v", err)
	}

	withoutResource := validPlan()
	withoutResource.Resources = nil
	withoutResource.Permissions = nil
	if _, err := policy.SealPlan(withoutResource); !errors.Is(err, policy.ErrInvalidPlan) {
		t.Fatalf("SealPlan() resource-less mutation error = %v, want ErrInvalidPlan", err)
	}

	withoutIdentity := validPlan()
	secondStep := withoutIdentity.Steps[0]
	secondStep.ID = "delete-instance"
	secondStep.ExecutingIdentity = domain.IdentityDestructive
	withoutIdentity.Steps = append(withoutIdentity.Steps, secondStep)
	if _, err := policy.SealPlan(withoutIdentity); !errors.Is(err, policy.ErrInvalidPlan) {
		t.Fatalf("SealPlan() missing step identity coverage error = %v, want ErrInvalidPlan", err)
	}
}

func validExecutionEvidence(plan domain.Plan, checkedAt time.Time) policy.ExecutionEvidence {
	evidence := policy.ExecutionEvidence{
		PlanID:           plan.PlanID,
		PlanHash:         plan.PlanHash,
		ProjectID:        plan.ProjectID,
		Environment:      plan.Environment,
		EnvironmentClass: plan.EnvironmentClass,
		Principal:        plan.Principal,
		CheckedAt:        checkedAt,
		ObservedAt:       checkedAt,
		PolicyHash:       plan.PolicyHash,
		Preconditions:    append([]domain.PlanPrecondition(nil), plan.Preconditions...),
		Resources:        append([]domain.PlanResource(nil), plan.Resources...),
		RecoveryAssets:   append([]domain.PlanRecoveryAsset(nil), plan.Rollback.Assets...),
		Permissions:      append([]domain.PlanPermission(nil), plan.Permissions...),
	}
	if plan.ApprovalClass != domain.ApprovalRead || plan.Intent != nil {
		evidence.Approval = &policy.ApprovalEvidence{
			PlanID:            plan.PlanID,
			PlanHash:          plan.PlanHash,
			ProjectID:         plan.ProjectID,
			Environment:       plan.Environment,
			EnvironmentClass:  plan.EnvironmentClass,
			Principal:         plan.Principal,
			RecordObject:      "plans/" + plan.Environment + "/" + plan.PlanID + "-approval.json",
			ServerTimeCreated: checkedAt.Add(-time.Minute),
		}
	}
	if plan.Intent != nil {
		evidence.Approval.ServerTimeCreated = checkedAt
		evidence.Intent = &policy.IntentEvidence{
			PlanID:           plan.PlanID,
			PlanHash:         plan.PlanHash,
			ProjectID:        plan.ProjectID,
			PolicyHash:       plan.PolicyHash.Approved,
			Environment:      plan.Environment,
			EnvironmentClass: plan.EnvironmentClass,
			Principal:        plan.Principal,
			WindowStart:      plan.Intent.WindowStart,
			ValidUntil:       plan.Intent.ValidUntil,
			Active:           true,
			SoleActive:       true,
		}
	}
	if plan.StepUpRequired {
		evidence.ObservedAt = checkedAt.Add(-30 * time.Second)
		evidence.StepUp = &policy.StepUpEvidence{
			PlanID:            plan.PlanID,
			PlanHash:          plan.PlanHash,
			ProjectID:         plan.ProjectID,
			Environment:       plan.Environment,
			EnvironmentClass:  plan.EnvironmentClass,
			Principal:         plan.Principal,
			RecordObject:      "plans/" + plan.Environment + "/" + plan.PlanID + "-stepup-1.json",
			ServerTimeCreated: checkedAt.Add(-20 * time.Second),
		}
	}

	return evidence
}

func validExecutionContract(t *testing.T) domain.ExecutionContract {
	t.Helper()
	definition, err := workflow.NewDefinition(
		"WF-VM-02", "before-old-instance-delete", "stop-instance", domain.PointOfNoReturnStepComplete,
		[]workflow.StepDefinition{
			{
				ID:                  "stop-instance",
				Executor:            "gcloud",
				ExecutingIdentity:   domain.IdentityOperator,
				CommandSummary:      redact.Sanitize("gcloud compute instances stop example"),
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
			},
		},
	)
	if err != nil {
		t.Fatalf("NewDefinition() returned an error: %v", err)
	}

	return definition.ExecutionContract()
}

func executionContractForPlan(
	t *testing.T,
	plan domain.Plan,
	minimumApproval domain.ApprovalClass,
	requiresStepUp, requiresRecovery bool,
) domain.ExecutionContract {
	t.Helper()
	step := plan.Steps[0]
	var exposureRequirement *domain.ExecutionExposureRequirement
	if plan.Exposure != domain.ExposureNone && plan.ExposureControls != nil {
		exposureRequirement = &domain.ExecutionExposureRequirement{
			Delta: plan.Exposure, Profile: plan.ExposureControls.Profile,
			InternetWide:             plan.ExposureControls.InternetWide,
			SimulationPreconditionID: plan.ExposureControls.SimulationPreconditionID,
		}
	}
	definition, err := workflow.NewDefinition(
		plan.WorkflowID, plan.Rollback.Boundary, plan.PointOfNoReturn, plan.PointOfNoReturnTrigger,
		[]workflow.StepDefinition{{
			ID: step.ID, Executor: step.Executor, ExecutingIdentity: step.ExecutingIdentity,
			CommandSummary: step.CommandRedacted,
			Effect:         domain.StepEffectMutation, MinimumApproval: minimumApproval,
			TargetKinds: []string{step.Targets[0].Kind}, RequiredPermissions: []string{plan.Permissions[0].Permission},
			RequiresStepUp: requiresStepUp, RequiresRecoveryAsset: requiresRecovery,
			ExposureRequirement: exposureRequirement,
			Idempotent:          step.Idempotent, Retry: step.Retry, CancelSafe: step.CancelSafe,
			TimeoutSeconds: step.TimeoutSeconds, SuccessCondition: step.SuccessCondition,
			FailureBehavior: step.FailureBehavior,
		}},
	)
	if err != nil {
		t.Fatalf("NewDefinition() returned an error: %v", err)
	}

	return definition.ExecutionContract()
}

func cloneExposureControls(controls *domain.PlanExposureControls) *domain.PlanExposureControls {
	if controls == nil {
		return nil
	}
	cloned := *controls
	cloned.Targets = append([]domain.PlanResource(nil), controls.Targets...)
	cloned.Sources = append([]domain.PlanExposureSource(nil), controls.Sources...)
	cloned.Ports = append([]domain.PlanExposurePort(nil), controls.Ports...)

	return &cloned
}

func ap4ExecutionPlan(
	t *testing.T,
	stepID, kind, permission string,
	requiresStepUp bool,
) (domain.Plan, domain.ExecutionContract) {
	t.Helper()
	plan := validPlan()
	plan.ApprovalClass = domain.ApprovalDestructive
	plan.StepUpRequired = requiresStepUp
	plan.Resources[0].Kind = kind
	plan.Resources[0].Name = "target-resource"
	plan.Steps[0].ID = stepID
	plan.Steps[0].Executor = "compute-api"
	plan.Steps[0].CommandRedacted = redact.Sanitize("execute reviewed resource operation")
	plan.Steps[0].Targets[0] = plan.Resources[0]
	plan.Rollback.Assets[0].Protects = []domain.PlanResource{plan.Resources[0]}
	plan.Permissions[0].StepID = stepID
	plan.Permissions[0].Permission = permission
	plan.Permissions[0].Resource = plan.Resources[0]
	plan.PointOfNoReturn = stepID
	plan.PointOfNoReturnTrigger = domain.PointOfNoReturnStepComplete
	sealed, err := policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}
	definition, err := workflow.NewDefinition(
		plan.WorkflowID, plan.Rollback.Boundary, plan.PointOfNoReturn, plan.PointOfNoReturnTrigger,
		[]workflow.StepDefinition{
			{
				ID:                  stepID,
				Executor:            plan.Steps[0].Executor,
				ExecutingIdentity:   plan.Steps[0].ExecutingIdentity,
				CommandSummary:      plan.Steps[0].CommandRedacted,
				Effect:              domain.StepEffectMutation,
				MinimumApproval:     domain.ApprovalDestructive,
				TargetKinds:         []string{kind},
				RequiredPermissions: []string{permission},
				RequiresStepUp:      requiresStepUp,
				Idempotent:          plan.Steps[0].Idempotent,
				Retry:               plan.Steps[0].Retry,
				CancelSafe:          plan.Steps[0].CancelSafe,
				TimeoutSeconds:      plan.Steps[0].TimeoutSeconds,
				SuccessCondition:    plan.Steps[0].SuccessCondition,
				FailureBehavior:     plan.Steps[0].FailureBehavior,
			},
		},
	)
	if err != nil {
		t.Fatalf("NewDefinition() returned an error: %v", err)
	}

	return sealed, definition.ExecutionContract()
}

func expectBlockedKind(t *testing.T, err error, kind policy.PlanBlockerKind) {
	t.Helper()
	var blocked *policy.BlockedPlanError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want *BlockedPlanError", err)
	}
	for _, blocker := range blocked.Blockers() {
		if blocker.Kind == kind {
			return
		}
	}
	t.Fatalf("blockers = %#v, want kind %q", blocked.Blockers(), kind)
}
