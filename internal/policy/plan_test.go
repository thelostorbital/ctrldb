// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package policy_test

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/policy"
	"github.com/thelostorbital/ctrldb/internal/redact"
)

func TestPlanEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	want := validPlan()
	encoded, err := policy.EncodePlan(want)
	if err != nil {
		t.Fatalf("EncodePlan() returned an error: %v", err)
	}

	got, err := policy.DecodePlan(encoded)
	if err != nil {
		t.Fatalf("DecodePlan() returned an error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded plan differs:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestPlanDecodeResanitizesStoredText(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	plan.Steps[0].CommandRedacted = redact.Sanitize("password=SECRET_MARKER_STORED_PLAN")
	plan, err := policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}
	encoded, err := policy.EncodePlan(plan)
	if err != nil {
		t.Fatalf("EncodePlan() returned an error: %v", err)
	}

	encoded = bytes.Replace(
		encoded,
		[]byte(`"commandRedacted":"[redacted]"`),
		[]byte(`"commandRedacted":"password=SECRET_MARKER_STORED_PLAN"`),
		1,
	)
	decoded, err := policy.DecodePlan(encoded)
	if err != nil {
		t.Fatalf("DecodePlan() returned an error: %v", err)
	}
	if got := decoded.Steps[0].CommandRedacted.String(); got != "password=[redacted]" {
		t.Fatalf("decoded command = %q, want a redacted value", got)
	}
}

func TestPlanSealAndHashVerification(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	if err := policy.VerifyPlanHash(plan); err != nil {
		t.Fatalf("VerifyPlanHash() returned an error: %v", err)
	}

	const knownDigest = "836643e2a07f445f9f8b5076633b74a5343d19083924060fcf52d4e625111e77"
	if plan.PlanHash != knownDigest {
		t.Fatalf("sealed plan digest = %q, want known vector %q", plan.PlanHash, knownDigest)
	}

	input := plan
	input.PlanHash = "ignored-by-computation"
	digest, err := policy.ComputePlanHash(input)
	if err != nil {
		t.Fatalf("ComputePlanHash() returned an error: %v", err)
	}
	if digest != plan.PlanHash {
		t.Fatalf("ComputePlanHash() = %q, want %q", digest, plan.PlanHash)
	}
	if input.PlanHash != "ignored-by-computation" {
		t.Fatalf("ComputePlanHash() mutated its input to %q", input.PlanHash)
	}

	tampered := plan
	tampered.Downtime.ExpectedSeconds++
	if err := policy.VerifyPlanHash(tampered); !errors.Is(err, policy.ErrInvalidPlan) {
		t.Fatalf("VerifyPlanHash() tampered error = %v, want ErrInvalidPlan", err)
	}
	if _, err := policy.EncodePlan(tampered); !errors.Is(err, policy.ErrInvalidPlan) {
		t.Fatalf("EncodePlan() tampered error = %v, want ErrInvalidPlan", err)
	}

	encoded, err := policy.EncodePlan(plan)
	if err != nil {
		t.Fatalf("EncodePlan() returned an error: %v", err)
	}
	encoded = bytes.Replace(encoded, []byte(`"generation-7"`), []byte(`"generation-8"`), 1)
	if _, err := policy.DecodePlan(encoded); !errors.Is(err, policy.ErrInvalidPlan) {
		t.Fatalf("DecodePlan() tampered error = %v, want ErrInvalidPlan", err)
	}
}

func TestPlanHashCoversEveryPlanV1Field_TEST_U_PLAN_02(t *testing.T) {
	t.Parallel()

	original := validPlan()
	tests := []struct {
		name   string
		mutate func(*domain.Plan)
	}{
		{name: "plan id", mutate: func(plan *domain.Plan) { plan.PlanID = "plan-fedcba9876543210" }},
		{name: "workflow", mutate: func(plan *domain.Plan) { plan.WorkflowID = "WF-DSK-01" }},
		{name: "environment", mutate: func(plan *domain.Plan) { plan.Environment = "staging" }},
		{name: "principal", mutate: func(plan *domain.Plan) { plan.Principal = "reviewer@example.com" }},
		{name: "creation time", mutate: func(plan *domain.Plan) { plan.CreatedAt = plan.CreatedAt.Add(time.Second) }},
		{name: "approval", mutate: func(plan *domain.Plan) { plan.ApprovalClass = domain.ApprovalSecuritySensitive }},
		{name: "expiry", mutate: func(plan *domain.Plan) { plan.ExpiresAt = plan.ExpiresAt.Add(time.Minute) }},
		{name: "cooling off", mutate: func(plan *domain.Plan) { plan.CoolingOffSeconds++ }},
		{name: "policy hash", mutate: func(plan *domain.Plan) {
			plan.PolicyHash.Local = strings.Repeat("c", 64)
			plan.PolicyHash.Approved = strings.Repeat("c", 64)
		}},
		{name: "intent", mutate: func(plan *domain.Plan) {
			plan.Intent = &domain.PlanIntent{
				WindowStart: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
				ValidUntil:  time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
			}
		}},
		{name: "resource", mutate: func(plan *domain.Plan) { plan.Resources[0].Fingerprint = "generation-8" }},
		{name: "precondition", mutate: func(plan *domain.Plan) { plan.Preconditions[0].Detail = redact.Sanitize("ready") }},
		{name: "precondition outcome", mutate: func(plan *domain.Plan) { plan.Preconditions[0].OK = false }},
		{name: "permission", mutate: func(plan *domain.Plan) { plan.Permissions[0].Granted = false }},
		{name: "step", mutate: func(plan *domain.Plan) { plan.Steps[0].Executor = "compute-api" }},
		{name: "step retry", mutate: func(plan *domain.Plan) { plan.Steps[0].Retry.MaxAttempts++ }},
		{name: "step success", mutate: func(plan *domain.Plan) { plan.Steps[0].SuccessCondition = redact.Sanitize("stopped") }},
		{name: "step failure", mutate: func(plan *domain.Plan) { plan.Steps[0].FailureBehavior = domain.FailurePause }},
		{name: "cost", mutate: func(plan *domain.Plan) { plan.Cost.RunRate.AmountUSD++ }},
		{name: "downtime", mutate: func(plan *domain.Plan) { plan.Downtime.ExpectedSeconds++ }},
		{name: "exposure", mutate: func(plan *domain.Plan) { plan.Exposure = domain.ExposurePrivate }},
		{name: "protection", mutate: func(plan *domain.Plan) { plan.Protection[0] = redact.Sanitize("verified snapshot") }},
		{name: "rollback", mutate: func(plan *domain.Plan) { plan.Rollback.Assets[0] = "replacement-instance" }},
		{name: "point of no return", mutate: func(plan *domain.Plan) { plan.PointOfNoReturn = "" }},
		{name: "verification", mutate: func(plan *domain.Plan) { plan.Verification[0] = redact.Sanitize("database health check") }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			changed := validPlan()
			test.mutate(&changed)
			digest, err := policy.ComputePlanHash(changed)
			if err != nil {
				t.Fatalf("ComputePlanHash() returned an error: %v", err)
			}
			if digest == original.PlanHash {
				t.Fatalf("changing %s did not change the plan digest", test.name)
			}
		})
	}
}

func TestPlanDecodeRejectsOpenOrMalformedJSON(t *testing.T) {
	t.Parallel()

	encoded, err := policy.EncodePlan(validPlan())
	if err != nil {
		t.Fatalf("EncodePlan() returned an error: %v", err)
	}

	tests := map[string][]byte{
		"unknown top-level field": bytes.Replace(encoded, []byte(`{"planId"`), []byte(`{"unknown":true,"planId"`), 1),
		"unknown nested field": bytes.Replace(
			encoded,
			[]byte(`"identity":{"default"`),
			[]byte(`"identity":{"unknown":true,"default"`),
			1,
		),
		"trailing value": append(append([]byte(nil), encoded...), []byte(` {}`)...),
		"malformed":      []byte(`{"planId":`),
	}

	for name, input := range tests {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := policy.DecodePlan(input); !errors.Is(err, policy.ErrInvalidPlan) {
				t.Fatalf("DecodePlan() error = %v, want ErrInvalidPlan", err)
			}
		})
	}
}

func TestPlanDecodeRejectsMissingExecutionContractFields(t *testing.T) {
	t.Parallel()

	encoded, err := policy.EncodePlan(validPlan())
	if err != nil {
		t.Fatalf("EncodePlan() returned an error: %v", err)
	}

	for _, field := range []string{
		"environment", "principal", "createdAt", "permissions", "retry",
		"idempotent", "cancelSafe", "successCondition", "failureBehavior",
	} {
		field := field
		t.Run(field, func(t *testing.T) {
			without := removeJSONField(t, encoded, field)
			if _, err := policy.DecodePlan(without); !errors.Is(err, policy.ErrInvalidPlan) {
				t.Fatalf("DecodePlan() error = %v, want ErrInvalidPlan", err)
			}
		})
	}
}

func TestPlanValidationRejectsUnsafeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*domain.Plan)
	}{
		{name: "plan id", mutate: func(plan *domain.Plan) { plan.PlanID = "plan-production" }},
		{name: "plan hash", mutate: func(plan *domain.Plan) { plan.PlanHash = "ABC" }},
		{name: "workflow id", mutate: func(plan *domain.Plan) { plan.WorkflowID = "vm-resize" }},
		{name: "approval class", mutate: func(plan *domain.Plan) { plan.ApprovalClass = 255 }},
		{name: "zero expiry", mutate: func(plan *domain.Plan) { plan.ExpiresAt = time.Time{} }},
		{name: "zero creation", mutate: func(plan *domain.Plan) { plan.CreatedAt = time.Time{} }},
		{name: "expiry before creation", mutate: func(plan *domain.Plan) { plan.ExpiresAt = plan.CreatedAt }},
		{name: "environment", mutate: func(plan *domain.Plan) { plan.Environment = "Production" }},
		{name: "principal", mutate: func(plan *domain.Plan) { plan.Principal = "operator example" }},
		{name: "non UTC expiry", mutate: func(plan *domain.Plan) {
			plan.ExpiresAt = time.Date(2026, 9, 3, 12, 0, 0, 0, time.FixedZone("offset", 3600))
		}},
		{name: "negative cooling off", mutate: func(plan *domain.Plan) { plan.CoolingOffSeconds = -1 }},
		{name: "identity routing", mutate: func(plan *domain.Plan) { plan.Identity.DeleteSteps = domain.IdentityOperator }},
		{name: "local policy hash", mutate: func(plan *domain.Plan) { plan.PolicyHash.Local = "bad" }},
		{name: "approved policy hash", mutate: func(plan *domain.Plan) { plan.PolicyHash.Approved = "bad" }},
		{name: "policy match", mutate: func(plan *domain.Plan) { plan.PolicyHash.Match = false }},
		{name: "step up class", mutate: func(plan *domain.Plan) { plan.StepUpRequired = true }},
		{name: "intent window", mutate: func(plan *domain.Plan) {
			plan.Intent = &domain.PlanIntent{ValidUntil: time.Date(2026, 9, 4, 13, 0, 0, 0, time.UTC)}
		}},
		{name: "intent validity", mutate: func(plan *domain.Plan) {
			plan.Intent = &domain.PlanIntent{WindowStart: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
		}},
		{name: "intent order", mutate: func(plan *domain.Plan) {
			start := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
			plan.Intent = &domain.PlanIntent{WindowStart: start, ValidUntil: start}
		}},
		{name: "resource fields", mutate: func(plan *domain.Plan) { plan.Resources[0].Fingerprint = "" }},
		{name: "duplicate resource", mutate: func(plan *domain.Plan) { plan.Resources = append(plan.Resources, plan.Resources[0]) }},
		{name: "precondition id", mutate: func(plan *domain.Plan) { plan.Preconditions[0].ID = "" }},
		{name: "duplicate precondition", mutate: func(plan *domain.Plan) {
			plan.Preconditions = append(plan.Preconditions, plan.Preconditions[0])
		}},
		{name: "missing permissions", mutate: func(plan *domain.Plan) { plan.Permissions = nil }},
		{name: "permission identity", mutate: func(plan *domain.Plan) { plan.Permissions[0].Identity = "root" }},
		{name: "permission name", mutate: func(plan *domain.Plan) { plan.Permissions[0].Permission = "instances.stop" }},
		{name: "duplicate permission", mutate: func(plan *domain.Plan) {
			plan.Permissions = append(plan.Permissions, plan.Permissions[0])
		}},
		{name: "missing steps", mutate: func(plan *domain.Plan) { plan.Steps = nil }},
		{name: "step id", mutate: func(plan *domain.Plan) { plan.Steps[0].ID = "" }},
		{name: "duplicate step", mutate: func(plan *domain.Plan) { plan.Steps = append(plan.Steps, plan.Steps[0]) }},
		{name: "step executor", mutate: func(plan *domain.Plan) { plan.Steps[0].Executor = "" }},
		{name: "step identity", mutate: func(plan *domain.Plan) { plan.Steps[0].ExecutingIdentity = "root" }},
		{name: "empty command", mutate: func(plan *domain.Plan) { plan.Steps[0].CommandRedacted = redact.Sanitize("") }},
		{name: "zero retry attempts", mutate: func(plan *domain.Plan) { plan.Steps[0].Retry.MaxAttempts = 0 }},
		{name: "unbounded retry attempts", mutate: func(plan *domain.Plan) { plan.Steps[0].Retry.MaxAttempts = domain.MaxStepAttempts + 1 }},
		{name: "zero retry backoff", mutate: func(plan *domain.Plan) { plan.Steps[0].Retry.InitialBackoffSeconds = 0 }},
		{name: "inverted retry backoff", mutate: func(plan *domain.Plan) { plan.Steps[0].Retry.MaxBackoffSeconds = 1 }},
		{name: "zero step timeout", mutate: func(plan *domain.Plan) { plan.Steps[0].TimeoutSeconds = 0 }},
		{name: "unbounded step timeout", mutate: func(plan *domain.Plan) { plan.Steps[0].TimeoutSeconds = domain.MaxStepTimeoutSeconds + 1 }},
		{name: "missing success condition", mutate: func(plan *domain.Plan) { plan.Steps[0].SuccessCondition = redact.Sanitize("") }},
		{name: "failure behavior", mutate: func(plan *domain.Plan) { plan.Steps[0].FailureBehavior = "continue" }},
		{name: "point of no return", mutate: func(plan *domain.Plan) { plan.PointOfNoReturn = "missing-step" }},
		{name: "run rate amount", mutate: func(plan *domain.Plan) { plan.Cost.RunRate.AmountUSD = math.NaN() }},
		{name: "run rate period", mutate: func(plan *domain.Plan) { plan.Cost.RunRate.Period = "" }},
		{name: "cost item fields", mutate: func(plan *domain.Plan) { plan.Cost.Items[0].Kind = "" }},
		{name: "cost item amount", mutate: func(plan *domain.Plan) { plan.Cost.Items[0].AmountUSD = -1 }},
		{name: "incremental amount", mutate: func(plan *domain.Plan) { plan.Cost.Incremental.AmountUSD = math.Inf(1) }},
		{name: "incremental fields", mutate: func(plan *domain.Plan) { plan.Cost.Incremental.Plan = "" }},
		{name: "cost source", mutate: func(plan *domain.Plan) { plan.Cost.Source = "spreadsheet" }},
		{name: "price table format", mutate: func(plan *domain.Plan) { plan.Cost.PriceTableDate = "03-09-2026" }},
		{name: "price table date", mutate: func(plan *domain.Plan) { plan.Cost.PriceTableDate = "2026-02-30" }},
		{name: "budget state", mutate: func(plan *domain.Plan) { plan.Cost.Budget.State = "unknown" }},
		{name: "budget ceiling", mutate: func(plan *domain.Plan) {
			value := -1.0
			plan.Cost.Budget.CeilingUSD = &value
		}},
		{name: "downtime", mutate: func(plan *domain.Plan) { plan.Downtime.ExpectedSeconds = -1 }},
		{name: "downtime kind", mutate: func(plan *domain.Plan) { plan.Downtime.Kind = "" }},
		{name: "exposure", mutate: func(plan *domain.Plan) { plan.Exposure = "internet" }},
		{name: "protection", mutate: func(plan *domain.Plan) { plan.Protection = nil }},
		{name: "rollback boundary", mutate: func(plan *domain.Plan) { plan.Rollback.Boundary = "" }},
		{name: "verification", mutate: func(plan *domain.Plan) { plan.Verification = nil }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			plan := validPlan()
			test.mutate(&plan)
			if err := policy.ValidatePlan(plan); !errors.Is(err, policy.ErrInvalidPlan) {
				t.Fatalf("ValidatePlan() error = %v, want ErrInvalidPlan", err)
			}
			if _, err := policy.EncodePlan(plan); !errors.Is(err, policy.ErrInvalidPlan) {
				t.Fatalf("EncodePlan() error = %v, want ErrInvalidPlan", err)
			}
			_, err := policy.SealPlan(plan)
			if test.name == "plan hash" {
				if err != nil {
					t.Fatalf("SealPlan() should replace an invalid prior hash: %v", err)
				}
			} else if !errors.Is(err, policy.ErrInvalidPlan) {
				t.Fatalf("SealPlan() error = %v, want ErrInvalidPlan", err)
			}
		})
	}
}

func TestPlanExpiryGate(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	before := plan.ExpiresAt.Add(-time.Nanosecond)
	if err := policy.ValidatePlanAt(plan, before); err != nil {
		t.Fatalf("ValidatePlanAt() before expiry returned an error: %v", err)
	}

	for _, now := range []time.Time{plan.ExpiresAt, plan.ExpiresAt.Add(time.Second)} {
		if err := policy.ValidatePlanAt(plan, now); !errors.Is(err, policy.ErrExpiredPlan) {
			t.Errorf("ValidatePlanAt(%s) error = %v, want ErrExpiredPlan", now, err)
		}
	}

	if err := policy.ValidatePlanAt(plan, time.Time{}); !errors.Is(err, policy.ErrInvalidPlan) {
		t.Fatalf("ValidatePlanAt() zero clock error = %v, want ErrInvalidPlan", err)
	}
}

func TestPlanValiditySetsCreationAndExpiry_TEST_U_PLAN_02(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	createdAt := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	sealed, err := policy.SealPlanAt(plan, createdAt, 45*time.Minute)
	if err != nil {
		t.Fatalf("SealPlanAt() returned an error: %v", err)
	}
	if sealed.CreatedAt != createdAt || sealed.ExpiresAt != createdAt.Add(45*time.Minute) {
		t.Fatalf("SealPlanAt() boundaries = (%s, %s)", sealed.CreatedAt, sealed.ExpiresAt)
	}
	if err := policy.VerifyPlanHash(sealed); err != nil {
		t.Fatalf("VerifyPlanHash() returned an error: %v", err)
	}

	for _, validity := range []time.Duration{0, -time.Second} {
		if _, err := policy.SealPlanAt(plan, createdAt, validity); !errors.Is(err, policy.ErrInvalidPlan) {
			t.Errorf("SealPlanAt(validity=%s) error = %v, want ErrInvalidPlan", validity, err)
		}
	}
}

func TestPlanAllowsScheduledDestructiveStepUp(t *testing.T) {
	t.Parallel()

	plan := validPlan()
	plan.ApprovalClass = domain.ApprovalDataDestructive
	plan.CoolingOffSeconds = 600
	plan.StepUpRequired = true
	plan.Intent = &domain.PlanIntent{
		WindowStart: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC),
		ValidUntil:  time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
	}
	plan, err := policy.SealPlan(plan)
	if err != nil {
		t.Fatalf("SealPlan() returned an error: %v", err)
	}

	if err := policy.ValidatePlan(plan); err != nil {
		t.Fatalf("ValidatePlan() returned an error: %v", err)
	}
}

func validPlan() domain.Plan {
	ceiling := 200.0

	plan := domain.Plan{
		PlanID:            "plan-0123456789abcdef",
		WorkflowID:        "WF-VM-02",
		Environment:       "production",
		Principal:         "operator@example.com",
		CreatedAt:         time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC),
		ApprovalClass:     domain.ApprovalProtected,
		ExpiresAt:         time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC),
		CoolingOffSeconds: 0,
		Identity:          domain.DefaultIdentityPlan(),
		PolicyHash: domain.PlanPolicyHash{
			Local:    strings.Repeat("b", 64),
			Approved: strings.Repeat("b", 64),
			Match:    true,
		},
		Resources: []domain.PlanResource{
			{Kind: "instance", Name: "example-instance", Fingerprint: "generation-7"},
		},
		Preconditions: []domain.PlanPrecondition{
			{ID: "instance-healthy", OK: true, Detail: redact.Sanitize("healthy")},
		},
		Permissions: []domain.PlanPermission{
			{Identity: domain.IdentityOperator, Permission: "compute.instances.stop", Granted: true},
		},
		Steps: []domain.PlanStep{
			{
				ID:                "stop-instance",
				Executor:          "gcloud",
				ExecutingIdentity: domain.IdentityOperator,
				CommandRedacted:   redact.Sanitize("gcloud compute instances stop example"),
				Idempotent:        true,
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
		Cost: domain.PlanCost{
			RunRate: domain.PlanCostRate{AmountUSD: 30, Period: "month"},
			Items: []domain.PlanCostItem{
				{Resource: "example-instance", Kind: "compute", AmountUSD: 30},
			},
			Incremental:    &domain.PlanCostIncremental{AmountUSD: 5, Period: "month", Plan: "resize"},
			Source:         domain.CostSourceListPriceTable,
			PriceTableDate: "2026-09-03",
			Assumptions:    []redact.Text{redact.Sanitize("on-demand list price")},
			Unpriced:       []string{},
			Budget: domain.PlanCostBudget{
				State:      domain.BudgetOK,
				CeilingUSD: &ceiling,
			},
		},
		Downtime: domain.PlanDowntime{ExpectedSeconds: 30, Kind: "write-pause"},
		Exposure: domain.ExposureNone,
		Protection: []redact.Text{
			redact.Sanitize("fresh recovery point"),
		},
		Rollback: domain.PlanRollback{
			Boundary: "before-old-instance-delete",
			Assets:   []string{"example-instance"},
		},
		PointOfNoReturn: "stop-instance",
		Verification: []redact.Text{
			redact.Sanitize("independent instance and database health check"),
		},
	}

	sealed, err := policy.SealPlan(plan)
	if err != nil {
		panic(err)
	}

	return sealed
}

func removeJSONField(t *testing.T, encoded []byte, field string) []byte {
	t.Helper()

	needle := []byte(`"` + field + `":`)
	start := bytes.Index(encoded, needle)
	if start < 0 {
		t.Fatalf("encoded plan omitted %q", field)
	}
	end := start + len(needle)
	depth := 0
	inString := false
	for end < len(encoded) {
		character := encoded[end]
		if character == '"' && (end == 0 || encoded[end-1] != '\\') {
			inString = !inString
		}
		if !inString {
			switch character {
			case '{', '[':
				depth++
			case '}', ']':
				if depth == 0 {
					goto found
				}
				depth--
			case ',':
				if depth == 0 {
					end++
					goto found
				}
			}
		}
		end++
	}

found:
	if end <= len(encoded) && start > 0 && end < len(encoded) && encoded[end] == '}' && encoded[start-1] == ',' {
		start--
	}

	return append(append([]byte(nil), encoded[:start]...), encoded[end:]...)
}
