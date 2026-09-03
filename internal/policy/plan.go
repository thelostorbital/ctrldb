// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package policy validates plans and applies safety policy without performing I/O.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

var (
	// ErrInvalidPlan is returned when a plan violates its closed schema or
	// safety invariants.
	ErrInvalidPlan = errors.New("invalid plan")

	// ErrExpiredPlan is returned when a structurally valid plan has reached its
	// immutable expiry boundary.
	ErrExpiredPlan = errors.New("expired plan")
)

var (
	planIDPattern     = regexp.MustCompile(`^plan-[0-9a-f]{16}$`)
	planHashPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	workflowIDPattern = regexp.MustCompile(`^WF-[A-Z0-9]+-[0-9]{2}$`)
	datePattern       = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// EncodePlan validates plan and serializes it as compact JSON.
func EncodePlan(plan domain.Plan) ([]byte, error) {
	if err := ValidatePlan(plan); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidPlan, err)
	}

	return encoded, nil
}

// DecodePlan rejects unknown fields and trailing values, then validates the
// complete plan before returning it.
func DecodePlan(encoded []byte) (domain.Plan, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	var plan domain.Plan
	if err := decoder.Decode(&plan); err != nil {
		return domain.Plan{}, fmt.Errorf("%w: decode: %v", ErrInvalidPlan, err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return domain.Plan{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidPlan)
	}

	if err := ValidatePlan(plan); err != nil {
		return domain.Plan{}, err
	}

	return plan, nil
}

// ValidatePlan checks the resource-independent PlanV1 invariants.
func ValidatePlan(plan domain.Plan) error {
	if !planIDPattern.MatchString(plan.PlanID) {
		return invalid("planId", "must match plan-<16 lowercase hex>")
	}
	if !planHashPattern.MatchString(plan.PlanHash) {
		return invalid("planHash", "must be 64 lowercase hex characters")
	}
	if !workflowIDPattern.MatchString(plan.WorkflowID) {
		return invalid("workflowId", "must match WF-<GROUP>-<NN>")
	}
	if !plan.ApprovalClass.Valid() {
		return invalid("approvalClass", "unknown value")
	}
	if err := validateUTCTime("expiresAt", plan.ExpiresAt); err != nil {
		return err
	}
	if plan.CoolingOffSeconds < 0 {
		return invalid("coolingOffSeconds", "must not be negative")
	}
	if err := validateIdentityPlan(plan.Identity); err != nil {
		return err
	}
	if err := validatePolicyHash(plan.PolicyHash); err != nil {
		return err
	}
	if plan.StepUpRequired && plan.ApprovalClass < domain.ApprovalDestructive {
		return invalid("stepUpRequired", "requires a destructive approval class")
	}
	if plan.Intent != nil {
		if err := validateIntent(*plan.Intent); err != nil {
			return err
		}
	}
	if err := validateResources(plan.Resources); err != nil {
		return err
	}
	if err := validatePreconditions(plan.Preconditions); err != nil {
		return err
	}
	if err := validateSteps(plan.Steps, plan.PointOfNoReturn); err != nil {
		return err
	}
	if err := validateCost(plan.Cost); err != nil {
		return err
	}
	if plan.Downtime.ExpectedSeconds < 0 {
		return invalid("downtime.expectedSeconds", "must not be negative")
	}
	if plan.Downtime.Kind == "" {
		return invalid("downtime.kind", "must not be empty")
	}
	if !plan.Exposure.Valid() {
		return invalid("exposure", "unknown value")
	}
	if plan.ApprovalClass >= domain.ApprovalProtected && len(plan.Protection) == 0 {
		return invalid("protection", "must describe at least one safeguard for AP-2 or stronger")
	}
	if plan.Rollback.Boundary == "" {
		return invalid("rollback.boundary", "must not be empty; use none when unavailable")
	}
	if len(plan.Verification) == 0 {
		return invalid("verification", "must contain at least one independent check")
	}

	return nil
}

// ValidatePlanAt applies structural validation and the immutable expiry gate.
func ValidatePlanAt(plan domain.Plan, now time.Time) error {
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	if now.IsZero() {
		return invalid("currentTime", "must not be zero")
	}
	if !now.Before(plan.ExpiresAt) {
		return fmt.Errorf("%w: plan %s expired at %s", ErrExpiredPlan, plan.PlanID, plan.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}

func validateIdentityPlan(identity domain.IdentityPlan) error {
	want := domain.DefaultIdentityPlan()
	if identity != want {
		return invalid(
			"identity",
			"must route default/operator, host-control/provisioner, delete/destructive, and bootstrap/human",
		)
	}

	return nil
}

func validatePolicyHash(policyHash domain.PlanPolicyHash) error {
	if policyHash.Local != "" && !planHashPattern.MatchString(policyHash.Local) {
		return invalid("policyHash.local", "must be empty or 64 lowercase hex characters")
	}
	if policyHash.Approved != "" && !planHashPattern.MatchString(policyHash.Approved) {
		return invalid("policyHash.approved", "must be empty or 64 lowercase hex characters")
	}

	matches := policyHash.Local != "" && policyHash.Local == policyHash.Approved
	if policyHash.Match != matches {
		return invalid("policyHash.match", "does not agree with local and approved hashes")
	}

	return nil
}

func validateIntent(intent domain.PlanIntent) error {
	if err := validateUTCTime("intent.windowStart", intent.WindowStart); err != nil {
		return err
	}
	if err := validateUTCTime("intent.validUntil", intent.ValidUntil); err != nil {
		return err
	}
	if !intent.ValidUntil.After(intent.WindowStart) {
		return invalid("intent.validUntil", "must be later than windowStart")
	}

	return nil
}

func validateResources(resources []domain.PlanResource) error {
	seen := make(map[string]struct{}, len(resources))
	for index, resource := range resources {
		path := fmt.Sprintf("resources[%d]", index)
		if resource.Kind == "" || resource.Name == "" || resource.Fingerprint == "" {
			return invalid(path, "kind, name, and fingerprint must not be empty")
		}

		key := resource.Kind + "\x00" + resource.Name
		if _, exists := seen[key]; exists {
			return invalid(path, "duplicate kind and name")
		}
		seen[key] = struct{}{}
	}

	return nil
}

func validatePreconditions(preconditions []domain.PlanPrecondition) error {
	seen := make(map[string]struct{}, len(preconditions))
	for index, precondition := range preconditions {
		path := fmt.Sprintf("preconditions[%d]", index)
		if precondition.ID == "" {
			return invalid(path+".id", "must not be empty")
		}
		if _, exists := seen[precondition.ID]; exists {
			return invalid(path+".id", "duplicate value")
		}
		seen[precondition.ID] = struct{}{}
	}

	return nil
}

func validateSteps(steps []domain.PlanStep, pointOfNoReturn string) error {
	if len(steps) == 0 {
		return invalid("steps", "must contain at least one step")
	}

	seen := make(map[string]struct{}, len(steps))
	for index, step := range steps {
		path := fmt.Sprintf("steps[%d]", index)
		if step.ID == "" {
			return invalid(path+".id", "must not be empty")
		}
		if _, exists := seen[step.ID]; exists {
			return invalid(path+".id", "duplicate value")
		}
		seen[step.ID] = struct{}{}

		if step.Executor == "" {
			return invalid(path+".executor", "must not be empty")
		}
		if !step.ExecutingIdentity.Valid() {
			return invalid(path+".executingIdentity", "unknown value")
		}
		if step.TimeoutSeconds < 0 {
			return invalid(path+".timeoutSeconds", "must not be negative")
		}
	}

	if pointOfNoReturn != "" {
		if _, exists := seen[pointOfNoReturn]; !exists {
			return invalid("pointOfNoReturn", "must name a step in this plan")
		}
	}

	return nil
}

func validateCost(cost domain.PlanCost) error {
	if err := validateAmount("cost.runRate.amountUSD", cost.RunRate.AmountUSD); err != nil {
		return err
	}
	if cost.RunRate.Period == "" {
		return invalid("cost.runRate.period", "must not be empty")
	}
	for index, item := range cost.Items {
		path := fmt.Sprintf("cost.items[%d]", index)
		if item.Resource == "" || item.Kind == "" {
			return invalid(path, "resource and kind must not be empty")
		}
		if err := validateAmount(path+".amountUSD", item.AmountUSD); err != nil {
			return err
		}
	}
	if cost.Incremental != nil {
		if err := validateAmount("cost.incremental.amountUSD", cost.Incremental.AmountUSD); err != nil {
			return err
		}
		if cost.Incremental.Period == "" || cost.Incremental.Plan == "" {
			return invalid("cost.incremental", "period and plan must not be empty")
		}
	}
	if !cost.Source.Valid() {
		return invalid("cost.source", "unknown value")
	}
	if !datePattern.MatchString(cost.PriceTableDate) {
		return invalid("cost.priceTableDate", "must use YYYY-MM-DD")
	}
	if _, err := time.Parse(time.DateOnly, cost.PriceTableDate); err != nil {
		return invalid("cost.priceTableDate", "must be a real calendar date")
	}
	if !cost.Budget.State.Valid() {
		return invalid("cost.budget.state", "unknown value")
	}
	if cost.Budget.CeilingUSD != nil {
		if err := validateAmount("cost.budget.ceilingUSD", *cost.Budget.CeilingUSD); err != nil {
			return err
		}
	}

	return nil
}

func validateAmount(path string, amount float64) error {
	if math.IsNaN(amount) || math.IsInf(amount, 0) || amount < 0 {
		return invalid(path, "must be a finite non-negative number")
	}

	return nil
}

func validateUTCTime(path string, value time.Time) error {
	if value.IsZero() {
		return invalid(path, "must not be zero")
	}
	_, offset := value.Zone()
	if offset != 0 {
		return invalid(path, "must be UTC")
	}

	return nil
}

func invalid(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidPlan, path, reason)
}
