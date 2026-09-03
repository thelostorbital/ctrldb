// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"time"

	"github.com/thelostorbital/ctrldb/internal/redact"
)

// Plan is the immutable review artifact produced before a workflow executes.
// Validation and serialization are owned by internal/policy.
type Plan struct {
	PlanID            string             `json:"planId"`
	PlanHash          string             `json:"planHash"`
	WorkflowID        string             `json:"workflowId"`
	ApprovalClass     ApprovalClass      `json:"approvalClass"`
	ExpiresAt         time.Time          `json:"expiresAt"`
	CoolingOffSeconds int64              `json:"coolingOffSeconds"`
	Identity          IdentityPlan       `json:"identity"`
	PolicyHash        PlanPolicyHash     `json:"policyHash"`
	StepUpRequired    bool               `json:"stepUpRequired"`
	Intent            *PlanIntent        `json:"intent,omitempty"`
	Resources         []PlanResource     `json:"resources"`
	Preconditions     []PlanPrecondition `json:"preconditions"`
	Steps             []PlanStep         `json:"steps"`
	Cost              PlanCost           `json:"cost"`
	Downtime          PlanDowntime       `json:"downtime"`
	Exposure          ExposureDelta      `json:"exposure"`
	Protection        []redact.Text      `json:"protection"`
	Rollback          PlanRollback       `json:"rollback"`
	PointOfNoReturn   string             `json:"pointOfNoReturn,omitempty"`
	Verification      []redact.Text      `json:"verification"`
}

// IdentityPlan records the default and privileged step identity routes.
type IdentityPlan struct {
	Default          ExecutionIdentity `json:"default"`
	HostControlSteps ExecutionIdentity `json:"hostControlSteps"`
	DeleteSteps      ExecutionIdentity `json:"deleteSteps"`
	BootstrapSteps   ExecutionIdentity `json:"bootstrapSteps"`
}

// DefaultIdentityPlan returns the mandatory production identity routing.
func DefaultIdentityPlan() IdentityPlan {
	return IdentityPlan{
		Default:          IdentityOperator,
		HostControlSteps: IdentityProvisioner,
		DeleteSteps:      IdentityDestructive,
		BootstrapSteps:   IdentityHuman,
	}
}

// PlanPolicyHash binds a plan to its local and approved policy versions.
type PlanPolicyHash struct {
	Local    string `json:"local,omitempty"`
	Approved string `json:"approved,omitempty"`
	Match    bool   `json:"match"`
}

// PlanIntent describes an optional scheduled execution window.
type PlanIntent struct {
	ValidUntil  time.Time `json:"validUntil"`
	WindowStart time.Time `json:"windowStart"`
}

// PlanResource is a fingerprinted resource affected by a plan.
type PlanResource struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

// PlanPrecondition is a discovery-backed condition reviewed with a plan.
type PlanPrecondition struct {
	ID     string      `json:"id"`
	OK     bool        `json:"ok"`
	Detail redact.Text `json:"detail"`
}

// PlanStep is one typed, bounded unit of execution.
type PlanStep struct {
	ID                string            `json:"id"`
	Executor          string            `json:"executor"`
	ExecutingIdentity ExecutionIdentity `json:"executingIdentity"`
	CommandRedacted   redact.Text       `json:"commandRedacted"`
	Idempotent        bool              `json:"idempotent"`
	CancelSafe        bool              `json:"cancelSafe"`
	TimeoutSeconds    int64             `json:"timeoutSeconds"`
}

// CostSource identifies the data source behind a plan estimate.
type CostSource string

const (
	CostSourceListPriceTable CostSource = "list-price-table"
	CostSourceBudgetAPI      CostSource = "budget-api"
)

// Valid reports whether source is a supported cost source.
func (source CostSource) Valid() bool {
	return source == CostSourceListPriceTable || source == CostSourceBudgetAPI
}

// BudgetState describes whether a cost ceiling can be evaluated.
type BudgetState string

const (
	BudgetOK          BudgetState = "ok"
	BudgetMissing     BudgetState = "missing"
	BudgetUnavailable BudgetState = "unavailable"
)

// Valid reports whether state is a supported budget state.
func (state BudgetState) Valid() bool {
	return state == BudgetOK || state == BudgetMissing || state == BudgetUnavailable
}

// PlanCost contains the reviewable cost subset embedded in a plan.
type PlanCost struct {
	RunRate        PlanCostRate         `json:"runRate"`
	Items          []PlanCostItem       `json:"items"`
	Incremental    *PlanCostIncremental `json:"incremental,omitempty"`
	Source         CostSource           `json:"source"`
	PriceTableDate string               `json:"priceTableDate"`
	Stale          bool                 `json:"stale"`
	Assumptions    []redact.Text        `json:"assumptions"`
	Unpriced       []string             `json:"unpriced"`
	Budget         PlanCostBudget       `json:"budget"`
}

// PlanCostRate is a recurring amount over a named period.
type PlanCostRate struct {
	AmountUSD float64 `json:"amountUSD"`
	Period    string  `json:"period"`
}

// PlanCostItem is one resource contributing to the run rate.
type PlanCostItem struct {
	Resource  string  `json:"resource"`
	Kind      string  `json:"kind"`
	AmountUSD float64 `json:"amountUSD"`
}

// PlanCostIncremental describes the plan's additional cost.
type PlanCostIncremental struct {
	AmountUSD float64 `json:"amountUSD"`
	Period    string  `json:"period"`
	Plan      string  `json:"plan"`
}

// PlanCostBudget contains the cost-ceiling signal used at planning time.
type PlanCostBudget struct {
	State      BudgetState `json:"state"`
	Reason     redact.Text `json:"reason,omitempty"`
	CeilingUSD *float64    `json:"ceilingUSD,omitempty"`
}

// PlanDowntime makes the expected availability impact explicit.
type PlanDowntime struct {
	ExpectedSeconds int64  `json:"expectedSeconds"`
	Kind            string `json:"kind"`
}

// PlanRollback describes the rollback boundary and retained assets.
type PlanRollback struct {
	Boundary string   `json:"boundary"`
	Assets   []string `json:"assets"`
}
