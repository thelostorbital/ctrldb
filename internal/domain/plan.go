// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/thelostorbital/ctrldb/internal/redact"
)

var ErrInvalidExecutionContract = errors.New("invalid execution contract")

var (
	executionWorkflowIDPattern = regexp.MustCompile(`^WF-[A-Z0-9]+-[0-9]{2}$`)
	executionIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	executionPermissionPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*){2,}$`)
)

// Plan is the immutable review artifact produced before a workflow executes.
// Validation and serialization are owned by internal/policy.
type Plan struct {
	PlanID                 string                 `json:"planId"`
	PlanHash               string                 `json:"planHash"`
	WorkflowID             string                 `json:"workflowId"`
	ProjectID              string                 `json:"projectId"`
	Environment            string                 `json:"environment"`
	EnvironmentClass       EnvironmentClass       `json:"environmentClass"`
	Principal              string                 `json:"principal"`
	CreatedAt              time.Time              `json:"createdAt"`
	ApprovalClass          ApprovalClass          `json:"approvalClass"`
	ExpiresAt              time.Time              `json:"expiresAt"`
	CoolingOffSeconds      int64                  `json:"coolingOffSeconds"`
	Identity               IdentityPlan           `json:"identity"`
	PolicyHash             PlanPolicyHash         `json:"policyHash"`
	StepUpRequired         bool                   `json:"stepUpRequired"`
	Intent                 *PlanIntent            `json:"intent,omitempty"`
	Resources              []PlanResource         `json:"resources"`
	Preconditions          []PlanPrecondition     `json:"preconditions"`
	Permissions            []PlanPermission       `json:"permissions"`
	Steps                  []PlanStep             `json:"steps"`
	Cost                   PlanCost               `json:"cost"`
	Downtime               PlanDowntime           `json:"downtime"`
	Exposure               ExposureDelta          `json:"exposure"`
	ExposureControls       *PlanExposureControls  `json:"exposureControls,omitempty"`
	Protection             []redact.Text          `json:"protection"`
	Rollback               PlanRollback           `json:"rollback"`
	PointOfNoReturn        string                 `json:"pointOfNoReturn,omitempty"`
	PointOfNoReturnTrigger PointOfNoReturnTrigger `json:"pointOfNoReturnTrigger,omitempty"`
	Verification           []redact.Text          `json:"verification"`
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
	Scope       string `json:"scope"`
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
	Retry             RetryPolicy       `json:"retry"`
	CancelSafe        bool              `json:"cancelSafe"`
	TimeoutSeconds    int64             `json:"timeoutSeconds"`
	SuccessCondition  redact.Text       `json:"successCondition"`
	FailureBehavior   FailureBehavior   `json:"failureBehavior"`
	Targets           []PlanResource    `json:"targets"`
}

// StepEffect distinguishes read-only work from a mutation-capable step.
type StepEffect string

const (
	StepEffectRead     StepEffect = "read"
	StepEffectMutation StepEffect = "mutation"
)

// Valid reports whether effect is part of the closed execution contract.
func (effect StepEffect) Valid() bool {
	return effect == StepEffectRead || effect == StepEffectMutation
}

// PointOfNoReturnTrigger defines the exact event that crosses an irreversible
// step boundary.
type PointOfNoReturnTrigger string

const (
	PointOfNoReturnStepStart        PointOfNoReturnTrigger = "step-start"
	PointOfNoReturnMutationObserved PointOfNoReturnTrigger = "mutation-observed"
	PointOfNoReturnStepComplete     PointOfNoReturnTrigger = "step-complete"
)

// Valid reports whether trigger is part of the closed execution contract.
func (trigger PointOfNoReturnTrigger) Valid() bool {
	return trigger == PointOfNoReturnStepStart || trigger == PointOfNoReturnMutationObserved ||
		trigger == PointOfNoReturnStepComplete
}

// ExecutionStepContract is the resource-independent trusted definition of one
// implemented step. Runtime plans bind it to concrete Targets separately.
type ExecutionStepContract struct {
	ID                    string
	Executor              string
	ExecutingIdentity     ExecutionIdentity
	Effect                StepEffect
	MinimumApproval       ApprovalClass
	TargetKinds           []string
	RequiredPermissions   []string
	RequiresStepUp        bool
	RequiresRecoveryAsset bool
	Idempotent            bool
	Retry                 RetryPolicy
	CancelSafe            bool
	TimeoutSeconds        int64
	SuccessCondition      redact.Text
	FailureBehavior       FailureBehavior
}

// ExecutionContract is immutable after construction; slice-bearing fields are
// defensively copied both into and out of the value.
type ExecutionContract struct {
	workflowID             string
	rollbackBoundary       string
	pointOfNoReturn        string
	pointOfNoReturnTrigger PointOfNoReturnTrigger
	steps                  []ExecutionStepContract
	digest                 string
}

// NewExecutionContract constructs a closed resource-independent contract.
func NewExecutionContract(
	workflowID, rollbackBoundary, pointOfNoReturn string,
	pointOfNoReturnTrigger PointOfNoReturnTrigger,
	steps []ExecutionStepContract,
) (ExecutionContract, error) {
	if !executionWorkflowIDPattern.MatchString(workflowID) ||
		!executionIdentifierPattern.MatchString(rollbackBoundary) || len(steps) == 0 {
		return ExecutionContract{}, fmt.Errorf("%w: invalid workflow, rollback boundary, or steps", ErrInvalidExecutionContract)
	}
	seen := make(map[string]struct{}, len(steps))
	cloned := make([]ExecutionStepContract, len(steps))
	rollbackRequired := false
	for index, step := range steps {
		if !executionIdentifierPattern.MatchString(step.ID) || !executionIdentifierPattern.MatchString(step.Executor) ||
			!step.ExecutingIdentity.Valid() || !step.Effect.Valid() || !step.MinimumApproval.Valid() ||
			!step.Retry.Valid() || step.TimeoutSeconds <= 0 || step.TimeoutSeconds > MaxStepTimeoutSeconds ||
			step.SuccessCondition.String() == "" || !step.FailureBehavior.Valid() {
			return ExecutionContract{}, fmt.Errorf("%w: invalid step %d", ErrInvalidExecutionContract, index)
		}
		if step.Effect == StepEffectMutation && step.MinimumApproval == ApprovalRead {
			return ExecutionContract{}, fmt.Errorf("%w: mutation step has read approval", ErrInvalidExecutionContract)
		}
		if step.RequiresStepUp && (step.Effect != StepEffectMutation || step.MinimumApproval < ApprovalDestructive) {
			return ExecutionContract{}, fmt.Errorf("%w: step-up requires an AP-4 or stronger mutation step", ErrInvalidExecutionContract)
		}
		if step.RequiresRecoveryAsset && (step.Effect != StepEffectMutation || step.MinimumApproval < ApprovalDestructive) {
			return ExecutionContract{}, fmt.Errorf(
				"%w: recovery assets require an AP-4 or stronger mutation step", ErrInvalidExecutionContract,
			)
		}
		if step.Effect == StepEffectMutation && step.MinimumApproval == ApprovalDataDestructive &&
			!step.RequiresRecoveryAsset {
			return ExecutionContract{}, fmt.Errorf("%w: AP-5 mutation step requires recovery assets", ErrInvalidExecutionContract)
		}
		if _, duplicate := seen[step.ID]; duplicate {
			return ExecutionContract{}, fmt.Errorf("%w: duplicate step", ErrInvalidExecutionContract)
		}
		seen[step.ID] = struct{}{}
		rollbackRequired = rollbackRequired || step.Effect == StepEffectMutation || step.FailureBehavior == FailureRollback
		if err := validateContractStrings(step.TargetKinds, executionIdentifierPattern); err != nil {
			return ExecutionContract{}, fmt.Errorf("%w: invalid target kinds", ErrInvalidExecutionContract)
		}
		if err := validateContractStrings(step.RequiredPermissions, executionPermissionPattern); err != nil {
			return ExecutionContract{}, fmt.Errorf("%w: invalid required permissions", ErrInvalidExecutionContract)
		}
		cloned[index] = cloneExecutionStepContract(step)
	}
	if pointOfNoReturn != "" {
		if !executionIdentifierPattern.MatchString(pointOfNoReturn) {
			return ExecutionContract{}, fmt.Errorf("%w: invalid point of no return", ErrInvalidExecutionContract)
		}
		if _, exists := seen[pointOfNoReturn]; !exists {
			return ExecutionContract{}, fmt.Errorf("%w: point of no return is not a step", ErrInvalidExecutionContract)
		}
		if !pointOfNoReturnTrigger.Valid() {
			return ExecutionContract{}, fmt.Errorf("%w: invalid point-of-no-return trigger", ErrInvalidExecutionContract)
		}
	} else if pointOfNoReturnTrigger != "" {
		return ExecutionContract{}, fmt.Errorf("%w: trigger without point of no return", ErrInvalidExecutionContract)
	}
	if rollbackRequired && rollbackBoundary == "none" {
		return ExecutionContract{}, fmt.Errorf("%w: mutation or rollback step requires a rollback boundary", ErrInvalidExecutionContract)
	}

	contract := ExecutionContract{
		workflowID: workflowID, rollbackBoundary: rollbackBoundary, pointOfNoReturn: pointOfNoReturn,
		pointOfNoReturnTrigger: pointOfNoReturnTrigger, steps: cloned,
	}
	encoded, err := json.Marshal(struct {
		WorkflowID             string                  `json:"workflowId"`
		RollbackBoundary       string                  `json:"rollbackBoundary"`
		PointOfNoReturn        string                  `json:"pointOfNoReturn"`
		PointOfNoReturnTrigger PointOfNoReturnTrigger  `json:"pointOfNoReturnTrigger"`
		Steps                  []ExecutionStepContract `json:"steps"`
	}{workflowID, rollbackBoundary, pointOfNoReturn, pointOfNoReturnTrigger, cloned})
	if err != nil {
		return ExecutionContract{}, fmt.Errorf("%w: digest encoding", ErrInvalidExecutionContract)
	}
	contract.digest = fmt.Sprintf("%x", sha256.Sum256(encoded))

	return contract, nil
}

// WorkflowID returns the immutable workflow binding.
func (contract ExecutionContract) WorkflowID() string { return contract.workflowID }

// RollbackBoundary returns the immutable reviewed rollback boundary.
func (contract ExecutionContract) RollbackBoundary() string { return contract.rollbackBoundary }

// PointOfNoReturn returns the exact optional step after which rollback is no
// longer promised.
func (contract ExecutionContract) PointOfNoReturn() string { return contract.pointOfNoReturn }

// PointOfNoReturnTrigger returns the immutable event that crosses the
// irreversible boundary.
func (contract ExecutionContract) PointOfNoReturnTrigger() PointOfNoReturnTrigger {
	return contract.pointOfNoReturnTrigger
}

// Digest returns the immutable hash bound into durable cancellation records.
func (contract ExecutionContract) Digest() string { return contract.digest }

// Steps returns a detached copy of the trusted step contracts.
func (contract ExecutionContract) Steps() []ExecutionStepContract {
	steps := make([]ExecutionStepContract, len(contract.steps))
	for index, step := range contract.steps {
		steps[index] = cloneExecutionStepContract(step)
	}

	return steps
}

func cloneExecutionStepContract(step ExecutionStepContract) ExecutionStepContract {
	step.TargetKinds = append([]string(nil), step.TargetKinds...)
	step.RequiredPermissions = append([]string(nil), step.RequiredPermissions...)

	return step
}

func validateContractStrings(values []string, pattern *regexp.Regexp) error {
	if len(values) == 0 {
		return ErrInvalidExecutionContract
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !pattern.MatchString(value) {
			return ErrInvalidExecutionContract
		}
		if _, duplicate := seen[value]; duplicate {
			return ErrInvalidExecutionContract
		}
		seen[value] = struct{}{}
	}

	return nil
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

// RecoveryAssetKind identifies the two independently verifiable recovery
// mechanisms approved for destructive plans.
type RecoveryAssetKind string

const (
	RecoveryAssetPBMRecoveryPoint RecoveryAssetKind = "pbm-recovery-point"
	RecoveryAssetSnapshot         RecoveryAssetKind = "snapshot"
)

// Valid reports whether kind is part of the closed recovery contract.
func (kind RecoveryAssetKind) Valid() bool {
	return kind == RecoveryAssetPBMRecoveryPoint || kind == RecoveryAssetSnapshot
}

// PlanRecoveryAsset binds recovery proof to one exact provider resource.
type PlanRecoveryAsset struct {
	Kind        RecoveryAssetKind `json:"kind"`
	Resource    PlanResource      `json:"resource"`
	EvidenceRef string            `json:"evidenceRef"`
	VerifiedAt  time.Time         `json:"verifiedAt"`
	RestoreTo   *time.Time        `json:"restoreTo,omitempty"`
}

// ExposureProfile is the approved access workflow profile that owns a change.
type ExposureProfile string

const (
	ExposureProfileACC01 ExposureProfile = "ACC-01"
	ExposureProfileACC02 ExposureProfile = "ACC-02"
	ExposureProfileACC03 ExposureProfile = "ACC-03"
	ExposureProfileACC04 ExposureProfile = "ACC-04"
	ExposureProfileACC05 ExposureProfile = "ACC-05"
	ExposureProfileACC06 ExposureProfile = "ACC-06"
	ExposureProfileACC07 ExposureProfile = "ACC-07"
	ExposureProfileACC08 ExposureProfile = "ACC-08"
)

// Valid reports whether profile is in the closed access-profile registry.
func (profile ExposureProfile) Valid() bool {
	switch profile {
	case ExposureProfileACC01, ExposureProfileACC02, ExposureProfileACC03, ExposureProfileACC04,
		ExposureProfileACC05, ExposureProfileACC06, ExposureProfileACC07, ExposureProfileACC08:
		return true
	default:
		return false
	}
}

// ExposureSourceKind identifies one enforceable network source selector.
type ExposureSourceKind string

const (
	ExposureSourceCIDR           ExposureSourceKind = "cidr"
	ExposureSourceTag            ExposureSourceKind = "tag"
	ExposureSourceServiceAccount ExposureSourceKind = "service-account"
	ExposureSourceIAP            ExposureSourceKind = "iap"
	ExposureSourceTunnel         ExposureSourceKind = "tunnel"
	ExposureSourcePrivateRange   ExposureSourceKind = "private-range"
)

// Valid reports whether kind is in the closed selector registry.
func (kind ExposureSourceKind) Valid() bool {
	switch kind {
	case ExposureSourceCIDR, ExposureSourceTag, ExposureSourceServiceAccount,
		ExposureSourceIAP, ExposureSourceTunnel, ExposureSourcePrivateRange:
		return true
	default:
		return false
	}
}

// ExposureAuthentication identifies the approved authentication boundary.
type ExposureAuthentication string

const (
	ExposureAuthIAP     ExposureAuthentication = "iap-os-login"
	ExposureAuthSCRAM   ExposureAuthentication = "scram-sha-256"
	ExposureAuthVPN     ExposureAuthentication = "vpn"
	ExposureAuthOverlay ExposureAuthentication = "overlay"
)

// Valid reports whether authentication is part of the closed access contract.
func (authentication ExposureAuthentication) Valid() bool {
	return authentication == ExposureAuthIAP || authentication == ExposureAuthSCRAM ||
		authentication == ExposureAuthVPN || authentication == ExposureAuthOverlay
}

// ExposureTrust identifies the trust anchor required by an access path.
type ExposureTrust string

const (
	ExposureTrustNone    ExposureTrust = "none"
	ExposureTrustPrivate ExposureTrust = "private"
	ExposureTrustPublic  ExposureTrust = "public"
)

// Valid reports whether trust is part of the closed TLS contract.
func (trust ExposureTrust) Valid() bool {
	return trust == ExposureTrustNone || trust == ExposureTrustPrivate || trust == ExposureTrustPublic
}

// PlanExposureSource is one typed, canonical reachability selector.
type PlanExposureSource struct {
	Kind  ExposureSourceKind `json:"kind"`
	Value string             `json:"value"`
}

// PlanExposurePort is one exact protocol and destination port.
type PlanExposurePort struct {
	Protocol string `json:"protocol"`
	Number   uint16 `json:"number"`
}

// PlanExposureTLS records enforceable transport-security requirements.
type PlanExposureTLS struct {
	Required             bool          `json:"required"`
	HostnameVerification bool          `json:"hostnameVerification"`
	Trust                ExposureTrust `json:"trust"`
}

// PlanExposureControls binds an exposure delta to the access contract that
// scopes, expires, audits, and revokes it.
type PlanExposureControls struct {
	Profile                           ExposureProfile        `json:"profile"`
	Targets                           []PlanResource         `json:"targets"`
	Sources                           []PlanExposureSource   `json:"sources"`
	Ports                             []PlanExposurePort     `json:"ports"`
	Authentication                    ExposureAuthentication `json:"authentication"`
	TLS                               PlanExposureTLS        `json:"tls"`
	ExpiresAt                         *time.Time             `json:"expiresAt,omitempty"`
	ReviewAt                          *time.Time             `json:"reviewAt,omitempty"`
	AuditLogging                      bool                   `json:"auditLogging"`
	RevocationWorkflowID              string                 `json:"revocationWorkflowId"`
	SimulationPreconditionID          string                 `json:"simulationPreconditionId"`
	InternetWide                      bool                   `json:"internetWide"`
	PermanentInternetWideAcknowledged bool                   `json:"permanentInternetWideAcknowledged"`
}

// PlanDowntime makes the expected availability impact explicit.
type PlanDowntime struct {
	ExpectedSeconds int64  `json:"expectedSeconds"`
	Kind            string `json:"kind"`
}

// PlanRollback describes the rollback boundary and retained assets.
type PlanRollback struct {
	Boundary string              `json:"boundary"`
	Assets   []PlanRecoveryAsset `json:"assets"`
}
