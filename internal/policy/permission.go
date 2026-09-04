// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

const (
	executionEvidenceFreshness = 10 * time.Minute
	stepUpFreshness            = 10 * time.Minute
)

var (
	// ErrPlanBlocked identifies a valid review artifact whose current execution
	// evidence does not authorize mutation.
	ErrPlanBlocked = errors.New("plan blocked")
	// ErrInvalidPermissionProbe identifies ambiguous permission-probe input.
	ErrInvalidPermissionProbe = errors.New("invalid permission probe")
)

// PlanBlockerKind distinguishes independently reviewable execution blockers.
type PlanBlockerKind string

const (
	BlockerPlanBinding  PlanBlockerKind = "plan-binding"
	BlockerContract     PlanBlockerKind = "execution-contract"
	BlockerPlanTime     PlanBlockerKind = "plan-time"
	BlockerApproval     PlanBlockerKind = "approval"
	BlockerCoolingOff   PlanBlockerKind = "cooling-off"
	BlockerIntent       PlanBlockerKind = "intent"
	BlockerPolicy       PlanBlockerKind = "policy"
	BlockerPrecondition PlanBlockerKind = "precondition"
	BlockerResource     PlanBlockerKind = "resource"
	BlockerPermission   PlanBlockerKind = "permission"
	BlockerStepUp       PlanBlockerKind = "step-up"
)

// PlanBlocker names one failed safety check without carrying provider output.
type PlanBlocker struct {
	Kind     PlanBlockerKind
	ID       string
	Identity domain.ExecutionIdentity
}

// PermissionProbe is one exact testIamPermissions-style observation request.
type PermissionProbe struct {
	ProjectID string
	StepID    string
	Identity  domain.ExecutionIdentity
	Resource  domain.PlanResource
	Required  []string
	Granted   []string
}

// ApprovalEvidence is the create-only approval record read immediately before
// execution. ServerTimeCreated is the storage service timestamp, never a
// client-authored field or the plan creation time.
type ApprovalEvidence struct {
	PlanID            string
	PlanHash          string
	ProjectID         string
	Environment       string
	EnvironmentClass  domain.EnvironmentClass
	Principal         string
	RecordObject      string
	ServerTimeCreated time.Time
}

// IntentEvidence is the current authoritative view of a scheduled intent.
type IntentEvidence struct {
	PlanID           string
	PlanHash         string
	ProjectID        string
	PolicyHash       string
	Environment      string
	EnvironmentClass domain.EnvironmentClass
	Principal        string
	WindowStart      time.Time
	ValidUntil       time.Time
	Active           bool
	SoleActive       bool
}

// StepUpEvidence is the create-only fresh-login record for a destructive plan.
type StepUpEvidence struct {
	PlanID            string
	PlanHash          string
	ProjectID         string
	Environment       string
	EnvironmentClass  domain.EnvironmentClass
	Principal         string
	RecordObject      string
	ServerTimeCreated time.Time
}

// ExecutionEvidence is a typed, provider-independent revalidation snapshot.
// CheckedAt is the authoritative gate time. ObservedAt is the authoritative
// completion time of the resource, precondition, and permission revalidation
// represented by this value; the gate verifies its required ordering. The
// browser-login interval consumes the bounded revalidation freshness budget;
// executors must still enforce their per-step fingerprints and etags.
type ExecutionEvidence struct {
	PlanID           string
	PlanHash         string
	ProjectID        string
	Environment      string
	EnvironmentClass domain.EnvironmentClass
	Principal        string
	CheckedAt        time.Time
	ObservedAt       time.Time
	Approval         *ApprovalEvidence
	Intent           *IntentEvidence
	PolicyHash       domain.PlanPolicyHash
	Preconditions    []domain.PlanPrecondition
	Resources        []domain.PlanResource
	Permissions      []domain.PlanPermission
	StepUp           *StepUpEvidence
}

// BlockedPlanError is returned before any mutation for a reviewable but
// non-executable plan. ExitCode is the stable command-mode validation code.
type BlockedPlanError struct {
	planID   string
	blockers []PlanBlocker
}

// PermissionChecks converts a probe response into stable plan evidence. The
// response may contain only requested permissions; omissions become denied.
func PermissionChecks(probe PermissionProbe) ([]domain.PlanPermission, error) {
	if !projectIDPattern.MatchString(probe.ProjectID) || !identifierPattern.MatchString(probe.StepID) ||
		!probe.Identity.Valid() {
		return nil, fmt.Errorf("%w: invalid step or identity", ErrInvalidPermissionProbe)
	}
	if err := validateResources([]domain.PlanResource{probe.Resource}, probe.ProjectID); err != nil {
		return nil, fmt.Errorf("%w: incomplete fingerprinted resource", ErrInvalidPermissionProbe)
	}
	if len(probe.Required) == 0 {
		return nil, fmt.Errorf("%w: required set is empty", ErrInvalidPermissionProbe)
	}

	requiredSet := make(map[string]struct{}, len(probe.Required))
	for _, permission := range probe.Required {
		if !permissionPattern.MatchString(permission) {
			return nil, fmt.Errorf("%w: malformed required permission", ErrInvalidPermissionProbe)
		}
		if _, exists := requiredSet[permission]; exists {
			return nil, fmt.Errorf("%w: duplicate required permission", ErrInvalidPermissionProbe)
		}
		requiredSet[permission] = struct{}{}
	}

	grantedSet := make(map[string]struct{}, len(probe.Granted))
	for _, permission := range probe.Granted {
		if _, requested := requiredSet[permission]; !requested {
			return nil, fmt.Errorf("%w: response contains an unrequested permission", ErrInvalidPermissionProbe)
		}
		if _, exists := grantedSet[permission]; exists {
			return nil, fmt.Errorf("%w: duplicate granted permission", ErrInvalidPermissionProbe)
		}
		grantedSet[permission] = struct{}{}
	}

	checks := make([]domain.PlanPermission, len(probe.Required))
	for index, permission := range probe.Required {
		_, isGranted := grantedSet[permission]
		checks[index] = domain.PlanPermission{
			StepID:     probe.StepID,
			Identity:   probe.Identity,
			Permission: permission,
			Resource:   probe.Resource,
			Granted:    isGranted,
		}
	}

	return checks, nil
}

// Error implements error.
func (err *BlockedPlanError) Error() string {
	if err == nil {
		return ErrPlanBlocked.Error()
	}

	return fmt.Sprintf("%s: plan %s has %d blocker(s)", ErrPlanBlocked, err.planID, len(err.blockers))
}

// Unwrap supports errors.Is(err, ErrPlanBlocked).
func (err *BlockedPlanError) Unwrap() error { return ErrPlanBlocked }

// ExitCode is the stable command-mode exit code for a validation blocker.
func (err *BlockedPlanError) ExitCode() int { return 3 }

// PlanID returns the immutable plan identity associated with the blockers.
func (err *BlockedPlanError) PlanID() string {
	if err == nil {
		return ""
	}

	return err.planID
}

// Blockers returns a detached copy in deterministic gate order.
func (err *BlockedPlanError) Blockers() []PlanBlocker {
	if err == nil {
		return nil
	}

	result := make([]PlanBlocker, len(err.blockers))
	copy(result, err.blockers)

	return result
}

// ValidatePlanForExecution consumes only typed current evidence. It performs
// no discovery or mutation and fails closed before an executor is reachable.
func ValidatePlanForExecution(plan domain.Plan, evidence ExecutionEvidence, contract domain.ExecutionContract) error {
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	if !validEvidenceTime(evidence.CheckedAt) {
		return &BlockedPlanError{planID: plan.PlanID, blockers: []PlanBlocker{{Kind: BlockerPlanTime, ID: "checked-at"}}}
	}
	if err := ValidatePlanAt(plan, evidence.CheckedAt); err != nil {
		return err
	}

	blockers := make([]PlanBlocker, 0)
	if !validEvidenceTime(evidence.ObservedAt) || evidence.ObservedAt.After(evidence.CheckedAt) ||
		evidence.ObservedAt.Before(plan.CreatedAt) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerPlanTime, ID: "fresh-observation"})
	}
	if evidence.CheckedAt.Sub(evidence.ObservedAt) > executionEvidenceFreshness {
		blockers = append(blockers, PlanBlocker{Kind: BlockerPlanTime, ID: "stale-observation"})
	}
	if evidence.CheckedAt.Before(plan.CreatedAt) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerPlanTime, ID: "before-plan-creation"})
	}
	if evidence.PlanID != plan.PlanID || evidence.PlanHash != plan.PlanHash || evidence.ProjectID != plan.ProjectID ||
		evidence.Environment != plan.Environment || evidence.EnvironmentClass != plan.EnvironmentClass ||
		evidence.Principal != plan.Principal {
		blockers = append(blockers, PlanBlocker{Kind: BlockerPlanBinding, ID: "execution-evidence"})
	}
	var contractRequiresApproval, contractRequiresStepUp bool
	blockers, contractRequiresApproval, contractRequiresStepUp = validateExecutionContract(plan, contract, blockers)

	requireApproval := contractRequiresApproval || plan.ApprovalClass != domain.ApprovalRead || plan.Intent != nil
	if requireApproval {
		blockers = validateApprovalEvidence(plan, evidence, blockers)
	} else if evidence.Approval != nil {
		blockers = append(blockers, PlanBlocker{Kind: BlockerApproval, ID: "unexpected"})
	}
	blockers = validateIntentEvidence(plan, evidence, blockers)

	if !plan.PolicyHash.Match || evidence.PolicyHash != plan.PolicyHash || !evidence.PolicyHash.Match {
		blockers = append(blockers, PlanBlocker{Kind: BlockerPolicy, ID: "approved-policy-hash"})
	}
	blockers = validatePreconditionEvidence(plan, evidence, blockers)
	blockers = validateResourceEvidence(plan, evidence, blockers)
	blockers = validatePermissionEvidence(plan, evidence, blockers)
	wantStepUp := plan.EnvironmentClass == domain.EnvironmentProduction &&
		(plan.ApprovalClass == domain.ApprovalDataDestructive || contractRequiresStepUp)
	if plan.StepUpRequired != wantStepUp {
		blockers = append(blockers, PlanBlocker{Kind: BlockerStepUp, ID: "workflow-requirement"})
	}
	blockers = validateStepUpEvidence(plan, evidence, blockers)

	if len(blockers) != 0 {
		return &BlockedPlanError{planID: plan.PlanID, blockers: blockers}
	}

	return nil
}

func validateExecutionContract(
	plan domain.Plan,
	contract domain.ExecutionContract,
	blockers []PlanBlocker,
) ([]PlanBlocker, bool, bool) {
	contractSteps := contract.Steps()
	if contract.WorkflowID() != plan.WorkflowID || len(contractSteps) != len(plan.Steps) ||
		contract.RollbackBoundary() != plan.Rollback.Boundary ||
		contract.PointOfNoReturn() != plan.PointOfNoReturn {
		return append(blockers, PlanBlocker{Kind: BlockerContract, ID: "workflow-or-step-set"}), true, true
	}

	minimumApproval := domain.ApprovalRead
	mutationCapable := false
	requiresStepUp := false
	for _, step := range contractSteps {
		if step.MinimumApproval > minimumApproval {
			minimumApproval = step.MinimumApproval
		}
		mutationCapable = mutationCapable || step.Effect == domain.StepEffectMutation
		requiresStepUp = requiresStepUp || step.RequiresStepUp
	}

	expectedPermissions := make(map[string]struct{})
	contractMismatch := false
	for index, step := range plan.Steps {
		expected := contractSteps[index]
		if step.ID != expected.ID || !planStepMatchesContract(step, expected) {
			contractMismatch = true
			continue
		}
		allowedKinds := make(map[string]struct{}, len(expected.TargetKinds))
		for _, kind := range expected.TargetKinds {
			allowedKinds[kind] = struct{}{}
		}
		for _, target := range step.Targets {
			if _, allowed := allowedKinds[target.Kind]; !allowed {
				contractMismatch = true
				continue
			}
			for _, permission := range expected.RequiredPermissions {
				required := domain.PlanPermission{
					StepID: step.ID, Identity: step.ExecutingIdentity, Permission: permission, Resource: target,
				}
				expectedPermissions[planPermissionKey(required)] = struct{}{}
			}
		}
	}
	if contractMismatch || plan.ApprovalClass < minimumApproval ||
		(mutationCapable && plan.ApprovalClass == domain.ApprovalRead) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerContract, ID: "step-or-risk-mismatch"})
	}
	if len(plan.Permissions) != len(expectedPermissions) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerPermission, ID: "workflow-required-set"})
	} else {
		for _, permission := range plan.Permissions {
			if _, expected := expectedPermissions[planPermissionKey(permission)]; !expected {
				blockers = append(blockers, PlanBlocker{Kind: BlockerPermission, ID: "workflow-required-set"})
				break
			}
		}
	}

	return blockers, minimumApproval != domain.ApprovalRead || mutationCapable, requiresStepUp
}

func planStepMatchesContract(step domain.PlanStep, expected domain.ExecutionStepContract) bool {
	return step.Executor == expected.Executor && step.ExecutingIdentity == expected.ExecutingIdentity &&
		step.Idempotent == expected.Idempotent && step.Retry == expected.Retry &&
		step.CancelSafe == expected.CancelSafe && step.TimeoutSeconds == expected.TimeoutSeconds &&
		step.SuccessCondition.String() == expected.SuccessCondition.String() &&
		step.FailureBehavior == expected.FailureBehavior
}

func validateApprovalEvidence(plan domain.Plan, evidence ExecutionEvidence, blockers []PlanBlocker) []PlanBlocker {
	approval := evidence.Approval
	if approval == nil {
		return append(blockers, PlanBlocker{Kind: BlockerApproval, ID: "missing"})
	}
	if approval.PlanID != plan.PlanID || approval.PlanHash != plan.PlanHash || approval.ProjectID != plan.ProjectID ||
		approval.Environment != plan.Environment || approval.EnvironmentClass != plan.EnvironmentClass ||
		approval.Principal != plan.Principal ||
		approval.RecordObject != fmt.Sprintf("plans/%s/%s-approval.json", plan.Environment, plan.PlanID) ||
		!validEvidenceTime(approval.ServerTimeCreated) ||
		approval.ServerTimeCreated.Before(plan.CreatedAt) || approval.ServerTimeCreated.After(evidence.CheckedAt) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerApproval, ID: "invalid-binding"})
	}
	readyAt := approval.ServerTimeCreated.Add(time.Duration(plan.CoolingOffSeconds) * time.Second)
	if evidence.CheckedAt.Before(readyAt) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerCoolingOff, ID: "not-elapsed"})
	}
	if evidence.ObservedAt.Before(readyAt) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerCoolingOff, ID: "revalidation-before-elapse"})
	}
	if plan.Intent != nil && approval.ServerTimeCreated.Before(plan.Intent.WindowStart) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerApproval, ID: "window-confirmation"})
	}

	return blockers
}

func validateIntentEvidence(plan domain.Plan, evidence ExecutionEvidence, blockers []PlanBlocker) []PlanBlocker {
	if plan.Intent == nil {
		if evidence.Intent != nil {
			return append(blockers, PlanBlocker{Kind: BlockerIntent, ID: "unexpected"})
		}
		return blockers
	}
	intent := evidence.Intent
	if intent == nil {
		return append(blockers, PlanBlocker{Kind: BlockerIntent, ID: "missing"})
	}
	if intent.PlanID != plan.PlanID || intent.PlanHash != plan.PlanHash || intent.ProjectID != plan.ProjectID ||
		intent.PolicyHash != plan.PolicyHash.Approved || intent.Environment != plan.Environment ||
		intent.EnvironmentClass != plan.EnvironmentClass || intent.Principal != plan.Principal ||
		!intent.WindowStart.Equal(plan.Intent.WindowStart) ||
		!intent.ValidUntil.Equal(plan.Intent.ValidUntil) || !intent.Active || !intent.SoleActive {
		blockers = append(blockers, PlanBlocker{Kind: BlockerIntent, ID: "invalid-binding"})
	}
	if evidence.CheckedAt.Before(intent.WindowStart) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerIntent, ID: "before-window"})
	}
	if evidence.CheckedAt.After(intent.ValidUntil) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerIntent, ID: "expired"})
	}
	if evidence.ObservedAt.Before(intent.WindowStart) || evidence.ObservedAt.After(intent.ValidUntil) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerIntent, ID: "revalidation-outside-window"})
	}

	return blockers
}

func validatePreconditionEvidence(plan domain.Plan, evidence ExecutionEvidence, blockers []PlanBlocker) []PlanBlocker {
	observed := make(map[string]domain.PlanPrecondition, len(evidence.Preconditions))
	for _, precondition := range evidence.Preconditions {
		if _, duplicate := observed[precondition.ID]; duplicate {
			blockers = append(blockers, PlanBlocker{Kind: BlockerPrecondition, ID: "duplicate-evidence"})
		}
		observed[precondition.ID] = precondition
	}
	if len(evidence.Preconditions) != len(plan.Preconditions) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerPrecondition, ID: "incomplete-evidence"})
	}
	for _, expected := range plan.Preconditions {
		current, exists := observed[expected.ID]
		if !expected.OK || !exists || !current.OK || current.Detail.String() != expected.Detail.String() {
			blockers = append(blockers, PlanBlocker{Kind: BlockerPrecondition, ID: expected.ID})
		}
	}

	return blockers
}

func validateResourceEvidence(plan domain.Plan, evidence ExecutionEvidence, blockers []PlanBlocker) []PlanBlocker {
	observed := make(map[string]domain.PlanResource, len(evidence.Resources))
	for _, resource := range evidence.Resources {
		key := resource.Scope + "\x00" + resource.Kind + "\x00" + resource.Name
		if _, duplicate := observed[key]; duplicate {
			blockers = append(blockers, PlanBlocker{Kind: BlockerResource, ID: "duplicate-evidence"})
		}
		observed[key] = resource
	}
	if len(evidence.Resources) != len(plan.Resources) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerResource, ID: "incomplete-evidence"})
	}
	for _, expected := range plan.Resources {
		current, exists := observed[expected.Scope+"\x00"+expected.Kind+"\x00"+expected.Name]
		if !exists || current != expected {
			blockers = append(blockers, PlanBlocker{Kind: BlockerResource, ID: expected.Kind + "/" + expected.Name})
		}
	}

	return blockers
}

func validatePermissionEvidence(plan domain.Plan, evidence ExecutionEvidence, blockers []PlanBlocker) []PlanBlocker {
	observed := make(map[string]domain.PlanPermission, len(evidence.Permissions))
	for _, permission := range evidence.Permissions {
		key := planPermissionKey(permission)
		if _, duplicate := observed[key]; duplicate {
			blockers = append(blockers, PlanBlocker{Kind: BlockerPermission, ID: "duplicate-evidence"})
		}
		observed[key] = permission
	}
	if len(evidence.Permissions) != len(plan.Permissions) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerPermission, ID: "incomplete-evidence"})
	}
	for _, expected := range plan.Permissions {
		current, exists := observed[planPermissionKey(expected)]
		if !expected.Granted || !exists || !current.Granted || current != expected {
			blockers = append(blockers, PlanBlocker{
				Kind: BlockerPermission, ID: expected.Permission, Identity: expected.Identity,
			})
		}
	}

	return blockers
}

func validateStepUpEvidence(plan domain.Plan, evidence ExecutionEvidence, blockers []PlanBlocker) []PlanBlocker {
	if !plan.StepUpRequired {
		if evidence.StepUp != nil {
			return append(blockers, PlanBlocker{Kind: BlockerStepUp, ID: "unexpected"})
		}
		return blockers
	}
	stepUp := evidence.StepUp
	if stepUp == nil {
		return append(blockers, PlanBlocker{Kind: BlockerStepUp, ID: "missing"})
	}
	if stepUp.PlanID != plan.PlanID || stepUp.PlanHash != plan.PlanHash || stepUp.ProjectID != plan.ProjectID ||
		stepUp.Environment != plan.Environment || stepUp.EnvironmentClass != plan.EnvironmentClass ||
		stepUp.Principal != plan.Principal ||
		!validStepUpObject(stepUp.RecordObject, plan) || !validEvidenceTime(stepUp.ServerTimeCreated) ||
		stepUp.ServerTimeCreated.Before(evidence.ObservedAt) ||
		stepUp.ServerTimeCreated.After(evidence.CheckedAt) ||
		evidence.CheckedAt.Sub(stepUp.ServerTimeCreated) > stepUpFreshness {
		blockers = append(blockers, PlanBlocker{Kind: BlockerStepUp, ID: "invalid-or-stale"})
	}
	if evidence.Approval == nil || stepUp.ServerTimeCreated.Before(
		evidence.Approval.ServerTimeCreated.Add(time.Duration(plan.CoolingOffSeconds)*time.Second),
	) {
		blockers = append(blockers, PlanBlocker{Kind: BlockerStepUp, ID: "before-revalidation"})
	}

	return blockers
}

func planPermissionKey(permission domain.PlanPermission) string {
	return permission.StepID + "\x00" + string(permission.Identity) + "\x00" + permission.Permission + "\x00" +
		permission.Resource.Scope + "\x00" + permission.Resource.Kind + "\x00" + permission.Resource.Name + "\x00" +
		permission.Resource.Fingerprint
}

func validEvidenceTime(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()

	return offset == 0
}

func validStepUpObject(object string, plan domain.Plan) bool {
	prefix := fmt.Sprintf("plans/%s/%s-stepup-", plan.Environment, plan.PlanID)
	if !strings.HasPrefix(object, prefix) || !strings.HasSuffix(object, ".json") {
		return false
	}
	sequence := strings.TrimSuffix(strings.TrimPrefix(object, prefix), ".json")
	if sequence == "" {
		return false
	}
	for _, character := range sequence {
		if character < '0' || character > '9' {
			return false
		}
	}

	return true
}
