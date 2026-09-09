// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"slices"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

// GatewayMode distinguishes a forward bootstrap step from its recorded
// compensation. Both are admitted only inside the approved envelope.
type GatewayMode string

const (
	GatewayApply      GatewayMode = "apply"
	GatewayCompensate GatewayMode = "compensate"
)

// AuthorizationRequest carries every input the gateway requires. Every value
// is supplied by the engine from immutable or freshly observed sources; none
// is inferred from ambient configuration.
type AuthorizationRequest struct {
	Mode        GatewayMode
	Plan        bootstrap.CompiledPlan
	Approval    ApprovalProof
	Intent      bootstrap.StepIntent
	Claim       StepClaimRecord
	Observation StepObservation
	Lock        LockRecord
	Credential  CredentialEvidence
	Harness     isolation.HarnessStateV1
	Expected    isolation.HarnessStateExpectation
	Now         time.Time
}

// Authorize is the single gateway. It fails closed on any missing, stale,
// mismatched, or unadmitted input and otherwise returns exactly one
// per-step MutationAuthorization.
func Authorize(request AuthorizationRequest) (MutationAuthorization, error) {
	if request.Mode != GatewayApply && request.Mode != GatewayCompensate {
		return MutationAuthorization{}, denied("mode")
	}
	if !validUTC(request.Now) {
		return MutationAuthorization{}, denied("now must be explicit UTC")
	}
	reviewed := request.Plan.Plan()
	if request.Plan.DocumentHash() == "" || reviewed.PlanHash == "" || reviewed.PlanID == "" {
		return MutationAuthorization{}, denied("plan is not a sealed compiled plan")
	}
	if err := validateApproval(request.Approval, request.Plan, reviewed, request.Now); err != nil {
		return MutationAuthorization{}, err
	}
	intent, err := matchIntent(request.Plan, request.Intent)
	if err != nil {
		return MutationAuthorization{}, err
	}
	if err := validateClaim(request.Mode, request.Claim, request.Lock, intent, request.Observation, request.Now); err != nil {
		return MutationAuthorization{}, err
	}
	if err := validateLock(request.Lock, request.Claim.Claim.OperationID, reviewed.PlanID, request.Now); err != nil {
		return MutationAuthorization{}, err
	}
	if err := validateCredential(request.Credential, reviewed.Principal, intent.ExecutingIdentity, request.Now); err != nil {
		return MutationAuthorization{}, err
	}
	action := isolation.HarnessActionBootstrapStep
	if request.Mode == GatewayCompensate {
		action = isolation.HarnessActionRollbackStep
	}
	admission := isolation.HarnessAdmissionRequest{
		Action: action, WorkflowID: bootstrap.WorkflowID,
		Plan:        isolation.PlanIdentity{ID: reviewed.PlanID, Hash: reviewed.PlanHash},
		OperationID: request.Claim.Claim.OperationID, BootstrapEnvelopeHash: request.Expected.BootstrapEnvelopeHash,
		StepID: intent.StepID, Expected: request.Expected, Now: request.Now,
	}
	if err := isolation.AdmitHarnessAction(request.Harness, admission); err != nil {
		return MutationAuthorization{}, deniedAs(ErrAuthorizationDenied, "harness admission: "+err.Error())
	}
	return MutationAuthorization{
		PlanDocumentSHA256:    request.Plan.DocumentHash(),
		PlanV1Hash:            reviewed.PlanHash,
		EnvelopeBindingSHA256: intent.EnvelopeBindingSHA256,
		OperationID:           request.Claim.Claim.OperationID,
		StepID:                intent.StepID,
		Attempt:               request.Claim.Claim.Attempt,
		ClaimGeneration:       request.Claim.Generation,
		ExecutingIdentity:     intent.ExecutingIdentity,
		ObservationRevision:   request.Observation.Revision,
		ObservedAt:            request.Observation.ObservedAt,
		ValidUntil:            request.Observation.ValidUntil,
		Now:                   request.Now,
	}, nil
}

func validateApproval(approval ApprovalProof, plan bootstrap.CompiledPlan, reviewed domain.Plan, now time.Time) error {
	switch {
	case approval.PlanID != reviewed.PlanID || approval.ApprovalToken != reviewed.PlanID:
		return deniedAs(ErrApprovalInvalid, "approval token does not name the plan")
	case approval.PlanDocumentSHA256 != plan.DocumentHash():
		return deniedAs(ErrApprovalInvalid, "plan document hash mismatch")
	case approval.PlanV1Hash != reviewed.PlanHash:
		return deniedAs(ErrApprovalInvalid, "PlanV1 hash mismatch")
	case approval.Principal == "" || approval.Principal != reviewed.Principal:
		return deniedAs(ErrApprovalInvalid, "approving principal mismatch")
	case approval.ApprovalClass != reviewed.ApprovalClass || approval.ApprovalClass != domain.ApprovalSecuritySensitive:
		return deniedAs(ErrApprovalInvalid, "approval class is not the plan's AP-3")
	case !validUTC(approval.ApprovedAt) || !validUTC(approval.ValidUntil) || !approval.ApprovedAt.Before(approval.ValidUntil):
		return deniedAs(ErrApprovalInvalid, "approval window malformed")
	case approval.ApprovedAt.Before(reviewed.CreatedAt) || approval.ValidUntil.After(reviewed.ExpiresAt):
		return deniedAs(ErrApprovalInvalid, "approval window exceeds plan validity")
	case now.Before(approval.ApprovedAt):
		return deniedAs(ErrApprovalInvalid, "approval is not yet effective")
	case !now.Before(approval.ValidUntil):
		return deniedAs(ErrApprovalInvalid, "approval expired")
	case !now.Before(reviewed.ExpiresAt) || now.Before(reviewed.CreatedAt):
		return deniedAs(ErrPlanExpired, "plan validity window")
	}
	return nil
}

func matchIntent(plan bootstrap.CompiledPlan, intent bootstrap.StepIntent) (bootstrap.StepIntent, error) {
	binding := plan.Binding().BindingSHA256
	for _, candidate := range plan.Intents() {
		if candidate.StepID != intent.StepID {
			continue
		}
		if !equalCanonical(candidate, intent) || candidate.EnvelopeBindingSHA256 != binding {
			return bootstrap.StepIntent{}, denied("intent does not match the approved plan")
		}
		return candidate, nil
	}
	return bootstrap.StepIntent{}, denied("intent is not part of the approved plan")
}

func findIntent(plan bootstrap.CompiledPlan, stepID string) (bootstrap.StepIntent, bool) {
	for _, candidate := range plan.Intents() {
		if candidate.StepID == stepID {
			return candidate, true
		}
	}
	return bootstrap.StepIntent{}, false
}

func validateClaim(mode GatewayMode, claim StepClaimRecord, lock LockRecord, intent bootstrap.StepIntent, observation StepObservation, now time.Time) error {
	if claim.Generation == 0 || claim.Claim.OperationID == "" || claim.Claim.OperationID != lock.OperationID {
		return denied("durable step claim missing or unbound")
	}
	claimedStep := intent.StepID
	if mode == GatewayCompensate {
		claimedStep = rollbackStepPrefix + intent.StepID
	}
	if claim.Claim.StepID != claimedStep || claim.Claim.Attempt == 0 || claim.Claim.Attempt > attemptBound(intent) {
		return denied("durable step claim does not match the intent attempt bound")
	}
	if !freshAt(observation.ObservedAt, observation.ValidUntil, now) || observation.Revision == "" {
		return deniedAs(ErrObservationStale, "step observation")
	}
	if claim.Claim.ObservationRevision != observation.Revision || !claim.Claim.ObservedAt.Equal(observation.ObservedAt) {
		return deniedAs(ErrObservationStale, "claim was recorded against a different observation")
	}
	if !validUTC(claim.Claim.ClaimedAt) || now.Before(claim.Claim.ClaimedAt) {
		return denied("claim time")
	}
	return nil
}

func validateLock(lock LockRecord, operationID, planID string, now time.Time) error {
	if lock.State != LockHeld || lock.Generation == 0 || lock.OperationID != operationID || lock.PlanID != planID ||
		lock.WorkflowID != bootstrap.WorkflowID {
		return deniedAs(ErrLockLost, "lock is not held by this operation")
	}
	if !validUTC(lock.LeaseUntil) || !now.Before(lock.LeaseUntil) {
		return deniedAs(ErrLockLost, "lock lease expired")
	}
	return nil
}

func validateCredential(credential CredentialEvidence, principal string, identity domain.ExecutionIdentity, now time.Time) error {
	if identity != domain.IdentityHuman {
		return deniedAs(ErrIdentityMismatch, "WF-TEST-01 bootstrap steps execute only as the human principal")
	}
	if credential.Account == "" || credential.Account != principal || credential.Identity != identity {
		return deniedAs(ErrIdentityMismatch, "fresh credential does not match the plan principal")
	}
	if !freshAt(credential.VerifiedAt, credential.ValidUntil, now) {
		return deniedAs(ErrIdentityMismatch, "credential evidence is not fresh")
	}
	return nil
}

// RevalidatePermissions checks fresh exact permission evidence against every
// permission the approved plan declares for the authorized step. The engine
// calls it after the gateway issues an authorization and before any mutation
// adapter is reached; a failure never reaches a provider write.
func RevalidatePermissions(plan bootstrap.CompiledPlan, authorization MutationAuthorization, evidence *bootstrap.PermissionEvidence) error {
	reviewed := plan.Plan()
	if authorization.PlanDocumentSHA256 != plan.DocumentHash() || authorization.PlanV1Hash != reviewed.PlanHash {
		return deniedAs(ErrPermissionRevalidation, "authorization does not bind the plan")
	}
	intent, ok := findIntent(plan, authorization.StepID)
	if !ok {
		return deniedAs(ErrPermissionRevalidation, "authorization names an unknown step")
	}
	return validateStepPermissions(evidence, reviewed, intent, authorization.Now)
}

func validateStepPermissions(evidence *bootstrap.PermissionEvidence, reviewed domain.Plan, intent bootstrap.StepIntent, now time.Time) error {
	required := make([]string, 0)
	for _, permission := range reviewed.Permissions {
		if permission.StepID == intent.StepID {
			if permission.Identity != intent.ExecutingIdentity || !permission.Granted {
				return deniedAs(ErrPermissionRevalidation, "plan permission is not granted to the executing identity")
			}
			required = append(required, permission.Permission)
		}
	}
	if len(required) == 0 {
		return deniedAs(ErrPermissionRevalidation, "plan declares no permission for the step")
	}
	if evidence == nil {
		return deniedAs(ErrPermissionRevalidation, "fresh permission evidence missing")
	}
	if evidence.Schema != bootstrap.PermissionEvidenceSchemaV1 || evidence.Account != reviewed.Principal ||
		evidence.Project != reviewed.ProjectID || evidence.Revision == "" || !freshAt(evidence.ObservedAt, evidence.ValidUntil, now) {
		return deniedAs(ErrPermissionRevalidation, "permission evidence is not fresh and exact")
	}
	observed := make([]string, 0, len(evidence.Grants))
	for _, grant := range evidence.Grants {
		if grant.StepID != intent.StepID || grant.Identity != intent.ExecutingIdentity || !grant.Granted {
			return deniedAs(ErrPermissionRevalidation, "evidence contains a foreign, denied, or misattributed grant")
		}
		observed = append(observed, grant.Permission)
	}
	if !slices.Equal(observed, required) {
		return deniedAs(ErrPermissionRevalidation, "evidence does not equal the declared step permissions")
	}
	return nil
}

func equalCanonical(left, right any) bool {
	leftHash, leftErr := hashJSON(left)
	rightHash, rightErr := hashJSON(right)
	return leftErr == nil && rightErr == nil && leftHash == rightHash
}
