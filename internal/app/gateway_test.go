// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

// boardFields is the uniform mutation-authorization field list fixed by the
// M-1 parallel board. Every adapter's prefixed struct must carry exactly it.
var boardFields = []string{
	"PlanDocumentSHA256", "PlanV1Hash", "EnvelopeBindingSHA256", "OperationID", "StepID", "Attempt",
	"ClaimGeneration", "ExecutingIdentity", "ObservationRevision", "ObservedAt", "ValidUntil", "Now",
}

func TestMutationAuthorizationCarriesExactlyTheBoardFields(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeOf(MutationAuthorization{})
	names := make([]string, 0, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		names = append(names, typ.Field(index).Name)
	}
	if !slices.Equal(names, boardFields) {
		t.Fatalf("MutationAuthorization fields = %v, want %v", names, boardFields)
	}
}

type gatewayFixture struct {
	plan    bootstrap.CompiledPlan
	request AuthorizationRequest
}

func validGatewayRequest(t *testing.T) gatewayFixture {
	t.Helper()
	plan := fixturePlan(t)
	approval := fixtureApproval(plan)
	now := testNow.Add(3 * time.Minute)
	seed, err := HarnessSeed(plan, testOperationID, EnvelopeRecord{Hash: testEnvelope, Generation: 1}, approval)
	if err != nil {
		t.Fatalf("HarnessSeed() unexpected error: %v", err)
	}
	state, err := isolation.NewPendingHarnessStateV1(seed)
	if err != nil {
		t.Fatalf("NewPendingHarnessStateV1() unexpected error: %v", err)
	}
	intent := plan.Intents()[0]
	observation := StepObservation{Revision: strings.Repeat("c", 64), ObservedAt: now.Add(-time.Second), ValidUntil: now.Add(time.Minute),
		Resources: []ResourceObservation{{ResourceID: "audit-bucket", State: ResourceAbsent}}}
	return gatewayFixture{plan: plan, request: AuthorizationRequest{
		Mode: GatewayApply, Plan: plan, Approval: approval, Intent: intent,
		Claim: StepClaimRecord{Generation: 7, Claim: StepClaim{OperationID: testOperationID, StepID: intent.StepID, Attempt: 1,
			ObservationRevision: observation.Revision, ObservedAt: observation.ObservedAt, ClaimedAt: now, AbsentResourceIDs: []string{"audit-bucket"}}},
		Observation: observation,
		Lock: LockRecord{State: LockHeld, OperationID: testOperationID, PlanID: testPlanID, WorkflowID: bootstrap.WorkflowID,
			AcquiredAt: now, HeartbeatAt: now, LeaseUntil: now.Add(LockLease), Generation: 3},
		Credential: CredentialEvidence{Account: testAccount, Identity: domain.IdentityHuman, VerifiedAt: now.Add(-time.Second), ValidUntil: now.Add(time.Minute)},
		Harness:    state, Expected: harnessExpectation(seed), Now: now,
	}}
}

func TestAuthorizeIssuesTheBoundAuthorization(t *testing.T) {
	t.Parallel()
	fixture := validGatewayRequest(t)
	authorization, err := Authorize(fixture.request)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	want := MutationAuthorization{
		PlanDocumentSHA256: fixture.plan.DocumentHash(), PlanV1Hash: fixture.plan.Plan().PlanHash,
		EnvelopeBindingSHA256: fixture.plan.Binding().BindingSHA256, OperationID: testOperationID,
		StepID: "k1-audit-bootstrap", Attempt: 1, ClaimGeneration: 7, ExecutingIdentity: domain.IdentityHuman,
		ObservationRevision: fixture.request.Observation.Revision, ObservedAt: fixture.request.Observation.ObservedAt,
		ValidUntil: fixture.request.Observation.ValidUntil, Now: fixture.request.Now,
	}
	if authorization != want {
		t.Fatalf("Authorize() = %+v, want %+v", authorization, want)
	}
}

func TestAuthorizeFailsClosedOnEveryGate(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		mutate func(*AuthorizationRequest)
		want   error
	}{
		"foreign intent": {func(request *AuthorizationRequest) { request.Intent.Compensation = "changed" }, ErrAuthorizationDenied},
		"unknown step":   {func(request *AuthorizationRequest) { request.Intent.StepID = "t9-extra" }, ErrAuthorizationDenied},
		"stale observation": {func(request *AuthorizationRequest) {
			request.Observation.ValidUntil = request.Now
		}, ErrObservationStale},
		"claim observation mismatch": {func(request *AuthorizationRequest) {
			request.Claim.Claim.ObservationRevision = strings.Repeat("d", 64)
		}, ErrObservationStale},
		"claim missing":  {func(request *AuthorizationRequest) { request.Claim = StepClaimRecord{} }, ErrAuthorizationDenied},
		"claim overflow": {func(request *AuthorizationRequest) { request.Claim.Claim.Attempt = 4 }, ErrAuthorizationDenied},
		"lock released":  {func(request *AuthorizationRequest) { request.Lock.State = LockReleased }, ErrLockLost},
		"lock foreign":   {func(request *AuthorizationRequest) { request.Lock.OperationID = "op-00000000000000bb" }, ErrAuthorizationDenied},
		"lock expired":   {func(request *AuthorizationRequest) { request.Lock.LeaseUntil = request.Now }, ErrLockLost},
		"credential account": {func(request *AuthorizationRequest) {
			request.Credential.Account = "intruder@example.invalid"
		}, ErrIdentityMismatch},
		"credential stale": {func(request *AuthorizationRequest) { request.Credential.ValidUntil = request.Now }, ErrIdentityMismatch},
		"identity not human": {func(request *AuthorizationRequest) {
			request.Intent.ExecutingIdentity = domain.IdentityOperator
		}, ErrAuthorizationDenied},
		"approval hash": {func(request *AuthorizationRequest) { request.Approval.PlanV1Hash = testEnvelope }, ErrApprovalInvalid},
		"plan expired": {func(request *AuthorizationRequest) {
			request.Now = testNow.Add(2 * time.Hour)
			request.Approval.ValidUntil = testNow.Add(3 * time.Hour)
		}, ErrApprovalInvalid},
		"envelope mismatch": {func(request *AuthorizationRequest) {
			request.Expected.BootstrapEnvelopeHash = strings.Repeat("e", 64)
		}, ErrAuthorizationDenied},
		"foreign operation": {func(request *AuthorizationRequest) {
			request.Claim.Claim.OperationID = "op-00000000000000bb"
			request.Lock.OperationID = "op-00000000000000bb"
		}, ErrAuthorizationDenied},
		"local now": {func(request *AuthorizationRequest) { request.Now = request.Now.In(time.FixedZone("x", 3600)) }, ErrAuthorizationDenied},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := validGatewayRequest(t)
			testCase.mutate(&fixture.request)
			if _, err := Authorize(fixture.request); !errors.Is(err, testCase.want) {
				t.Fatalf("Authorize() error = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestCompensateModeAdmitsOnlyRecordedRollbackClaims(t *testing.T) {
	t.Parallel()
	fixture := validGatewayRequest(t)
	fixture.request.Mode = GatewayCompensate
	if _, err := Authorize(fixture.request); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("compensation with a forward claim error = %v", err)
	}
	fixture.request.Claim.Claim.StepID = rollbackStepPrefix + fixture.request.Intent.StepID
	authorization, err := Authorize(fixture.request)
	if err != nil || authorization.StepID != fixture.request.Intent.StepID {
		t.Fatalf("Authorize(compensate) = %+v, %v", authorization, err)
	}
}

func TestRevalidatePermissionsRequiresExactFreshEvidence(t *testing.T) {
	t.Parallel()
	fixture := validGatewayRequest(t)
	authorization, err := Authorize(fixture.request)
	if err != nil {
		t.Fatalf("Authorize() unexpected error: %v", err)
	}
	good := permissionEvidenceFor(authorization.StepID, authorization.Now)
	if err := RevalidatePermissions(fixture.plan, authorization, &good); err != nil {
		t.Fatalf("RevalidatePermissions(good) = %v", err)
	}
	for name, mutate := range map[string]func(*bootstrap.PermissionEvidence){
		"missing grant":   func(evidence *bootstrap.PermissionEvidence) { evidence.Grants = evidence.Grants[1:] },
		"denied grant":    func(evidence *bootstrap.PermissionEvidence) { evidence.Grants[0].Granted = false },
		"foreign step":    func(evidence *bootstrap.PermissionEvidence) { evidence.Grants[0].StepID = "t1-network" },
		"foreign project": func(evidence *bootstrap.PermissionEvidence) { evidence.Project = "another-project" },
		"stale":           func(evidence *bootstrap.PermissionEvidence) { evidence.ValidUntil = authorization.Now },
		"extra grant": func(evidence *bootstrap.PermissionEvidence) {
			evidence.Grants = append(evidence.Grants, bootstrap.PermissionGrant{StepID: authorization.StepID, Identity: domain.IdentityHuman, Permission: "storage.buckets.delete", Granted: true})
		},
	} {
		evidence := permissionEvidenceFor(authorization.StepID, authorization.Now)
		mutate(&evidence)
		if err := RevalidatePermissions(fixture.plan, authorization, &evidence); !errors.Is(err, ErrPermissionRevalidation) {
			t.Fatalf("%s: RevalidatePermissions() = %v", name, err)
		}
	}
	if err := RevalidatePermissions(fixture.plan, authorization, nil); !errors.Is(err, ErrPermissionRevalidation) {
		t.Fatalf("nil evidence accepted: %v", err)
	}
}
