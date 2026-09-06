// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

func TestPendingHarnessAdmitsOnlySameApprovedBootstrapEnvelope(t *testing.T) {
	t.Parallel()

	state := validPendingHarnessState(t)
	request := validPendingAdmission(state)
	if err := isolation.AdmitHarnessAction(state, request); err != nil {
		t.Fatalf("AdmitHarnessAction(bootstrap) unexpected error: %v", err)
	}
	rollback := request
	rollback.Action = isolation.HarnessActionRollbackStep
	rollback.StepID = "rollback-network"
	if err := isolation.AdmitHarnessAction(state, rollback); err != nil {
		t.Fatalf("AdmitHarnessAction(rollback) unexpected error: %v", err)
	}
	expiredRollback := rollback
	expiredRollback.Now = validHarnessStateSeed().ApprovalValidUntil.Add(24 * time.Hour)
	if err := isolation.AdmitHarnessAction(state, expiredRollback); err != nil {
		t.Fatalf("AdmitHarnessAction(expired-window recorded rollback) unexpected error: %v", err)
	}
	prematureRollback := rollback
	prematureRollback.Now = validHarnessStateSeed().ApprovedAt.Add(-time.Second)
	if err := isolation.AdmitHarnessAction(state, prematureRollback); !errors.Is(err, isolation.ErrHarnessStateStale) {
		t.Fatalf("AdmitHarnessAction(pre-approval rollback) error = %v; want ErrHarnessStateStale", err)
	}

	tests := []struct {
		name   string
		mutate func(*isolation.HarnessAdmissionRequest)
		kind   error
	}{
		{name: "TEST-I", mutate: func(value *isolation.HarnessAdmissionRequest) { value.Action = isolation.HarnessActionIntegrationTest }, kind: isolation.ErrHarnessAdmissionDenied},
		{name: "TEST-D", mutate: func(value *isolation.HarnessAdmissionRequest) { value.Action = isolation.HarnessActionDestructiveTest }, kind: isolation.ErrHarnessAdmissionDenied},
		{name: "unrelated mutation", mutate: func(value *isolation.HarnessAdmissionRequest) {
			value.Action = isolation.HarnessActionUnrelatedMutation
		}, kind: isolation.ErrHarnessAdmissionDenied},
		{name: "other workflow", mutate: func(value *isolation.HarnessAdmissionRequest) { value.WorkflowID = "WF-PROV-01" }, kind: isolation.ErrHarnessAdmissionDenied},
		{name: "other plan", mutate: func(value *isolation.HarnessAdmissionRequest) { value.Plan.ID = "plan-fedcba9876543210" }, kind: isolation.ErrHarnessAdmissionDenied},
		{name: "other operation", mutate: func(value *isolation.HarnessAdmissionRequest) { value.OperationID = "op-fedcba9876543210" }, kind: isolation.ErrHarnessAdmissionDenied},
		{name: "other envelope", mutate: func(value *isolation.HarnessAdmissionRequest) { value.BootstrapEnvelopeHash = strings.Repeat("e", 64) }, kind: isolation.ErrHarnessAdmissionDenied},
		{name: "unrecorded step", mutate: func(value *isolation.HarnessAdmissionRequest) { value.StepID = "create-unknown" }, kind: isolation.ErrHarnessAdmissionDenied},
		{name: "expired approval", mutate: func(value *isolation.HarnessAdmissionRequest) { value.Now = validHarnessStateSeed().ApprovalValidUntil }, kind: isolation.ErrHarnessStateStale},
		{name: "cross project state", mutate: func(value *isolation.HarnessAdmissionRequest) { value.Expected.ProjectID = "other-project" }, kind: isolation.ErrHarnessStateMismatch},
		{name: "stale generation", mutate: func(value *isolation.HarnessAdmissionRequest) { value.Expected.ControlRecordGeneration++ }, kind: isolation.ErrHarnessStateMismatch},
		{name: "trusted plan drift", mutate: func(value *isolation.HarnessAdmissionRequest) {
			value.Expected.ApprovedPlan.ID = "plan-fedcba9876543210"
		}, kind: isolation.ErrHarnessStateMismatch},
		{name: "trusted operation drift", mutate: func(value *isolation.HarnessAdmissionRequest) { value.Expected.OperationID = "op-fedcba9876543210" }, kind: isolation.ErrHarnessStateMismatch},
		{name: "trusted envelope drift", mutate: func(value *isolation.HarnessAdmissionRequest) {
			value.Expected.BootstrapEnvelopeHash = strings.Repeat("d", 64)
		}, kind: isolation.ErrHarnessStateMismatch},
		{name: "trusted bootstrap steps drift", mutate: func(value *isolation.HarnessAdmissionRequest) {
			value.Expected.BootstrapSteps = []string{"create-audit"}
		}, kind: isolation.ErrHarnessStateMismatch},
		{name: "trusted rollback steps drift", mutate: func(value *isolation.HarnessAdmissionRequest) {
			value.Expected.RollbackSteps = []string{"rollback-other"}
		}, kind: isolation.ErrHarnessStateMismatch},
		{name: "trusted approval drift", mutate: func(value *isolation.HarnessAdmissionRequest) {
			value.Expected.ApprovalValidUntil = value.Expected.ApprovalValidUntil.Add(time.Minute)
		}, kind: isolation.ErrHarnessStateMismatch},
		{name: "capability drift", mutate: func(value *isolation.HarnessAdmissionRequest) {
			value.Expected.CleanupCapabilities[0] = "compute.snapshots"
		}, kind: isolation.ErrHarnessStateMismatch},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validPendingAdmission(state)
			test.mutate(&value)
			if err := isolation.AdmitHarnessAction(state, value); !errors.Is(err, test.kind) {
				t.Fatalf("AdmitHarnessAction() error = %v; want %v", err, test.kind)
			}
		})
	}
}

func TestOpenHarnessRequiresFreshExactUsableT8ForTests(t *testing.T) {
	t.Parallel()

	pending := validPendingHarnessState(t)
	open, err := pending.OpenAfterT8(validT8Evidence(), validT8BoundaryNow())
	if err != nil {
		t.Fatalf("OpenAfterT8() unexpected error: %v", err)
	}
	request := validOpenTestAdmission()
	for _, action := range []isolation.HarnessAction{isolation.HarnessActionIntegrationTest, isolation.HarnessActionDestructiveTest} {
		request.Action = action
		if err := isolation.AdmitHarnessAction(open, request); err != nil {
			t.Fatalf("AdmitHarnessAction(%s) unexpected error: %v", action, err)
		}
	}

	tests := []struct {
		name   string
		mutate func(*isolation.HarnessAdmissionRequest)
	}{
		{name: "stale T8", mutate: func(value *isolation.HarnessAdmissionRequest) { value.Now = validT8Evidence().ValidUntil }},
		{name: "future clock", mutate: func(value *isolation.HarnessAdmissionRequest) {
			value.Now = validT8Evidence().ObservedAt.Add(-time.Second)
		}},
		{name: "wrong revision", mutate: func(value *isolation.HarnessAdmissionRequest) { value.T8ObservationRevision = strings.Repeat("f", 64) }},
		{name: "missing revision", mutate: func(value *isolation.HarnessAdmissionRequest) { value.T8ObservationRevision = "" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validOpenTestAdmission()
			test.mutate(&value)
			if err := isolation.AdmitHarnessAction(open, value); !errors.Is(err, isolation.ErrHarnessAdmissionDenied) {
				t.Fatalf("AdmitHarnessAction() error = %v; want ErrHarnessAdmissionDenied", err)
			}
		})
	}

	drifted, err := open.MarkTestsUnusable(validDriftEvidence())
	if err != nil {
		t.Fatalf("MarkTestsUnusable() unexpected error: %v", err)
	}
	if err := isolation.AdmitHarnessAction(drifted, validOpenTestAdmission()); !errors.Is(err, isolation.ErrHarnessAdmissionDenied) {
		t.Fatalf("AdmitHarnessAction(unusable TEST-I) error = %v; want ErrHarnessAdmissionDenied", err)
	}
	unrelated := validOpenTestAdmission()
	unrelated.Action = isolation.HarnessActionUnrelatedMutation
	unrelated.T8ObservationRevision = ""
	unrelated.Now = validT8Evidence().ValidUntil.Add(24 * time.Hour)
	if err := isolation.AdmitHarnessAction(drifted, unrelated); err != nil {
		t.Fatalf("open drifted harness recreated global blockade: %v", err)
	}
}

func TestHarnessAdmissionRejectsMalformedAndUnknownRequests(t *testing.T) {
	t.Parallel()

	state := validPendingHarnessState(t)
	request := validPendingAdmission(state)
	request.Now = request.Now.In(time.FixedZone("offset", 60))
	if err := isolation.AdmitHarnessAction(state, request); !errors.Is(err, isolation.ErrHarnessAdmissionDenied) {
		t.Fatalf("non-UTC request error = %v; want ErrHarnessAdmissionDenied", err)
	}
	open, _ := state.OpenAfterT8(validT8Evidence(), validT8BoundaryNow())
	unknown := validOpenTestAdmission()
	unknown.Action = "unknown"
	if err := isolation.AdmitHarnessAction(open, unknown); !errors.Is(err, isolation.ErrHarnessAdmissionDenied) {
		t.Fatalf("unknown action error = %v; want ErrHarnessAdmissionDenied", err)
	}
	if err := isolation.AdmitHarnessAction(isolation.HarnessStateV1{}, unknown); !errors.Is(err, isolation.ErrInvalidHarnessState) {
		t.Fatalf("zero state error = %v; want ErrInvalidHarnessState", err)
	}
}

func validPendingAdmission(state isolation.HarnessStateV1) isolation.HarnessAdmissionRequest {
	seed := validHarnessStateSeed()
	return isolation.HarnessAdmissionRequest{
		Action: isolation.HarnessActionBootstrapStep, WorkflowID: isolation.WFTestWorkflowID,
		Plan: seed.ApprovedPlan, OperationID: seed.OperationID,
		BootstrapEnvelopeHash: seed.BootstrapEnvelopeHash, StepID: "create-network",
		Expected: validHarnessExpectation(), Now: seed.ApprovedAt.Add(30 * time.Minute),
	}
}

func validOpenTestAdmission() isolation.HarnessAdmissionRequest {
	evidence := validT8Evidence()
	return isolation.HarnessAdmissionRequest{
		Action:                isolation.HarnessActionIntegrationTest,
		T8ObservationRevision: evidence.Revision,
		Expected:              validHarnessExpectation(), Now: evidence.ObservedAt.Add(time.Minute),
	}
}

func validHarnessExpectation() isolation.HarnessStateExpectation {
	seed := validHarnessStateSeed()
	return isolation.HarnessStateExpectation{
		ProjectID: seed.ProjectID, Environment: seed.Environment, EnvironmentClass: seed.EnvironmentClass,
		ManifestHash: seed.ManifestHash, ApprovedPlan: seed.ApprovedPlan, OperationID: seed.OperationID,
		BootstrapEnvelopeHash: seed.BootstrapEnvelopeHash, ControlRecordGeneration: seed.ControlRecordGeneration,
		Resources: seed.Resources, CleanupCapabilities: append([]isolation.CleanupCapability(nil), seed.CleanupCapabilities...),
		BootstrapSteps: append([]string(nil), seed.BootstrapSteps...), RollbackSteps: append([]string(nil), seed.RollbackSteps...),
		ApprovedAt: seed.ApprovedAt, ApprovalValidUntil: seed.ApprovalValidUntil,
	}
}
