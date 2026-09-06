// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"errors"
	"time"
)

var ErrHarnessAdmissionDenied = errors.New("test harness admission denied")

type HarnessAction string

const (
	HarnessActionBootstrapStep     HarnessAction = "wf-test-bootstrap-step"
	HarnessActionRollbackStep      HarnessAction = "wf-test-rollback-step"
	HarnessActionIntegrationTest   HarnessAction = "test-i"
	HarnessActionDestructiveTest   HarnessAction = "test-d"
	HarnessActionUnrelatedMutation HarnessAction = "unrelated-mutation"
)

// HarnessStateExpectation is the trusted durable-observation binding. A
// caller cannot validate state against values sourced from that same state;
// the future control adapter supplies these from the manifest, approved plan,
// and generation-bearing object observation.
type HarnessStateExpectation struct {
	ProjectID               string
	Environment             string
	EnvironmentClass        string
	ManifestHash            string
	ControlRecordGeneration uint64
	Resources               HarnessResourceFingerprints
	CleanupCapabilities     []CleanupCapability
}

// HarnessAdmissionRequest asks only whether the TEST-ISO global blockade is
// satisfied. A successful result is not provider authorization; ordinary plan,
// approval, journal, lock, revalidation, and typed-intent gates still apply.
type HarnessAdmissionRequest struct {
	Action                HarnessAction
	WorkflowID            string
	Plan                  PlanIdentity
	OperationID           string
	BootstrapEnvelopeHash string
	StepID                string
	T8ObservationRevision string
	Expected              HarnessStateExpectation
	Now                   time.Time
}

// AdmitHarnessAction enforces D-156's pre-T8 global blockade and the fresh,
// exact state requirement for every TEST-I/TEST-D run.
func AdmitHarnessAction(state HarnessStateV1, request HarnessAdmissionRequest) error {
	if err := state.validate(); err != nil {
		return err
	}
	if err := validateHarnessExpectation(state, request.Expected); err != nil {
		return err
	}
	if request.Now.IsZero() {
		return guardError(ErrHarnessAdmissionDenied, "now", "must be explicit")
	}
	if _, offset := request.Now.Zone(); offset != 0 {
		return guardError(ErrHarnessAdmissionDenied, "now", "must use UTC")
	}

	if state.payload.BootstrapPhase == BootstrapPhasePending {
		return admitPendingHarnessAction(state, request)
	}
	return admitOpenHarnessAction(state, request)
}

func admitPendingHarnessAction(state HarnessStateV1, request HarnessAdmissionRequest) error {
	if request.Now.Before(state.payload.ApprovedAt) || !request.Now.Before(state.payload.ApprovalValidUntil) {
		return guardError(ErrHarnessStateStale, "approval", "is outside the approved bootstrap window")
	}
	if request.Action != HarnessActionBootstrapStep && request.Action != HarnessActionRollbackStep {
		return guardError(ErrHarnessAdmissionDenied, "bootstrapPhase", "admits only the approved WF-TEST-01 envelope")
	}
	if request.WorkflowID != WFTestWorkflowID || request.Plan != state.payload.ApprovedPlan ||
		request.OperationID != state.payload.OperationID || request.BootstrapEnvelopeHash != state.payload.BootstrapEnvelopeHash {
		return guardError(ErrHarnessAdmissionDenied, "bootstrapBinding", "does not match the pending bootstrap envelope")
	}
	steps := state.payload.BootstrapSteps
	if request.Action == HarnessActionRollbackStep {
		steps = state.payload.RollbackSteps
	}
	if !containsStep(steps, request.StepID) {
		return guardError(ErrHarnessAdmissionDenied, "stepID", "is not recorded in the approved bootstrap envelope")
	}
	return nil
}

func admitOpenHarnessAction(state HarnessStateV1, request HarnessAdmissionRequest) error {
	switch request.Action {
	case HarnessActionIntegrationTest, HarnessActionDestructiveTest:
		if state.payload.TestUsability != TestUsabilityUsable || state.payload.T8ValidUntil == nil ||
			!request.Now.Before(*state.payload.T8ValidUntil) || request.Now.Before(*state.payload.T8ObservedAt) ||
			request.T8ObservationRevision != state.payload.T8ObservationRevision {
			return guardError(ErrHarnessAdmissionDenied, "t8", "is not fresh, usable, and exact")
		}
		return nil
	case HarnessActionUnrelatedMutation:
		return nil
	case HarnessActionBootstrapStep, HarnessActionRollbackStep:
		if request.WorkflowID != WFTestWorkflowID {
			return guardError(ErrHarnessAdmissionDenied, "workflowID", "does not identify WF-TEST-01")
		}
		return nil
	default:
		return guardError(ErrHarnessAdmissionDenied, "action", "is unknown")
	}
}

func validateHarnessExpectation(state HarnessStateV1, expected HarnessStateExpectation) error {
	if state.payload.ProjectID != expected.ProjectID || state.payload.Environment != expected.Environment ||
		state.payload.EnvironmentClass != expected.EnvironmentClass ||
		state.payload.ManifestHash != expected.ManifestHash ||
		state.payload.ControlRecordGeneration != expected.ControlRecordGeneration ||
		state.payload.Resources != expected.Resources {
		return guardError(ErrHarnessStateMismatch, "binding", "does not match trusted configuration and durable observation")
	}
	if err := ValidateCleanupCapabilities(expected.CleanupCapabilities); err != nil ||
		!equalCleanupCapabilities(state.payload.CleanupCapabilities, expected.CleanupCapabilities) {
		return guardError(ErrHarnessStateMismatch, "cleanupCapabilities", "does not match trusted policy")
	}
	return nil
}

func equalCleanupCapabilities(first, second []CleanupCapability) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
