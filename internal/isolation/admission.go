// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"errors"
	"slices"
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
	ProjectID                string
	Environment              string
	EnvironmentClass         string
	ManifestHash             string
	ApprovedPlan             PlanIdentity
	OperationID              string
	BootstrapEnvelopeHash    string
	ControlRecordGeneration  uint64
	Resources                HarnessResourceFingerprints
	CleanupCapabilities      []CleanupCapability
	BootstrapSteps           []string
	RollbackSteps            []string
	ApprovedAt               time.Time
	ApprovalValidUntil       time.Time
	BootstrapPhase           BootstrapPhase
	BootstrapOpenedAt        time.Time
	T8ObservationRevision    string
	T8ObservedAt             time.Time
	T8ValidUntil             time.Time
	TestUsability            TestUsability
	DriftObservationRevision string
	DriftDetectedAt          time.Time
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
	if request.Now.Before(state.payload.ApprovedAt) {
		return guardError(ErrHarnessStateStale, "approval", "precedes the approved bootstrap window")
	}
	// The approval deadline stops forward bootstrap work, not the exact
	// compensation already approved in the same immutable envelope. Provider
	// ownership, journal, lock, and live revalidation gates still apply to the
	// admitted rollback step.
	if request.Action == HarnessActionBootstrapStep && !request.Now.Before(state.payload.ApprovalValidUntil) {
		return guardError(ErrHarnessStateStale, "approval", "is outside the approved bootstrap execution window")
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
		state.payload.ApprovedPlan != expected.ApprovedPlan ||
		state.payload.OperationID != expected.OperationID ||
		state.payload.BootstrapEnvelopeHash != expected.BootstrapEnvelopeHash ||
		state.payload.ControlRecordGeneration != expected.ControlRecordGeneration ||
		state.payload.Resources != expected.Resources ||
		!slices.Equal(state.payload.BootstrapSteps, expected.BootstrapSteps) ||
		!slices.Equal(state.payload.RollbackSteps, expected.RollbackSteps) ||
		!state.payload.ApprovedAt.Equal(expected.ApprovedAt) ||
		!state.payload.ApprovalValidUntil.Equal(expected.ApprovalValidUntil) ||
		state.payload.BootstrapPhase != expected.BootstrapPhase ||
		!optionalTimeMatches(state.payload.BootstrapOpenedAt, expected.BootstrapOpenedAt) ||
		state.payload.TestUsability != expected.TestUsability ||
		state.payload.DriftObservationRevision != expected.DriftObservationRevision ||
		!optionalTimeMatches(state.payload.DriftDetectedAt, expected.DriftDetectedAt) {
		return guardError(ErrHarnessStateMismatch, "binding", "does not match trusted configuration and durable observation")
	}
	if err := validateUTCWindow(expected.ApprovedAt, expected.ApprovalValidUntil, 0); err != nil {
		return guardError(ErrHarnessStateMismatch, "approval", "trusted expectation is malformed")
	}
	if err := ValidateCleanupCapabilities(expected.CleanupCapabilities); err != nil ||
		!equalCleanupCapabilities(state.payload.CleanupCapabilities, expected.CleanupCapabilities) {
		return guardError(ErrHarnessStateMismatch, "cleanupCapabilities", "does not match trusted policy")
	}
	if state.payload.BootstrapPhase == BootstrapPhasePending {
		if expected.T8ObservationRevision != "" || !expected.T8ObservedAt.IsZero() || !expected.T8ValidUntil.IsZero() {
			return guardError(ErrHarnessStateMismatch, "t8", "pending trusted state cannot contain T8 evidence")
		}
		return nil
	}
	if state.payload.T8ObservedAt == nil || state.payload.T8ValidUntil == nil ||
		expected.T8ObservationRevision != state.payload.T8ObservationRevision ||
		!expected.T8ObservedAt.Equal(*state.payload.T8ObservedAt) ||
		!expected.T8ValidUntil.Equal(*state.payload.T8ValidUntil) ||
		validateT8Evidence(T8Evidence{expected.T8ObservationRevision, expected.T8ObservedAt, expected.T8ValidUntil}) != nil {
		return guardError(ErrHarnessStateMismatch, "t8", "does not match the trusted complete T8 observation")
	}
	return nil
}

func optionalTimeMatches(actual *time.Time, expected time.Time) bool {
	if actual == nil {
		return expected.IsZero()
	}
	return actual.Equal(expected)
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
