// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

const otherPlanID = "plan-fedcba9876543210"

var happyStates = []domain.OperationState{
	domain.OperationDiscover, domain.OperationValidate, domain.OperationPlan, domain.OperationLock,
	domain.OperationExecute, domain.OperationVerify, domain.OperationDocument, domain.OperationComplete,
}

func TestPreviewIsNonMutating(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	preview, err := fixture.engine.Preview(fixture.plan)
	if err != nil {
		t.Fatalf("Preview() unexpected error: %v", err)
	}
	if len(preview.Steps) != 14 || preview.PointOfNoReturnStep != "k1-retention-lock" || preview.DocumentHash != fixture.plan.DocumentHash() {
		t.Fatalf("Preview() = %+v", preview)
	}
	if len(fixture.store.calls) != 0 || fixture.provider.observeCalls != 0 || len(fixture.provider.applies) != 0 {
		t.Fatalf("plan-only touched store %v, observer %d, adapters %d", fixture.store.calls, fixture.provider.observeCalls, len(fixture.provider.applies))
	}
}

func TestExecuteCompletesFirstBootstrapAndOpensHarness(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	report, err := fixture.run()
	if err != nil {
		t.Fatalf("Execute() unexpected error: %v (report %+v)", err, report)
	}
	if report.State != domain.OperationComplete || report.BootstrapPhase != isolation.BootstrapPhaseOpen ||
		report.TestUsability != isolation.TestUsabilityUsable || !report.PointOfNoReturnCrossed {
		t.Fatalf("report = %+v", report)
	}
	if !slices.Equal(fixture.store.states(), happyStates) {
		t.Fatalf("journal states = %v", fixture.store.states())
	}
	want := make([]string, 0)
	for _, intent := range fixture.plan.Intents() {
		if intent.Kind != bootstrap.IntentIsolationGate {
			want = append(want, intent.StepID)
		}
	}
	if !slices.Equal(fixture.provider.appliedSteps(), want) {
		t.Fatalf("applied steps = %v", fixture.provider.appliedSteps())
	}
	for _, authorization := range fixture.provider.applies {
		if authorization.PlanDocumentSHA256 != fixture.plan.DocumentHash() || authorization.PlanV1Hash != fixture.plan.Plan().PlanHash ||
			authorization.OperationID != testOperationID || authorization.ExecutingIdentity != domain.IdentityHuman {
			t.Fatalf("authorization = %+v", authorization)
		}
	}
	if fixture.store.lock.State != LockReleased || fixture.store.calls["ReplaceHarnessState"] != 1 {
		t.Fatalf("lock %+v replace calls %d", fixture.store.lock, fixture.store.calls["ReplaceHarnessState"])
	}
}

func TestApprovalMismatchOrExpiryBlocksEveryMutation(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*harness, *ApprovalProof){
		"document hash": func(_ *harness, approval *ApprovalProof) { approval.PlanDocumentSHA256 = testEnvelope },
		"plan v1 hash":  func(_ *harness, approval *ApprovalProof) { approval.PlanV1Hash = testEnvelope },
		"other plan id": func(_ *harness, approval *ApprovalProof) { approval.ApprovalToken = otherPlanID },
		"principal":     func(_ *harness, approval *ApprovalProof) { approval.Principal = "someone-else@example.invalid" },
		"class":         func(_ *harness, approval *ApprovalProof) { approval.ApprovalClass = domain.ApprovalDestructive },
		"expired":       func(_ *harness, approval *ApprovalProof) { approval.ValidUntil = testNow.Add(90 * time.Second) },
		"plan expired":  func(fixture *harness, _ *ApprovalProof) { fixture.clock.now = testNow.Add(2 * time.Hour) },
		"not effective": func(_ *harness, approval *ApprovalProof) { approval.ApprovedAt = testNow.Add(30 * time.Minute) },
		"beyond plan":   func(_ *harness, approval *ApprovalProof) { approval.ValidUntil = testNow.Add(2 * time.Hour) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newHarness(t)
			approval := fixtureApproval(fixture.plan)
			mutate(fixture, &approval)
			_, err := fixture.engine.Execute(t.Context(), RunRequest{Plan: fixture.plan, Approval: approval, OperationID: testOperationID})
			if err == nil {
				t.Fatalf("Execute() succeeded with a %s mismatch", name)
			}
			if !errors.Is(err, ErrApprovalInvalid) && !errors.Is(err, ErrPlanExpired) && !errors.Is(err, ErrInvalidRun) {
				t.Fatalf("Execute() error = %v", err)
			}
			if len(fixture.provider.applies) != 0 || len(fixture.provider.present) != 0 {
				t.Fatalf("%s mismatch reached an adapter: %v", name, fixture.provider.appliedSteps())
			}
		})
	}
}

func TestStaleObservationBlocksBeforeAnyAdapterCall(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	fixture.provider.staleObserve = true
	report, err := fixture.run()
	if !errors.Is(err, ErrOperationPaused) || !errors.Is(err, ErrDrift) {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(fixture.provider.applies) != 0 || report.State != domain.OperationPaused || !report.Resumable {
		t.Fatalf("stale observation reached adapters %v, report %+v", fixture.provider.appliedSteps(), report)
	}
}

func TestLockHeldByAnotherOperationRefuses(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	fixture.store.foreignHolder = true
	_, err := fixture.run()
	if !errors.Is(err, ErrLockHeld) || len(fixture.provider.applies) != 0 {
		t.Fatalf("Execute() error = %v, applies %v", err, fixture.provider.appliedSteps())
	}
}

func TestLockLossStopsAtTheBoundaryWithoutGuessing(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	fixture.provider.failures["k2-control-bucket"] = []error{&lockDropper{fixture: fixture}}
	report, err := fixture.run()
	if !errors.Is(err, ErrOperationPaused) || !errors.Is(err, ErrLockLost) {
		t.Fatalf("Execute() error = %v", err)
	}
	if report.State != domain.OperationPaused || report.PauseReason != pauseReasonLockLost {
		t.Fatalf("report = %+v", report)
	}
	if fixture.provider.hasApplied("k3-bucket-iam") || len(fixture.provider.compensates) != 0 {
		t.Fatalf("engine continued after lock loss: %v", fixture.provider.appliedSteps())
	}
}

// lockDropper is a transient failure that also drops the lock generation, so
// the next boundary heartbeat fails exactly like a takeover would.
type lockDropper struct{ fixture *harness }

func (dropper *lockDropper) Error() string { return "step failed: transient (not-occurred)" }
func (dropper *lockDropper) Unwrap() error {
	dropper.fixture.store.refreshFails = true
	return &StepFailure{Class: domain.RetryFailureTransient, Mutation: domain.MutationNotOccurred, Summary: "transient"}
}

func TestBoundedRetryThenSuccess(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	transient := &StepFailure{Class: domain.RetryFailureTransient, Mutation: domain.MutationNotOccurred, Summary: "429"}
	fixture.provider.failures["t1-network"] = []error{transient, transient}
	report, err := fixture.run()
	if err != nil {
		t.Fatalf("Execute() unexpected error: %v", err)
	}
	if !slices.Equal(fixture.provider.sleeps, []time.Duration{5 * time.Second, 10 * time.Second}) {
		t.Fatalf("sleeps = %v", fixture.provider.sleeps)
	}
	for _, step := range report.Steps {
		if step.StepID == "t1-network" && step.Attempts != 3 {
			t.Fatalf("t1 attempts = %d", step.Attempts)
		}
	}
}

func TestUnknownMutationNeverRetriesAndPauses(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	fixture.provider.failures["t2-subnet"] = []error{errors.New("connection reset before response")}
	report, err := fixture.run()
	if !errors.Is(err, ErrOperationPaused) || report.State != domain.OperationPaused || len(fixture.provider.sleeps) != 0 {
		t.Fatalf("Execute() = %+v, %v, sleeps %v", report, err, fixture.provider.sleeps)
	}
	if fixture.provider.hasApplied("t3-nat") || len(fixture.provider.compensates) != 0 {
		t.Fatalf("unknown mutation continued or rolled back: %v", fixture.provider.appliedSteps())
	}
	// Resume: the subnet now exists exactly as desired, so rediscovery
	// classifies the unobserved attempt as complete without a second write.
	fixture.provider.present["test-subnet"] = true
	fixture.provider.applied["t2-subnet"] = true
	report, err = fixture.run()
	if err != nil || report.State != domain.OperationComplete {
		t.Fatalf("resume = %+v, %v", report, err)
	}
	if applied := fixture.provider.appliedSteps(); slices.Index(applied, "t2-subnet") != len(applied)-1-slices.Index(slices.Clone(reverse(applied)), "t2-subnet") {
		t.Fatalf("t2 applied twice: %v", applied)
	}
}

func TestResumeAfterCrashAtEveryDurableBoundary(t *testing.T) {
	t.Parallel()
	baseline := newHarness(t)
	if _, err := baseline.run(); err != nil {
		t.Fatalf("baseline Execute() unexpected error: %v", err)
	}
	total := uint64(len(baseline.store.journal))
	for sequence := uint64(1); sequence <= total; sequence++ {
		t.Run(fmt.Sprintf("%02d-%s", sequence, baseline.store.journal[sequence-1].Kind), func(t *testing.T) {
			t.Parallel()
			fixture := newHarness(t)
			fixture.store.crashAtSeq = sequence
			if _, err := fixture.run(); !errors.Is(err, ErrJournalInvalid) {
				t.Fatalf("crash run error = %v", err)
			}
			fixture.clock.now = fixture.clock.Peek().Add(time.Minute)
			report, err := fixture.run()
			if err != nil {
				t.Fatalf("resume Execute() unexpected error: %v (report %+v)", err, report)
			}
			if report.State != domain.OperationComplete || report.BootstrapPhase != isolation.BootstrapPhaseOpen {
				t.Fatalf("resume report = %+v", report)
			}
			applied := fixture.provider.appliedSteps()
			counts := make(map[string]int)
			for _, step := range applied {
				counts[step]++
			}
			for step, count := range counts {
				if count != 1 {
					t.Fatalf("step %s applied %d times across crash and resume", step, count)
				}
			}
		})
	}
}

func TestCompensationTouchesOnlyRecordedResources(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	fixture.provider.present["test-network"] = true
	failure := &StepFailure{Class: domain.RetryFailureTransient, Mutation: domain.MutationNotOccurred, Summary: "quota"}
	fixture.provider.failures["t3-nat"] = []error{failure, failure, failure}
	report, err := fixture.run()
	if !errors.Is(err, ErrOperationCancelled) || report.State != domain.OperationVerifiedRollback {
		t.Fatalf("Execute() = %+v, %v", report, err)
	}
	compensated := fixture.provider.compensated
	for _, forbidden := range []string{"test-network", "audit-bucket", "test-router", "test-nat"} {
		if slices.Contains(compensated, forbidden) {
			t.Fatalf("compensation touched %s: %v", forbidden, compensated)
		}
	}
	for _, expected := range []string{"test-subnet", "control-bucket"} {
		if !slices.Contains(compensated, expected) {
			t.Fatalf("compensation skipped recorded %s: %v", expected, compensated)
		}
	}
	if !report.PointOfNoReturnCrossed || fixture.provider.present["audit-bucket"] != true {
		t.Fatalf("irreversible audit bucket was not preserved: %+v present %v", report, fixture.provider.present)
	}
	for _, authorization := range fixture.provider.compensates {
		if authorization.OperationID != testOperationID || authorization.PlanV1Hash != fixture.plan.Plan().PlanHash {
			t.Fatalf("compensation authorization = %+v", authorization)
		}
	}
}

func TestPointOfNoReturnCrossesOnlyWhenLockMutationObserved(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	failure := &StepFailure{Class: domain.RetryFailureTransient, Mutation: domain.MutationNotOccurred, Summary: "412"}
	fixture.provider.failures["k1-retention-lock"] = []error{failure, failure, failure}
	report, err := fixture.run()
	if !errors.Is(err, ErrOperationPaused) || report.PointOfNoReturnCrossed {
		t.Fatalf("Execute() = %+v, %v", report, err)
	}
	fixture.provider.cancel = true
	report, err = fixture.run()
	if !errors.Is(err, ErrOperationCancelled) || report.State != domain.OperationVerifiedRollback {
		t.Fatalf("cancel after pause = %+v, %v", report, err)
	}
	if !slices.Equal(fixture.provider.compensated, []string{"audit-bucket"}) {
		t.Fatalf("compensated = %v", fixture.provider.compensated)
	}
}

func TestCancellationBeforeAnyMutationCancelsCleanly(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	fixture.provider.cancel = true
	report, err := fixture.run()
	if !errors.Is(err, ErrOperationCancelled) || report.State != domain.OperationCancelled || len(fixture.provider.applies) != 0 {
		t.Fatalf("Execute() = %+v, %v, applies %v", report, err, fixture.provider.appliedSteps())
	}
}

func TestCancellationAfterPointOfNoReturnIsRefused(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	fixture.provider.failures["k2-control-bucket"] = []error{&cancelTrigger{fixture: fixture}}
	report, err := fixture.run()
	if !errors.Is(err, ErrOperationPaused) || report.State != domain.OperationPaused {
		t.Fatalf("Execute() = %+v, %v", report, err)
	}
	if len(fixture.provider.compensates) != 0 || !fixture.provider.present["audit-bucket"] {
		t.Fatalf("cancellation after PONR compensated: %v", fixture.provider.compensated)
	}
}

type cancelTrigger struct{ fixture *harness }

func (trigger *cancelTrigger) Error() string { return "step failed: transient (not-occurred)" }
func (trigger *cancelTrigger) Unwrap() error {
	trigger.fixture.provider.cancel = true
	return &StepFailure{Class: domain.RetryFailureTransient, Mutation: domain.MutationNotOccurred, Summary: "transient"}
}

func TestPendingBlockadeAdmitsOnlyThisEnvelope(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	fixture.provider.gateFails = true
	report, err := fixture.run()
	if !errors.Is(err, ErrOperationPaused) || report.BootstrapPhase != isolation.BootstrapPhasePending || report.TestUsability != isolation.TestUsabilityUnusable {
		t.Fatalf("T8 failure report = %+v, %v", report, err)
	}
	if fixture.store.calls["ReplaceHarnessState"] != 0 {
		t.Fatalf("T8 failure attempted the open transition")
	}
	state := fixture.store.harness.State
	seed, _ := HarnessSeed(fixture.plan, testOperationID, fixture.store.envelope, fixtureApproval(fixture.plan))
	expected := harnessExpectation(seed)
	for _, action := range []isolation.HarnessAction{isolation.HarnessActionIntegrationTest, isolation.HarnessActionDestructiveTest, isolation.HarnessActionUnrelatedMutation} {
		err := isolation.AdmitHarnessAction(state, isolation.HarnessAdmissionRequest{
			Action: action, WorkflowID: bootstrap.WorkflowID, Plan: expected.ApprovedPlan, OperationID: testOperationID,
			BootstrapEnvelopeHash: testEnvelope, StepID: "t1-network", Expected: expected, Now: fixture.clock.Peek(),
		})
		if !errors.Is(err, isolation.ErrHarnessAdmissionDenied) {
			t.Fatalf("%s admitted before T8: %v", action, err)
		}
	}
	err = isolation.AdmitHarnessAction(state, isolation.HarnessAdmissionRequest{
		Action: isolation.HarnessActionBootstrapStep, WorkflowID: bootstrap.WorkflowID, Plan: expected.ApprovedPlan,
		OperationID: "op-00000000000000bb", BootstrapEnvelopeHash: testEnvelope, StepID: "t1-network", Expected: expected, Now: fixture.clock.Peek(),
	})
	if !errors.Is(err, isolation.ErrHarnessAdmissionDenied) {
		t.Fatalf("foreign operation admitted before T8: %v", err)
	}
}

func TestT8TransitionIsCompareAndSwap(t *testing.T) {
	t.Parallel()
	fixture := newHarness(t)
	fixture.store.replaceBumps = true
	report, err := fixture.run()
	if !errors.Is(err, ErrOperationFailed) || report.State != domain.OperationCompleteWithFailedVerification {
		t.Fatalf("Execute() = %+v, %v", report, err)
	}
	if fixture.store.harness.State.BootstrapPhase() != isolation.BootstrapPhasePending {
		t.Fatalf("harness opened despite generation change")
	}
}

func TestGateRefusalsNeverReachAdapters(t *testing.T) {
	t.Parallel()
	t.Run("permission", func(t *testing.T) {
		t.Parallel()
		fixture := newHarness(t)
		fixture.provider.proveDenied = true
		_, err := fixture.run()
		if !errors.Is(err, ErrPermissionRevalidation) || len(fixture.provider.applies) != 0 {
			t.Fatalf("Execute() error = %v, applies %v", err, fixture.provider.appliedSteps())
		}
	})
	t.Run("credential", func(t *testing.T) {
		t.Parallel()
		fixture := newHarness(t)
		fixture.provider.credFails = true
		_, err := fixture.run()
		if !errors.Is(err, ErrOperationPaused) || len(fixture.provider.applies) != 0 {
			t.Fatalf("Execute() error = %v, applies %v", err, fixture.provider.appliedSteps())
		}
	})
	t.Run("conflicting resource", func(t *testing.T) {
		t.Parallel()
		fixture := newHarness(t)
		fixture.provider.conflicting["audit-bucket"] = true
		_, err := fixture.run()
		if !errors.Is(err, ErrDrift) || len(fixture.provider.applies) != 0 {
			t.Fatalf("Execute() error = %v, applies %v", err, fixture.provider.appliedSteps())
		}
	})
}

func TestTamperedSavedPlanIsRejected(t *testing.T) {
	t.Parallel()
	plan := fixturePlan(t)
	canonical, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() unexpected error: %v", err)
	}
	if _, err := bootstrap.ParseCompiledPlan(canonical); err != nil {
		t.Fatalf("ParseCompiledPlan(canonical) unexpected error: %v", err)
	}
	tampered := bytes.Replace(canonical, []byte("ctrldb-test-subnet"), []byte("ctrldb-prod-subnet"), 1)
	if !bytes.Contains(canonical, []byte("ctrldb-test-subnet")) {
		t.Fatalf("fixture plan does not contain the subnet name")
	}
	if _, err := bootstrap.ParseCompiledPlan(tampered); !errors.Is(err, bootstrap.ErrInvalidCompiledPlan) {
		t.Fatalf("tampered plan accepted: %v", err)
	}
}

func TestHarnessFingerprintsAreDerivedFromTheSealedPlan(t *testing.T) {
	t.Parallel()
	plan := fixturePlan(t)
	first, err := HarnessFingerprints(plan)
	if err != nil {
		t.Fatalf("HarnessFingerprints() unexpected error: %v", err)
	}
	second, _ := HarnessFingerprints(plan)
	if first != second || first.Image != plan.DesiredState().ImageDigest[len("sha256:"):] {
		t.Fatalf("fingerprints unstable: %+v vs %+v", first, second)
	}
}

func reverse(values []string) []string {
	result := slices.Clone(values)
	slices.Reverse(result)
	return result
}
