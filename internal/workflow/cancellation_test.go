// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

func TestCancellationQueuesUntilSafeBoundary_TEST_U_PLAN_05(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	request := validCancellationRequest(domain.OperationExecute, domain.MutationUnknown)
	machine := machineAt(t, domain.OperationExecute)
	next, decision, err := controller.Request(machine, request, false)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	if next.Pending() || decision.Action != workflow.CancellationPersist || decision.Target != "" || decision.JournalEntry == nil {
		t.Fatalf("unsafe cancellation decision = %#v, pending=%t", decision, next.Pending())
	}
	if decision.UIState != next.UIState(domain.OperationExecute, false, true) || !strings.Contains(decision.UIState, "durable") {
		t.Fatalf("persistence UI state mismatch: %q / %q", decision.UIState, next.UIState(domain.OperationExecute, false, true))
	}
	entries := validJournal()[:5]
	entries = append(entries, *decision.JournalEntry)
	restored, err := workflow.RestoreCancellationController(entries, request.OperationID, request.PlanID)
	if err != nil || !restored.Pending() {
		t.Fatalf("RestoreCancellationController() = (%#v, %v), want pending", restored, err)
	}

	cleared, decision, err := restored.AtBoundary(machine, true)
	if err != nil {
		t.Fatalf("AtBoundary() returned an error: %v", err)
	}
	if cleared.Pending() || decision.Action != workflow.CancellationRollback || decision.Target != domain.OperationRollback {
		t.Fatalf("mutated boundary decision = %#v, pending=%t", decision, cleared.Pending())
	}
}

func TestCancellationRoutesPreMutationDirectlyToCancelled(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	machine := machineAt(t, domain.OperationLock)
	next, decision, err := controller.Request(
		machine, validCancellationRequest(domain.OperationLock, domain.MutationNotOccurred), true,
	)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	if next.Pending() || decision.Action != workflow.CancellationCancel || decision.Target != domain.OperationCancelled {
		t.Fatalf("pre-mutation decision = %#v, pending=%t", decision, next.Pending())
	}
}

func TestMachineAppliesOnlyStateBoundCancellationDecisions(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	machine := machineAt(t, domain.OperationExecute)
	_, cancelDecision, err := controller.Request(
		machine, validCancellationRequest(domain.OperationExecute, domain.MutationNotOccurred), true,
	)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	if err := machine.ApplyCancellation(cancelDecision); err != nil {
		t.Fatalf("ApplyCancellation() returned an error: %v", err)
	}
	if machine.State() != domain.OperationCancelled {
		t.Fatalf("machine state = %s, want CANCELLED", machine.State())
	}
	if err := machine.ApplyCancellation(cancelDecision); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("second application error = %v, want ErrInvalidCancellation", err)
	}

	machine = machineAt(t, domain.OperationExecute)
	_, rollbackDecision, err := controller.Request(
		machine, validCancellationRequest(domain.OperationExecute, domain.MutationUnknown), true,
	)
	if err != nil {
		t.Fatalf("Request(rollback) returned an error: %v", err)
	}
	if err := machine.ApplyCancellation(rollbackDecision); err != nil {
		t.Fatalf("ApplyCancellation(rollback) returned an error: %v", err)
	}
	if machine.State() != domain.OperationRollback {
		t.Fatalf("machine state = %s, want ROLLBACK", machine.State())
	}

	forged := workflow.CancellationDecision{
		Action: workflow.CancellationCancel,
		Target: domain.OperationCancelled,
	}
	if err := machineAt(t, domain.OperationExecute).ApplyCancellation(forged); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("forged decision error = %v, want ErrInvalidCancellation", err)
	}

	boundMachine := machineAt(t, domain.OperationExecute)
	_, boundDecision, err := controller.Request(
		boundMachine, validCancellationRequest(domain.OperationExecute, domain.MutationNotOccurred), true,
	)
	if err != nil {
		t.Fatalf("Request(bound) returned an error: %v", err)
	}
	if err := machineAt(t, domain.OperationExecute).ApplyCancellation(boundDecision); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("other-machine replay error = %v, want ErrInvalidCancellation", err)
	}
	tamperedDecision := boundDecision
	tamperedDecision.Action = workflow.CancellationRollback
	if err := boundMachine.ApplyCancellation(tamperedDecision); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("action-target mismatch error = %v, want ErrInvalidCancellation", err)
	}
	if err := boundMachine.Transition(domain.OperationPaused); err != nil {
		t.Fatalf("Transition(PAUSED) returned an error: %v", err)
	}
	if err := boundMachine.ApplyCancellation(boundDecision); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("state-drift replay error = %v, want ErrInvalidCancellation", err)
	}
}

func TestCancellationDecisionIsSingleUseAcrossCopies(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	machine := machineAt(t, domain.OperationExecute)
	_, decision, err := controller.Request(
		machine, validCancellationRequest(domain.OperationExecute, domain.MutationNotOccurred), true,
	)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	copyOfDecision := decision

	start := make(chan struct{})
	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for _, candidate := range []workflow.CancellationDecision{decision, copyOfDecision} {
		candidate := candidate
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			results <- machine.ApplyCancellation(candidate)
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	var success, rejected int
	for result := range results {
		if result == nil {
			success++
		} else if errors.Is(result, workflow.ErrInvalidCancellation) {
			rejected++
		} else {
			t.Fatalf("ApplyCancellation() error = %v", result)
		}
	}
	if success != 1 || rejected != 1 || machine.State() != domain.OperationCancelled {
		t.Fatalf("concurrent applications: success=%d rejected=%d state=%s", success, rejected, machine.State())
	}
}

func TestCancellationRequestValidatesIdentityAtSafeBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*workflow.CancellationRequest)
	}{
		{name: "operation id", mutate: func(request *workflow.CancellationRequest) { request.OperationID = "operation-unsafe" }},
		{name: "plan id", mutate: func(request *workflow.CancellationRequest) { request.PlanID = "plan-unsafe" }},
		{name: "sequence", mutate: func(request *workflow.CancellationRequest) { request.Sequence = 0 }},
		{name: "request time", mutate: func(request *workflow.CancellationRequest) { request.RequestedAt = time.Time{} }},
		{name: "request time zone", mutate: func(request *workflow.CancellationRequest) {
			request.RequestedAt = time.Date(2026, 9, 3, 12, 0, 5, 0, time.FixedZone("offset", 3600))
		}},
		{name: "step id", mutate: func(request *workflow.CancellationRequest) { request.CurrentStepID = "unsafe/id" }},
		{name: "state mismatch", mutate: func(request *workflow.CancellationRequest) { request.OperationState = domain.OperationLock }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validCancellationRequest(domain.OperationExecute, domain.MutationNotOccurred)
			test.mutate(&request)
			var controller workflow.CancellationController
			if _, _, err := controller.Request(machineAt(t, domain.OperationExecute), request, true); !errors.Is(err, workflow.ErrInvalidCancellation) {
				t.Fatalf("Request() error = %v, want ErrInvalidCancellation", err)
			}
		})
	}
}

func TestCancellationFailsClosedOnUnsafeRoutes(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	if _, _, err := controller.Request(
		machineAt(t, domain.OperationComplete), validCancellationRequest(domain.OperationComplete, domain.MutationNotOccurred), true,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("terminal Request() error = %v, want ErrInvalidCancellation", err)
	}
	if _, decision, err := controller.Request(
		machineAt(t, domain.OperationExecute), validCancellationRequest(domain.OperationExecute, domain.MutationNotOccurred), true,
	); err != nil || decision.Target != domain.OperationCancelled {
		t.Fatalf("EXECUTE pre-mutation cancellation = (%#v, %v), want CANCELLED", decision, err)
	}
	if _, _, err := controller.Request(
		machineAt(t, domain.OperationLock), validCancellationRequest(domain.OperationLock, domain.MutationOccurred), true,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("LOCK rollback error = %v, want ErrInvalidCancellation", err)
	}
	if _, _, err := controller.Request(
		machineAt(t, domain.OperationDocument), validCancellationRequest(domain.OperationDocument, domain.MutationNotOccurred), false,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("unreachable queued cancellation error = %v, want ErrInvalidCancellation", err)
	}
	if _, _, err := controller.AtBoundary(machineAt(t, domain.OperationDocument), false); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("unreachable boundary cancellation error = %v, want ErrInvalidCancellation", err)
	}
	if state := controller.UIState(domain.OperationDocument, true, false); !strings.Contains(state, "unavailable") {
		t.Fatalf("DOCUMENT UI state = %q, want unavailable", state)
	}
	if _, _, err := controller.Request(
		machineAt(t, domain.OperationVerify), validCancellationRequest(domain.OperationVerify, domain.MutationNotOccurred), false,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("VERIFY pre-mutation queued cancellation error = %v, want ErrInvalidCancellation", err)
	}
	if state := controller.UIState(domain.OperationVerify, false, false); !strings.Contains(state, "unavailable") {
		t.Fatalf("VERIFY pre-mutation UI state = %q, want unavailable", state)
	}
}

func TestCancellationRestoreRejectsAmbiguousOrMismatchedEvidence(t *testing.T) {
	t.Parallel()

	request := validCancellationRequest(domain.OperationExecute, domain.MutationUnknown)
	var controller workflow.CancellationController
	_, decision, err := controller.Request(machineAt(t, domain.OperationExecute), request, false)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	entries := append(validJournal()[:5], *decision.JournalEntry)
	if _, err := workflow.RestoreCancellationController(entries, request.OperationID, "plan-fedcba9876543210"); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("mismatched restore error = %v, want ErrInvalidCancellation", err)
	}

	duplicate := *decision.JournalEntry
	cancellationCopy := *duplicate.Cancellation
	duplicate.Cancellation = &cancellationCopy
	duplicate.Sequence++
	duplicate.RecordedAt = duplicate.RecordedAt.Add(time.Second)
	duplicate.Cancellation.RequestedAt = duplicate.RecordedAt
	entries = append(entries, duplicate)
	if _, err := workflow.RestoreCancellationController(entries, request.OperationID, request.PlanID); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("ambiguous restore error = %v, want ErrInvalidCancellation", err)
	}
}

func TestCancellationJournalMustBeHonoredAtFirstCompatibleBoundary(t *testing.T) {
	t.Parallel()

	request := validCancellationRequest(domain.OperationExecute, domain.MutationUnknown)
	var controller workflow.CancellationController
	_, decision, err := controller.Request(machineAt(t, domain.OperationExecute), request, false)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	entries := append(validJournal()[:5], *decision.JournalEntry)
	skipped := validTransitionEntry(7, domain.OperationVerify)
	skipped.RecordedAt = request.RequestedAt.Add(time.Second)
	if err := workflow.ValidateJournal(append(entries, skipped)); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("skipped cancellation error = %v, want ErrInvalidJournalStream", err)
	}
	rollback := validTransitionEntry(7, domain.OperationRollback)
	rollback.RecordedAt = request.RequestedAt.Add(time.Second)
	if err := workflow.ValidateJournal(append(entries, rollback)); err != nil {
		t.Fatalf("persisted rollback route returned an error: %v", err)
	}
}

func TestCancellationJournalBindsInFlightStepAndEscalatesNewMutation(t *testing.T) {
	t.Parallel()

	request := validCancellationRequest(domain.OperationExecute, domain.MutationNotOccurred)
	request.CurrentStepID = "check-health"
	var controller workflow.CancellationController
	_, decision, err := controller.Request(machineAt(t, domain.OperationExecute), request, false)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	entries := append(validJournal()[:5], *decision.JournalEntry)
	step := validStepEntry()
	step.Sequence = 7
	step.Step.StartedAt = entries[4].RecordedAt
	endedAt := request.RequestedAt.Add(500 * time.Millisecond)
	step.Step.EndedAt = &endedAt
	step.RecordedAt = request.RequestedAt.Add(time.Second)
	step.Step.MutationOccurred = true
	entries = append(entries, step)
	rollback := validTransitionEntry(8, domain.OperationRollback)
	rollback.RecordedAt = step.RecordedAt.Add(time.Second)
	entries = append(entries, rollback)
	if err := workflow.ValidateJournal(entries); err != nil {
		t.Fatalf("mutation escalation journal returned an error: %v", err)
	}

	restored, err := workflow.RestoreCancellationController(entries[:len(entries)-1], request.OperationID, request.PlanID)
	if err != nil {
		t.Fatalf("RestoreCancellationController() returned an error: %v", err)
	}
	_, route, err := restored.AtBoundary(machineAt(t, domain.OperationExecute), true)
	if err != nil || route.Target != domain.OperationRollback {
		t.Fatalf("escalated boundary route = (%#v, %v), want ROLLBACK", route, err)
	}

	wrongStep := append([]domain.JournalEntry(nil), entries[:6]...)
	wrong := step
	wrong.Step = new(domain.JournalStep)
	*wrong.Step = *step.Step
	wrong.Step.ID = "different-step"
	wrongStep = append(wrongStep, wrong)
	if err := workflow.ValidateJournal(wrongStep); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("mismatched in-flight step error = %v, want ErrInvalidJournalStream", err)
	}
}

func TestCancellationJournalRequiresInFlightStepStartAtOrBeforeRequest(t *testing.T) {
	t.Parallel()

	request := validCancellationRequest(domain.OperationExecute, domain.MutationNotOccurred)
	request.CurrentStepID = "check-health"
	var controller workflow.CancellationController
	_, decision, err := controller.Request(machineAt(t, domain.OperationExecute), request, false)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	makeEntries := func(startedAt time.Time) []domain.JournalEntry {
		entries := append(validJournal()[:5], *decision.JournalEntry)
		step := validStepEntry()
		step.Sequence = 7
		step.Step.StartedAt = startedAt
		endedAt := request.RequestedAt.Add(time.Second)
		step.Step.EndedAt = &endedAt
		step.RecordedAt = endedAt

		return append(entries, step)
	}

	if err := workflow.ValidateJournal(makeEntries(request.RequestedAt)); err != nil {
		t.Fatalf("exact request-time step start returned an error: %v", err)
	}
	if err := workflow.ValidateJournal(makeEntries(request.RequestedAt.Add(time.Nanosecond))); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("post-request step start error = %v, want ErrInvalidJournalStream", err)
	}
}

func validCancellationRequest(state domain.OperationState, mutation domain.MutationObservation) workflow.CancellationRequest {
	return workflow.CancellationRequest{
		OperationID:         "op-0123456789abcdef",
		PlanID:              "plan-0123456789abcdef",
		Sequence:            6,
		RequestedAt:         time.Date(2026, 9, 3, 12, 0, 5, 0, time.UTC),
		OperationState:      state,
		CurrentStepID:       "stop-instance",
		MutationObservation: mutation,
	}
}
