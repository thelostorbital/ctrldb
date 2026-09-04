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
	request := validCancellationRequest()
	machine := machineAt(t, domain.OperationExecute)
	contract := cancellationContract(t, "stop-instance", false)
	base := validJournal()[:5]
	next, decision, err := controller.Request(machine, request, contract, base)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	if next.Pending() || decision.Action != workflow.CancellationPersist || decision.Target != "" || decision.JournalEntry == nil {
		t.Fatalf("unsafe cancellation decision = %#v, pending=%t", decision, next.Pending())
	}
	if decision.UIState != next.UIState(domain.OperationExecute, false, true) || !strings.Contains(decision.UIState, "durable") {
		t.Fatalf("persistence UI state mismatch: %q / %q", decision.UIState, next.UIState(domain.OperationExecute, false, true))
	}
	entries := append([]domain.JournalEntry(nil), base...)
	entries = append(entries, *decision.JournalEntry)
	restored, err := workflow.RestoreCancellationController(entries, request.OperationID, request.PlanID, contract)
	if err != nil || !restored.Pending() {
		t.Fatalf("RestoreCancellationController() = (%#v, %v), want pending", restored, err)
	}
	if _, _, err := restored.AtBoundary(machine, contract, entries); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("AtBoundary() without durable step completion error = %v, want ErrInvalidCancellation", err)
	}

	step := cancellationStepEntry("stop-instance", 7, request.RequestedAt, true)
	entries = append(entries, step)
	cleared, decision, err := restored.AtBoundary(machine, contract, entries)
	if err != nil {
		t.Fatalf("AtBoundary() returned an error: %v", err)
	}
	if cleared.Pending() || decision.Action != workflow.CancellationRollback || decision.Target != domain.OperationRollback {
		t.Fatalf("mutated boundary decision = %#v, pending=%t", decision, cleared.Pending())
	}
}

func TestCancellationRoutesToCancelledOnlyAfterDurableNonMutationBoundary(t *testing.T) {
	t.Parallel()

	request := validCancellationRequest()
	contract := cancellationContract(t, "stop-instance", true)
	machine := machineAt(t, domain.OperationExecute)
	base := validJournal()[:5]
	var controller workflow.CancellationController
	_, persist, err := controller.Request(machine, request, contract, base)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	entries := append(append([]domain.JournalEntry(nil), base...), *persist.JournalEntry)
	restored, err := workflow.RestoreCancellationController(entries, request.OperationID, request.PlanID, contract)
	if err != nil {
		t.Fatalf("RestoreCancellationController() returned an error: %v", err)
	}
	entries = append(entries, cancellationStepEntry("stop-instance", 7, request.RequestedAt, false))
	cleared, decision, err := restored.AtBoundary(machine, contract, entries)
	if err != nil {
		t.Fatalf("AtBoundary() returned an error: %v", err)
	}
	if cleared.Pending() || decision.Action != workflow.CancellationCancel || decision.Target != domain.OperationCancelled {
		t.Fatalf("non-mutating boundary decision = %#v, pending=%t", decision, cleared.Pending())
	}
	if err := machine.ApplyCancellation(decision); err != nil {
		t.Fatalf("ApplyCancellation() returned an error: %v", err)
	}
}

func TestCancellationRoutesPreMutationDirectlyToCancelled(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	machine := machineAt(t, domain.OperationLock)
	next, decision, err := controller.Request(machine, validCancellationRequest(), domain.ExecutionContract{}, nil)
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
	machine := machineAt(t, domain.OperationLock)
	_, cancelDecision, err := controller.Request(machine, validCancellationRequest(), domain.ExecutionContract{}, nil)
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

	machine = machineAt(t, domain.OperationPaused)
	contract := cancellationContract(t, "stop-instance", false)
	journal := pausedCancellationJournal(true)
	request := validCancellationRequest()
	request.Sequence = uint64(len(journal) + 1)
	request.RequestedAt = journal[len(journal)-1].RecordedAt.Add(time.Second)
	_, rollbackDecision, err := controller.Request(machine, request, contract, journal)
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

	boundMachine := machineAt(t, domain.OperationLock)
	_, boundDecision, err := controller.Request(boundMachine, validCancellationRequest(), domain.ExecutionContract{}, nil)
	if err != nil {
		t.Fatalf("Request(bound) returned an error: %v", err)
	}
	if err := machineAt(t, domain.OperationLock).ApplyCancellation(boundDecision); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("other-machine replay error = %v, want ErrInvalidCancellation", err)
	}
	tamperedDecision := boundDecision
	tamperedDecision.Action = workflow.CancellationRollback
	if err := boundMachine.ApplyCancellation(tamperedDecision); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("action-target mismatch error = %v, want ErrInvalidCancellation", err)
	}
	if err := boundMachine.Transition(domain.OperationExecute); err != nil {
		t.Fatalf("Transition(EXECUTE) returned an error: %v", err)
	}
	if err := boundMachine.ApplyCancellation(boundDecision); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("state-drift replay error = %v, want ErrInvalidCancellation", err)
	}
}

func TestCancellationDecisionIsSingleUseAcrossCopies(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	machine := machineAt(t, domain.OperationLock)
	_, decision, err := controller.Request(machine, validCancellationRequest(), domain.ExecutionContract{}, nil)
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
		{name: "other operation", mutate: func(request *workflow.CancellationRequest) { request.OperationID = "op-fedcba9876543210" }},
		{name: "other plan", mutate: func(request *workflow.CancellationRequest) { request.PlanID = "plan-fedcba9876543210" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validCancellationRequest()
			test.mutate(&request)
			var controller workflow.CancellationController
			if _, _, err := controller.Request(
				machineAt(t, domain.OperationLock), request, domain.ExecutionContract{}, nil,
			); !errors.Is(err, workflow.ErrInvalidCancellation) {
				t.Fatalf("Request() error = %v, want ErrInvalidCancellation", err)
			}
		})
	}
}

func TestCancellationFailsClosedOnUnsafeRoutes(t *testing.T) {
	t.Parallel()

	var controller workflow.CancellationController
	if _, _, err := controller.Request(
		machineAt(t, domain.OperationComplete), validCancellationRequest(), domain.ExecutionContract{}, nil,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("terminal Request() error = %v, want ErrInvalidCancellation", err)
	}
	request := validCancellationRequest()
	contract := cancellationContract(t, "stop-instance", true)
	if _, decision, err := controller.Request(
		machineAt(t, domain.OperationExecute), request, contract, validJournal()[:5],
	); err != nil || decision.Action != workflow.CancellationPersist || decision.Target != "" {
		t.Fatalf("EXECUTE cancellation = (%#v, %v), want durable persistence without authorization", decision, err)
	} else if applyErr := machineAt(t, domain.OperationExecute).ApplyCancellation(decision); !errors.Is(applyErr, workflow.ErrInvalidCancellation) {
		t.Fatalf("asserted safe/no-mutation request minted authorization: %v", applyErr)
	}
	if _, _, err := controller.Request(
		machineAt(t, domain.OperationDocument), validCancellationRequest(), domain.ExecutionContract{}, nil,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("unreachable queued cancellation error = %v, want ErrInvalidCancellation", err)
	}
	if _, _, err := controller.AtBoundary(
		machineAt(t, domain.OperationDocument), domain.ExecutionContract{}, nil,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("unreachable boundary cancellation error = %v, want ErrInvalidCancellation", err)
	}
	if state := controller.UIState(domain.OperationDocument, true, false); !strings.Contains(state, "unavailable") {
		t.Fatalf("DOCUMENT UI state = %q, want unavailable", state)
	}
	if _, _, err := controller.Request(
		machineAt(t, domain.OperationVerify), validCancellationRequest(), domain.ExecutionContract{}, nil,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("VERIFY pre-mutation queued cancellation error = %v, want ErrInvalidCancellation", err)
	}
	if state := controller.UIState(domain.OperationVerify, false, false); !strings.Contains(state, "unavailable") {
		t.Fatalf("VERIFY pre-mutation UI state = %q, want unavailable", state)
	}
}

func TestCancellationRestoreRejectsAmbiguousOrMismatchedEvidence(t *testing.T) {
	t.Parallel()

	request := validCancellationRequest()
	contract := cancellationContract(t, "stop-instance", false)
	base := validJournal()[:5]
	var controller workflow.CancellationController
	_, decision, err := controller.Request(machineAt(t, domain.OperationExecute), request, contract, base)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	entries := append(append([]domain.JournalEntry(nil), base...), *decision.JournalEntry)
	if _, err := workflow.RestoreCancellationController(
		entries, request.OperationID, "plan-fedcba9876543210", contract,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("mismatched restore error = %v, want ErrInvalidCancellation", err)
	}
	changedContract := cancellationContract(t, "stop-instance", true)
	restored, err := workflow.RestoreCancellationController(entries, request.OperationID, request.PlanID, contract)
	if err != nil {
		t.Fatalf("RestoreCancellationController() returned an error: %v", err)
	}
	entriesWithBoundary := append(
		append([]domain.JournalEntry(nil), entries...),
		cancellationStepEntry("stop-instance", 7, request.RequestedAt, false),
	)
	if _, _, err := restored.AtBoundary(
		machineAt(t, domain.OperationExecute), changedContract, entriesWithBoundary,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("changed execution contract error = %v, want ErrInvalidCancellation", err)
	}

	duplicate := *decision.JournalEntry
	cancellationCopy := *duplicate.Cancellation
	duplicate.Cancellation = &cancellationCopy
	duplicate.Sequence++
	duplicate.RecordedAt = duplicate.RecordedAt.Add(time.Second)
	duplicate.Cancellation.RequestedAt = duplicate.RecordedAt
	entries = append(entries, duplicate)
	if _, err := workflow.RestoreCancellationController(
		entries, request.OperationID, request.PlanID, contract,
	); !errors.Is(err, workflow.ErrInvalidCancellation) {
		t.Fatalf("ambiguous restore error = %v, want ErrInvalidCancellation", err)
	}
}

func TestRestoredCancellationCannotRouteAnotherOperationMachine(t *testing.T) {
	t.Parallel()

	request := validCancellationRequest()
	contract := cancellationContract(t, "stop-instance", false)
	base := validJournal()[:5]
	var controller workflow.CancellationController
	_, decision, err := controller.Request(machineAt(t, domain.OperationExecute), request, contract, base)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	entries := append(append([]domain.JournalEntry(nil), base...), *decision.JournalEntry)
	restored, err := workflow.RestoreCancellationController(entries, request.OperationID, request.PlanID, contract)
	if err != nil {
		t.Fatalf("RestoreCancellationController() returned an error: %v", err)
	}

	for _, binding := range []struct {
		operationID string
		planID      string
	}{
		{operationID: "op-fedcba9876543210", planID: request.PlanID},
		{operationID: request.OperationID, planID: "plan-fedcba9876543210"},
	} {
		machine, restoreErr := workflow.RestoreMachine(binding.operationID, binding.planID, domain.OperationExecute)
		if restoreErr != nil {
			t.Fatalf("RestoreMachine() returned an error: %v", restoreErr)
		}
		if _, _, routeErr := restored.AtBoundary(machine, contract, entries); !errors.Is(routeErr, workflow.ErrInvalidCancellation) {
			t.Fatalf("AtBoundary(other binding) error = %v, want ErrInvalidCancellation", routeErr)
		}
	}
}

func TestCancellationJournalMustBeHonoredAtFirstCompatibleBoundary(t *testing.T) {
	t.Parallel()

	request := validCancellationRequest()
	contract := cancellationContract(t, "stop-instance", false)
	base := validJournal()[:5]
	var controller workflow.CancellationController
	_, decision, err := controller.Request(machineAt(t, domain.OperationExecute), request, contract, base)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	entries := append(append([]domain.JournalEntry(nil), base...), *decision.JournalEntry)
	skipped := validTransitionEntry(7, domain.OperationVerify)
	skipped.RecordedAt = request.RequestedAt.Add(time.Second)
	if err := workflow.ValidateJournal(append(entries, skipped)); !errors.Is(err, workflow.ErrInvalidJournalStream) {
		t.Fatalf("skipped cancellation error = %v, want ErrInvalidJournalStream", err)
	}
	step := cancellationStepEntry("stop-instance", 7, request.RequestedAt, true)
	entries = append(entries, step)
	rollback := validTransitionEntry(8, domain.OperationRollback)
	rollback.RecordedAt = step.RecordedAt.Add(time.Second)
	if err := workflow.ValidateJournal(append(entries, rollback)); err != nil {
		t.Fatalf("persisted rollback route returned an error: %v", err)
	}
}

func TestCancellationJournalBindsInFlightStepAndEscalatesNewMutation(t *testing.T) {
	t.Parallel()

	request := validCancellationRequest()
	contract := cancellationContract(t, "check-health", false)
	base := validJournal()[:5]
	var controller workflow.CancellationController
	_, decision, err := controller.Request(machineAt(t, domain.OperationExecute), request, contract, base)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	entries := append(append([]domain.JournalEntry(nil), base...), *decision.JournalEntry)
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

	restored, err := workflow.RestoreCancellationController(
		entries[:len(entries)-1], request.OperationID, request.PlanID, contract,
	)
	if err != nil {
		t.Fatalf("RestoreCancellationController() returned an error: %v", err)
	}
	_, route, err := restored.AtBoundary(machineAt(t, domain.OperationExecute), contract, entries[:len(entries)-1])
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

	request := validCancellationRequest()
	contract := cancellationContract(t, "check-health", false)
	base := validJournal()[:5]
	var controller workflow.CancellationController
	_, decision, err := controller.Request(machineAt(t, domain.OperationExecute), request, contract, base)
	if err != nil {
		t.Fatalf("Request() returned an error: %v", err)
	}
	makeEntries := func(startedAt time.Time) []domain.JournalEntry {
		entries := append(append([]domain.JournalEntry(nil), base...), *decision.JournalEntry)
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

func validCancellationRequest() workflow.CancellationRequest {
	return workflow.CancellationRequest{
		OperationID: "op-0123456789abcdef",
		PlanID:      "plan-0123456789abcdef",
		Sequence:    6,
		RequestedAt: time.Date(2026, 9, 3, 12, 0, 5, 0, time.UTC),
	}
}

func cancellationContract(t *testing.T, stepID string, cancelSafe bool) domain.ExecutionContract {
	t.Helper()
	step := validDefinitionStep()
	step.ID = stepID
	step.CancelSafe = cancelSafe

	return retryContract(t, step)
}

func cancellationStepEntry(
	stepID string,
	sequence uint64,
	requestedAt time.Time,
	mutationOccurred bool,
) domain.JournalEntry {
	entry := validStepEntry()
	entry.Sequence = sequence
	entry.Step.ID = stepID
	entry.Step.StartedAt = requestedAt.Add(-time.Second)
	endedAt := requestedAt.Add(time.Second)
	entry.Step.EndedAt = &endedAt
	entry.Step.MutationOccurred = mutationOccurred
	entry.RecordedAt = endedAt

	return entry
}

func pausedCancellationJournal(mutationOccurred bool) []domain.JournalEntry {
	entries := append([]domain.JournalEntry(nil), validJournal()[:5]...)
	pause := validPausedEntry()
	pause.Sequence = 6
	pause.RecordedAt = entries[4].RecordedAt.Add(time.Second)
	pause.Pause.PausedAt = pause.RecordedAt
	pause.Pause.ResumeBy = pause.RecordedAt.Add(time.Hour)
	pause.Pause.MutationOccurred = mutationOccurred

	return append(entries, pause)
}
