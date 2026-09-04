// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

// ErrInvalidCancellation is returned when a cancellation decision cannot be
// represented safely by the operation state machine.
var ErrInvalidCancellation = errors.New("invalid cancellation decision")

// CancellationAction is the pure engine action chosen for a request.
type CancellationAction string

const (
	CancellationNone     CancellationAction = "none"
	CancellationPersist  CancellationAction = "persist-request"
	CancellationCancel   CancellationAction = "cancel"
	CancellationRollback CancellationAction = "rollback"
)

const (
	cancellationAvailableUI   = "Cancellation is available at this safe boundary."
	cancellationUnavailableUI = "Cancellation requires a durable request before the next safe boundary."
	cancellationNoRouteUI     = "Cancellation is unavailable in this operation state."
	cancellationQueuedUI      = "Cancellation queued; operation will stop at the next safe boundary."
	cancellationCancelUI      = "Cancellation accepted; no mutation may have occurred."
	cancellationRollbackUI    = "Cancellation accepted; rollback and independent verification are required."
)

// CancellationController is durable request state. Methods return the next
// value and a decision; the transition capability in a routed decision is a
// shared one-shot value across all decision copies.
type CancellationController struct {
	queued  bool
	target  domain.OperationState
	binding cancellationBinding
}

type cancellationBinding struct {
	operationID  string
	planID       string
	contractHash string
	sequence     uint64
	requestedAt  time.Time
	stepID       string
	cancelSafe   bool
}

// CancellationRequest contains the complete data needed to construct the
// durable journal record for a request made during an unsafe in-flight step.
type CancellationRequest struct {
	OperationID string
	PlanID      string
	Sequence    uint64
	RequestedAt time.Time
}

// CancellationDecision tells the engine whether to queue or transition.
type CancellationDecision struct {
	Action        CancellationAction
	Target        domain.OperationState
	JournalEntry  *domain.JournalEntry
	UIState       string
	authorization *cancellationAuthorization
}

type cancellationAuthorization struct {
	machine    *Machine
	generation uint64
	from       domain.OperationState
	target     domain.OperationState
	binding    cancellationBinding
	used       atomic.Bool
}

// Pending reports whether a cancellation waits for a safe boundary.
func (controller CancellationController) Pending() bool { return controller.queued }

// UIState returns the stable operator-facing state for the current boundary.
func (controller CancellationController) UIState(current domain.OperationState, cancelSafe, mutationMayHaveOccurred bool) string {
	target := cancellationTarget(mutationMayHaveOccurred)
	if controller.queued && controller.target == domain.OperationRollback {
		target = domain.OperationRollback
	}
	if !current.Valid() || current.Terminal() ||
		(cancelSafe && !CanTransition(current, target)) ||
		(!cancelSafe && !cancellationRouteReachable(current, target)) {
		return cancellationNoRouteUI
	}
	if controller.queued {
		return cancellationQueuedUI
	}
	if !cancelSafe {
		return cancellationUnavailableUI
	}

	return cancellationAvailableUI
}

// Request returns a durable record to persist during unsafe in-flight work or
// immediately routes a safe boundary according to observed mutation state.
func (controller CancellationController) Request(
	machine *Machine,
	request CancellationRequest,
	contract domain.ExecutionContract,
	entries []domain.JournalEntry,
) (CancellationController, CancellationDecision, error) {
	if machine == nil {
		return controller, CancellationDecision{}, fmt.Errorf("%w: nil machine", ErrInvalidCancellation)
	}
	current := machine.State()
	if machine.operationID != request.OperationID || machine.planID != request.PlanID {
		return controller, CancellationDecision{}, fmt.Errorf("%w: request does not match machine binding", ErrInvalidCancellation)
	}
	if err := validateCancellationRequest(request); err != nil {
		return controller, CancellationDecision{}, err
	}
	if controller.queued {
		return controller, CancellationDecision{}, fmt.Errorf("%w: cancellation request already recorded", ErrInvalidCancellation)
	}
	if !current.Valid() || current.Terminal() {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q cannot accept cancellation", ErrInvalidCancellation, current)
	}
	binding := cancellationBinding{
		operationID: request.OperationID, planID: request.PlanID,
		contractHash: contract.Digest(), sequence: request.Sequence, requestedAt: request.RequestedAt,
	}
	if cancellationStateIsStructurallyPreMutation(current) {
		return routeCancellationTo(controller, machine, domain.OperationCancelled, binding)
	}

	step, observation, err := cancellationContext(machine, contract, entries, request)
	if err != nil {
		return controller, CancellationDecision{}, err
	}
	binding.stepID = step.ID
	binding.cancelSafe = step.CancelSafe
	if observation != domain.MutationNotOccurred && contract.RollbackBoundary() == "none" {
		return controller, CancellationDecision{}, fmt.Errorf(
			"%w: execution contract has no rollback boundary", ErrInvalidCancellation,
		)
	}
	if current == domain.OperationPaused {
		return routeCancellation(controller, machine, observation != domain.MutationNotOccurred, binding)
	}
	if current != domain.OperationProtect && current != domain.OperationExecute {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q has no safe cancellation route", ErrInvalidCancellation, current)
	}

	entry := cancellationJournalEntry(request, current, step.ID, contract.Digest(), observation)
	stream := append(append([]domain.JournalEntry(nil), entries...), entry)
	if err := ValidateJournal(stream); err != nil {
		return controller, CancellationDecision{}, fmt.Errorf("%w: request does not extend the durable journal", ErrInvalidCancellation)
	}

	return controller, CancellationDecision{
		Action:       CancellationPersist,
		JournalEntry: &entry,
		UIState:      cancellationUnavailableUI,
	}, nil
}

// AtBoundary honours a queued request. With no queued request it produces no
// transition and leaves the controller unchanged.
func (controller CancellationController) AtBoundary(
	machine *Machine,
	contract domain.ExecutionContract,
	entries []domain.JournalEntry,
) (CancellationController, CancellationDecision, error) {
	if machine == nil {
		return controller, CancellationDecision{}, fmt.Errorf("%w: nil machine", ErrInvalidCancellation)
	}
	current := machine.State()
	if !controller.binding.matchesMachine(machine) && controller.queued {
		return controller, CancellationDecision{}, fmt.Errorf("%w: queued request does not match machine binding", ErrInvalidCancellation)
	}
	if !current.Valid() || current.Terminal() {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q cannot reach a cancellation boundary", ErrInvalidCancellation, current)
	}
	if !controller.queued {
		return controller, CancellationDecision{}, fmt.Errorf("%w: no durable cancellation request", ErrInvalidCancellation)
	}
	if len(entries) == 0 || entries[len(entries)-1].OperationState != current {
		return controller, CancellationDecision{}, fmt.Errorf(
			"%w: journal state does not match the current machine boundary", ErrInvalidCancellation,
		)
	}
	fresh, err := RestoreCancellationController(entries, machine.operationID, machine.planID, contract)
	if err != nil || !fresh.queued || fresh.binding != controller.binding {
		return controller, CancellationDecision{}, fmt.Errorf("%w: durable cancellation request changed", ErrInvalidCancellation)
	}
	if !cancellationBoundaryRecorded(entries, controller.binding) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: no durable safe boundary after request", ErrInvalidCancellation)
	}
	if !CanTransition(current, fresh.target) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: state %q has no safe cancellation route", ErrInvalidCancellation, current)
	}

	return routeCancellationTo(controller, machine, fresh.target, fresh.binding)
}

// ApplyCancellation advances machine only for a decision produced for its
// exact current state by CancellationController.
func (machine *Machine) ApplyCancellation(decision CancellationDecision) error {
	if machine == nil || decision.authorization == nil || decision.authorization.machine != machine ||
		decision.authorization.target != decision.Target ||
		!decision.authorization.binding.matchesMachine(machine) ||
		decision.authorization.binding.sequence == 0 || decision.authorization.binding.requestedAt.IsZero() ||
		!cancellationActionMatchesTarget(decision.Action, decision.Target) {
		return fmt.Errorf("%w: missing or mismatched authorization", ErrInvalidCancellation)
	}
	if !decision.authorization.used.CompareAndSwap(false, true) {
		return fmt.Errorf("%w: cancellation authorization already consumed", ErrInvalidCancellation)
	}
	if decision.authorization.generation != machine.generation || decision.authorization.from != machine.State() {
		return fmt.Errorf("%w: cancellation boundary changed", ErrInvalidCancellation)
	}

	return machine.transition(decision.Target, true)
}

func (binding cancellationBinding) matchesMachine(machine *Machine) bool {
	return machine != nil && binding.operationID == machine.operationID && binding.planID == machine.planID
}

func cancellationActionMatchesTarget(action CancellationAction, target domain.OperationState) bool {
	return action == CancellationCancel && target == domain.OperationCancelled ||
		action == CancellationRollback && target == domain.OperationRollback
}

func routeCancellation(
	controller CancellationController,
	machine *Machine,
	mutationMayHaveOccurred bool,
	binding cancellationBinding,
) (CancellationController, CancellationDecision, error) {
	return routeCancellationTo(controller, machine, cancellationTarget(mutationMayHaveOccurred), binding)
}

func routeCancellationTo(
	controller CancellationController,
	machine *Machine,
	target domain.OperationState,
	binding cancellationBinding,
) (CancellationController, CancellationDecision, error) {
	current := machine.State()
	action := CancellationCancel
	uiState := cancellationCancelUI
	if target == domain.OperationRollback {
		action = CancellationRollback
		uiState = cancellationRollbackUI
	}
	if !CanTransition(current, target) {
		return controller, CancellationDecision{}, fmt.Errorf("%w: %s cannot route to %s", ErrInvalidCancellation, current, target)
	}

	return CancellationController{}, CancellationDecision{
		Action:  action,
		Target:  target,
		UIState: uiState,
		authorization: &cancellationAuthorization{
			machine: machine, generation: machine.generation, from: current, target: target, binding: binding,
		},
	}, nil
}

// RestoreCancellationController validates a complete journal and reconstructs
// only a cancellation request that was durably recorded but not yet routed.
func RestoreCancellationController(
	entries []domain.JournalEntry,
	operationID, planID string,
	contract domain.ExecutionContract,
) (CancellationController, error) {
	if err := ValidateJournal(entries); err != nil {
		return CancellationController{}, fmt.Errorf("%w: invalid journal", ErrInvalidCancellation)
	}
	if len(entries) == 0 || entries[0].OperationID != operationID || entries[0].PlanID != planID {
		return CancellationController{}, fmt.Errorf("%w: journal binding mismatch", ErrInvalidCancellation)
	}
	if !contractDigestPattern.MatchString(contract.Digest()) {
		return CancellationController{}, fmt.Errorf("%w: invalid execution contract", ErrInvalidCancellation)
	}
	if pointOfNoReturnReached(contract, entries) {
		return CancellationController{}, fmt.Errorf("%w: point of no return has been reached", ErrInvalidCancellation)
	}

	var target domain.OperationState
	var binding cancellationBinding
	for _, entry := range entries {
		if entry.Kind == domain.JournalEntryStep {
			if _, ok := executionContractStep(contract, entry.Step.ID); !ok {
				return CancellationController{}, fmt.Errorf("%w: journal step is outside the execution contract", ErrInvalidCancellation)
			}
		}
		if entry.Kind == domain.JournalEntryCancellationRequest {
			if entry.Cancellation.ExecutionContractHash != contract.Digest() {
				return CancellationController{}, fmt.Errorf(
					"%w: cancellation request does not match the execution contract", ErrInvalidCancellation,
				)
			}
			step, ok := executionContractStep(contract, entry.Cancellation.CurrentStepID)
			if !ok {
				return CancellationController{}, fmt.Errorf("%w: cancellation step is outside the execution contract", ErrInvalidCancellation)
			}
			target = entry.Cancellation.RequiredRoute
			binding = cancellationBinding{
				operationID:  entry.OperationID,
				planID:       entry.PlanID,
				contractHash: entry.Cancellation.ExecutionContractHash,
				sequence:     entry.Sequence,
				requestedAt:  entry.Cancellation.RequestedAt,
				stepID:       step.ID,
				cancelSafe:   step.CancelSafe,
			}
			continue
		}
		if target != "" && entry.Kind == domain.JournalEntryStep &&
			(entry.Step.MutationOccurred || entry.Step.Outcome == domain.StepUnknown) {
			target = domain.OperationRollback
		}
		if target != "" && entry.Kind == domain.JournalEntryTransition && entry.OperationState == target {
			target = ""
			binding = cancellationBinding{}
		}
	}
	if target == domain.OperationRollback && contract.RollbackBoundary() == "none" {
		return CancellationController{}, fmt.Errorf("%w: execution contract has no rollback boundary", ErrInvalidCancellation)
	}

	return CancellationController{queued: target != "", target: target, binding: binding}, nil
}

func validateCancellationRequest(request CancellationRequest) error {
	if !operationIDPattern.MatchString(request.OperationID) || !journalPlanIDPattern.MatchString(request.PlanID) ||
		request.Sequence == 0 || request.RequestedAt.IsZero() {
		return fmt.Errorf("%w: invalid request identity", ErrInvalidCancellation)
	}
	_, offset := request.RequestedAt.Zone()
	if offset != 0 {
		return fmt.Errorf("%w: invalid request time", ErrInvalidCancellation)
	}

	return nil
}

func cancellationContext(
	machine *Machine,
	contract domain.ExecutionContract,
	entries []domain.JournalEntry,
	request CancellationRequest,
) (domain.ExecutionStepContract, domain.MutationObservation, error) {
	if err := ValidateJournal(entries); err != nil || len(entries) == 0 {
		return domain.ExecutionStepContract{}, "", fmt.Errorf("%w: invalid durable journal", ErrInvalidCancellation)
	}
	if !contractDigestPattern.MatchString(contract.Digest()) {
		return domain.ExecutionStepContract{}, "", fmt.Errorf("%w: invalid execution contract", ErrInvalidCancellation)
	}
	if pointOfNoReturnReached(contract, entries) {
		return domain.ExecutionStepContract{}, "", fmt.Errorf(
			"%w: point of no return has been reached", ErrInvalidCancellation,
		)
	}
	last := entries[len(entries)-1]
	if entries[0].OperationID != machine.operationID || entries[0].PlanID != machine.planID ||
		last.OperationState != machine.State() || request.Sequence != last.Sequence+1 ||
		request.RequestedAt.Before(last.RecordedAt) {
		return domain.ExecutionStepContract{}, "", fmt.Errorf("%w: journal does not match the current machine boundary", ErrInvalidCancellation)
	}

	steps := contract.Steps()
	if contract.WorkflowID() == "" || len(steps) == 0 {
		return domain.ExecutionStepContract{}, "", fmt.Errorf("%w: missing execution contract", ErrInvalidCancellation)
	}
	nextStep := 0
	observation := domain.MutationNotOccurred
	for _, entry := range entries {
		if entry.Kind == domain.JournalEntryCancellationRequest {
			return domain.ExecutionStepContract{}, "", fmt.Errorf(
				"%w: durable journal already contains a cancellation request", ErrInvalidCancellation,
			)
		}
		if entry.Pause != nil && entry.Pause.MutationOccurred {
			observation = domain.MutationOccurred
		}
		if entry.Kind != domain.JournalEntryStep {
			continue
		}
		if nextStep >= len(steps) || entry.Step.ID != steps[nextStep].ID {
			return domain.ExecutionStepContract{}, "", fmt.Errorf("%w: journal steps do not match the execution contract", ErrInvalidCancellation)
		}
		if entry.Step.Outcome == domain.StepUnknown {
			observation = domain.MutationUnknown
		} else if entry.Step.MutationOccurred && observation != domain.MutationUnknown {
			observation = domain.MutationOccurred
		}
		if entry.Step.Outcome == domain.StepDone {
			nextStep++
		}
	}
	if nextStep >= len(steps) {
		return domain.ExecutionStepContract{}, "", fmt.Errorf("%w: execution contract has no current step", ErrInvalidCancellation)
	}

	return steps[nextStep], observation, nil
}

func pointOfNoReturnReached(contract domain.ExecutionContract, entries []domain.JournalEntry) bool {
	pointOfNoReturn := contract.PointOfNoReturn()
	if pointOfNoReturn == "" {
		return false
	}
	pointIndex := -1
	stepIndexes := make(map[string]int)
	for index, step := range contract.Steps() {
		stepIndexes[step.ID] = index
		if step.ID == pointOfNoReturn {
			pointIndex = index
		}
	}
	if pointIndex < 0 {
		return true
	}
	trigger := contract.PointOfNoReturnTrigger()
	if !trigger.Valid() {
		return true
	}
	for _, entry := range entries {
		if entry.Kind != domain.JournalEntryStep {
			continue
		}
		index, exists := stepIndexes[entry.Step.ID]
		if !exists {
			return true
		}
		if index > pointIndex {
			return true
		}
		if index != pointIndex {
			continue
		}
		switch trigger {
		case domain.PointOfNoReturnStepStart:
			return true
		case domain.PointOfNoReturnMutationObserved:
			if entry.Step.MutationOccurred || entry.Step.Outcome == domain.StepUnknown {
				return true
			}
		case domain.PointOfNoReturnStepComplete:
			if entry.Step.Outcome == domain.StepDone {
				return true
			}
		}
	}

	return false
}

func executionContractStep(contract domain.ExecutionContract, stepID string) (domain.ExecutionStepContract, bool) {
	var matched domain.ExecutionStepContract
	found := false
	for _, step := range contract.Steps() {
		if step.ID != stepID {
			continue
		}
		if found {
			return domain.ExecutionStepContract{}, false
		}
		matched = step
		found = true
	}

	return matched, found
}

func cancellationBoundaryRecorded(entries []domain.JournalEntry, binding cancellationBinding) bool {
	for _, entry := range entries {
		if entry.Sequence > binding.sequence && entry.Kind == domain.JournalEntryStep &&
			entry.Step.ID == binding.stepID && entry.Step.EndedAt != nil {
			return true
		}
	}

	return false
}

func cancellationStateIsStructurallyPreMutation(state domain.OperationState) bool {
	switch state {
	case domain.OperationDiscover, domain.OperationValidate, domain.OperationPlan,
		domain.OperationApprovedWaiting, domain.OperationLock:
		return true
	default:
		return false
	}
}

func cancellationJournalEntry(
	request CancellationRequest,
	state domain.OperationState,
	stepID string,
	contractHash string,
	observation domain.MutationObservation,
) domain.JournalEntry {
	return domain.JournalEntry{
		Schema:         domain.JournalSchemaV1,
		OperationID:    request.OperationID,
		PlanID:         request.PlanID,
		Sequence:       request.Sequence,
		Kind:           domain.JournalEntryCancellationRequest,
		RecordedAt:     request.RequestedAt,
		OperationState: state,
		Cancellation: &domain.JournalCancellationRequest{
			RequestedAt:           request.RequestedAt,
			CurrentStepID:         stepID,
			ExecutionContractHash: contractHash,
			MutationObservation:   observation,
			RequiredRoute:         cancellationTarget(observation != domain.MutationNotOccurred),
		},
	}
}

func cancellationTarget(mutationMayHaveOccurred bool) domain.OperationState {
	if mutationMayHaveOccurred {
		return domain.OperationRollback
	}

	return domain.OperationCancelled
}

func cancellationRouteReachable(current, target domain.OperationState) bool {
	visited := map[domain.OperationState]bool{current: true}
	pending := []domain.OperationState{current}
	for len(pending) != 0 {
		state := pending[0]
		pending = pending[1:]
		if CanTransition(state, target) {
			return true
		}
		for next := range transitions[state] {
			if !next.Terminal() && !visited[next] {
				visited[next] = true
				pending = append(pending, next)
			}
		}
	}

	return false
}
