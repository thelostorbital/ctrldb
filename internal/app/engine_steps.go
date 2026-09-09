// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

// drive advances the operation from its journaled state to a terminal or
// paused boundary. Every branch journals before it changes in-memory state.
func (run *session) drive() error {
	if run.machine.State().Terminal() {
		return ErrOperationTerminal
	}
	if err := run.enterExecute(); err != nil {
		return err
	}
	if run.machine.State() == domain.OperationRollback {
		return run.compensate()
	}
	if err := run.classifyJournal(); err != nil {
		return err
	}
	for _, intent := range run.intents {
		if run.stepDone(intent.StepID) {
			continue
		}
		if err := run.boundary(); err != nil {
			return err
		}
		if err := run.runStep(intent); err != nil {
			return err
		}
	}
	return run.finish()
}

// enterExecute walks the pre-execution states, acquires the lock, and seals
// the pending harness state before the first mutation.
func (run *session) enterExecute() error {
	if run.machine.State() == domain.OperationPaused {
		if err := run.resumeFromPause(); err != nil {
			return err
		}
	}
	for _, next := range []domain.OperationState{domain.OperationDiscover, domain.OperationValidate, domain.OperationPlan, domain.OperationLock} {
		if err := run.advanceThrough(next); err != nil {
			return err
		}
	}
	if err := run.acquireLock(); err != nil {
		return err
	}
	if err := run.ensurePendingState(); err != nil {
		return err
	}
	if run.machine.State() == domain.OperationLock {
		return run.transition(domain.OperationExecute, nil)
	}
	return nil
}

func (run *session) advanceThrough(next domain.OperationState) error {
	current := run.machine.State()
	if len(run.entries) == 0 && next == domain.OperationDiscover {
		return run.append(run.baseEntry(domain.JournalEntryTransition, domain.OperationDiscover))
	}
	if current == domain.OperationExecute || current == domain.OperationRollback || current == next {
		return nil
	}
	if workflow.CanTransition(current, next) && stateOrder(next) > stateOrder(current) {
		return run.transition(next, nil)
	}
	return nil
}

func stateOrder(state domain.OperationState) int {
	switch state {
	case domain.OperationDiscover:
		return 1
	case domain.OperationValidate:
		return 2
	case domain.OperationPlan:
		return 3
	case domain.OperationLock:
		return 4
	case domain.OperationExecute:
		return 5
	default:
		return 0
	}
}

func (run *session) resumeFromPause() error {
	var pause *domain.JournalPause
	for _, entry := range run.entries {
		if entry.Pause != nil {
			pause = entry.Pause
		}
	}
	now := run.now()
	if pause == nil || pause.ReapprovalRequired || !now.Before(pause.ResumeBy) || !now.Before(run.reviewed.ExpiresAt) {
		return fmt.Errorf("%w: paused operation requires a new plan and approval", ErrPlanExpired)
	}
	if run.engine.deps.CancelRequested() {
		return run.cancelAtBoundary()
	}
	return run.transition(domain.OperationDiscover, nil)
}

func (run *session) acquireLock() error {
	record, err := run.engine.deps.Store.AcquireLock(run.ctx, LockRequest{
		OperationID: run.request.OperationID, PlanID: run.reviewed.PlanID, WorkflowID: bootstrap.WorkflowID,
		Now: run.now(), Lease: LockLease,
	})
	if err != nil {
		if errors.Is(err, ErrStoreConflict) {
			return fmt.Errorf("%w: %v", ErrLockHeld, err)
		}
		return fmt.Errorf("%w: lock: %v", ErrLockHeld, err)
	}
	if err := validateLock(record, run.request.OperationID, run.reviewed.PlanID, run.now()); err != nil {
		return fmt.Errorf("%w: %v", ErrLockHeld, err)
	}
	run.lock = record
	return nil
}

func (run *session) ensurePendingState() error {
	_, err := run.engine.deps.Store.ReadHarnessState(run.ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrStoreNotFound) {
		return fmt.Errorf("%w: harness state: %v", ErrInvalidRun, err)
	}
	state, err := isolation.NewPendingHarnessStateV1(run.seed)
	if err != nil {
		return fmt.Errorf("%w: pending harness state: %v", ErrInvalidRun, err)
	}
	if _, err := run.engine.deps.Store.CreateHarnessState(run.ctx, state); err != nil {
		return fmt.Errorf("%w: pending harness state: %v", ErrInvalidRun, err)
	}
	return nil
}

// boundary is the safe point between steps: the lock heartbeat must succeed
// and a requested cancellation is honoured through the workflow rules.
func (run *session) boundary() error {
	refreshed, err := run.engine.deps.Store.RefreshLock(run.ctx, run.lock, run.now())
	if err != nil || validateLock(refreshed, run.request.OperationID, run.reviewed.PlanID, run.now()) != nil {
		run.lock = LockRecord{}
		if pauseErr := run.pause(pauseReasonLockLost); pauseErr != nil {
			return pauseErr
		}
		return fmt.Errorf("%w: %w", ErrOperationPaused, ErrLockLost)
	}
	run.lock = refreshed
	if run.engine.deps.CancelRequested() {
		return run.cancelAtBoundary()
	}
	return nil
}

func (run *session) stepDone(stepID string) bool {
	for _, entry := range run.entries {
		if entry.Kind == domain.JournalEntryStep && entry.Step.ID == stepID && entry.Step.Outcome == domain.StepDone {
			return true
		}
	}
	return false
}

func (run *session) attempts(stepID string) uint32 {
	var attempts uint32
	for _, entry := range run.entries {
		if entry.Kind == domain.JournalEntryStep && entry.Step.ID == stepID && entry.Step.Attempt > attempts {
			attempts = entry.Step.Attempt
		}
	}
	return attempts
}

func (run *session) resources(intent bootstrap.StepIntent) []bootstrap.DesiredResource {
	result := make([]bootstrap.DesiredResource, 0, len(intent.ResourceIDs))
	for _, id := range intent.ResourceIDs {
		result = append(result, run.byID[id])
	}
	return result
}

// classifyJournal is WF-OPS-01 R3: every journaled DONE step must still be
// true against live state, and an in-flight claim without a journal outcome
// is classified from rediscovery, never from the journal alone.
func (run *session) classifyJournal() error {
	for _, intent := range run.intents {
		done := run.stepDone(intent.StepID)
		claim, inFlight := run.unrecordedClaim(intent.StepID)
		unknown := run.lastOutcomeUnknown(intent.StepID)
		if !done && !inFlight && !unknown {
			continue
		}
		observation, err := run.observe(intent)
		if err != nil {
			return err
		}
		states := classifyObservation(observation, intent.ResourceIDs)
		switch {
		case done && (states.conflicting || states.unknown || !states.allDesired):
			return run.driftStop("journaled step " + intent.StepID + " no longer matches the approved desired state")
		case done:
			continue
		case states.conflicting || states.unknown:
			return run.driftStop("in-flight step " + intent.StepID + " re-observed a conflicting resource")
		case inFlight:
			if err := run.recordInFlight(intent, claim, states); err != nil {
				return err
			}
		case states.allDesired:
			if err := run.recordStep(intent, run.attempts(intent.StepID)+1, domain.StepDone, true, run.now(), classifiedSummary); err != nil {
				return err
			}
		}
	}
	return nil
}

const classifiedSummary = "classified from rediscovery after an unobserved attempt"

// recordInFlight journals the outcome of a durable claim that never reached
// the journal. Verification-only steps are never marked complete from
// rediscovery because their evidence was not observed.
func (run *session) recordInFlight(intent bootstrap.StepIntent, claim StepClaim, states observationSummary) error {
	created := false
	for _, id := range claim.AbsentResourceIDs {
		if states.desired[id] {
			created = true
		}
	}
	outcome := domain.StepFailed
	if states.allDesired && intent.Kind != bootstrap.IntentIsolationGate {
		outcome = domain.StepDone
	}
	return run.recordStep(intent, claim.Attempt, outcome, created, claim.ClaimedAt, classifiedSummary)
}

func (run *session) lastOutcomeUnknown(stepID string) bool {
	var last *domain.JournalStep
	for _, entry := range run.entries {
		if entry.Kind == domain.JournalEntryStep && entry.Step.ID == stepID {
			last = entry.Step
		}
	}
	return last != nil && last.Outcome == domain.StepUnknown
}

func (run *session) unrecordedClaim(stepID string) (StepClaim, bool) {
	recorded := run.attempts(stepID)
	var latest *StepClaim
	for index := range run.claims {
		claim := run.claims[index].Claim
		if claim.StepID == stepID && claim.Attempt > recorded && (latest == nil || claim.Attempt > latest.Attempt) {
			latest = &claim
		}
	}
	if latest == nil {
		return StepClaim{}, false
	}
	return *latest, true
}

type observationSummary struct {
	desired     map[string]bool
	absent      []string
	partial     []string
	allDesired  bool
	conflicting bool
	unknown     bool
}

func classifyObservation(observation StepObservation, resourceIDs []string) observationSummary {
	summary := observationSummary{desired: make(map[string]bool), allDesired: true}
	seen := make(map[string]ResourceState)
	for _, item := range observation.Resources {
		seen[item.ResourceID] = item.State
	}
	for _, id := range resourceIDs {
		switch seen[id] {
		case ResourceDesired:
			summary.desired[id] = true
		case ResourceAbsent:
			summary.absent = append(summary.absent, id)
			summary.allDesired = false
		case ResourcePartial:
			summary.partial = append(summary.partial, id)
			summary.allDesired = false
		case ResourceConflicting:
			summary.conflicting = true
			summary.allDesired = false
		default:
			summary.unknown = true
			summary.allDesired = false
		}
	}
	return summary
}

func (run *session) observe(intent bootstrap.StepIntent) (StepObservation, error) {
	observation, err := run.engine.deps.Observer.Describe(run.ctx, intent, run.resources(intent))
	if err != nil {
		return StepObservation{}, run.driftStop("describe-before-act failed for " + intent.StepID)
	}
	if !freshAt(observation.ObservedAt, observation.ValidUntil, run.now()) || observation.Revision == "" {
		return StepObservation{}, run.driftStop("observation for " + intent.StepID + " is not fresh")
	}
	return observation, nil
}

func (run *session) driftStop(reason string) error {
	if err := run.pause(reason); err != nil {
		return err
	}
	return fmt.Errorf("%w: %w: %s", ErrOperationPaused, ErrDrift, reason)
}

const (
	pauseReasonLockLost     = "lock-lost"
	pauseReasonCancellation = "cancellation requested at a safe boundary"
)

// runStep performs bounded attempts of one intent. Gate failures pause
// without any provider write; provider failures follow the declared route.
func (run *session) runStep(intent bootstrap.StepIntent) error {
	for {
		attempt := run.attempts(intent.StepID) + 1
		if attempt > attemptBound(intent) {
			return run.pauseWith("retry limit reached for " + intent.StepID)
		}
		outcome, err := run.attempt(intent, attempt)
		if err != nil {
			return err
		}
		if outcome.done {
			return nil
		}
		decision := workflow.DecideRetry(run.contract, intent.StepID, attempt, outcome.class, outcome.mutation)
		if decision.Retry {
			if err := run.engine.deps.Sleep(run.ctx, decision.Delay); err != nil {
				return run.pauseWith("interrupted while waiting to retry " + intent.StepID)
			}
			continue
		}
		return run.routeFailure(intent, outcome)
	}
}

// attemptBound is the retry policy for mutation steps. A verification-only
// step never mutates, so an unobserved attempt (crash before its journal
// entry) may be re-verified up to the engine-wide attempt ceiling; failed
// verifications still follow the step's own retry policy through DecideRetry.
func attemptBound(intent bootstrap.StepIntent) uint32 {
	if intent.PointOfNoReturn == bootstrap.PONRVerificationOnly {
		return domain.MaxStepAttempts
	}
	return intent.Retry.MaxAttempts
}

type attemptOutcome struct {
	done     bool
	gate     bool
	class    domain.RetryFailureClass
	mutation domain.MutationObservation
	summary  string
}

func (run *session) attempt(intent bootstrap.StepIntent, attempt uint32) (attemptOutcome, error) {
	credential, err := run.engine.deps.Credentials.VerifyHumanCredential(run.ctx, run.reviewed.Principal)
	if err != nil {
		return attemptOutcome{}, run.pauseWith("credential revalidation failed for " + intent.StepID)
	}
	observation, err := run.observe(intent)
	if err != nil {
		return attemptOutcome{}, err
	}
	states := classifyObservation(observation, intent.ResourceIDs)
	if states.conflicting || states.unknown {
		return attemptOutcome{}, run.driftStop("pre-execution revalidation found a conflicting resource for " + intent.StepID)
	}
	if states.allDesired && intent.Kind != bootstrap.IntentIsolationGate {
		if err := run.recordStep(intent, attempt, domain.StepDone, false, run.now(), "desired state already exact; no mutation issued"); err != nil {
			return attemptOutcome{}, err
		}
		return attemptOutcome{done: true}, nil
	}
	now := run.now()
	claim, err := run.engine.deps.Store.ClaimStep(run.ctx, StepClaim{
		OperationID: run.request.OperationID, StepID: intent.StepID, Attempt: attempt,
		ObservationRevision: observation.Revision, ObservedAt: observation.ObservedAt, ClaimedAt: now,
		AbsentResourceIDs: slices.Clone(states.absent), PartialResourceIDs: slices.Clone(states.partial),
	})
	if err != nil {
		return attemptOutcome{}, run.pauseWith("durable step claim refused for " + intent.StepID)
	}
	run.claims = append(run.claims, claim)
	harness, err := run.engine.deps.Store.ReadHarnessState(run.ctx)
	if err != nil {
		return attemptOutcome{}, run.pauseWith("harness state unreadable before " + intent.StepID)
	}
	authorization, err := Authorize(AuthorizationRequest{
		Mode: GatewayApply, Plan: run.request.Plan, Approval: run.request.Approval, Intent: intent, Claim: claim,
		Observation: observation, Lock: run.lock, Credential: credential, Harness: harness.State, Expected: run.expected, Now: now,
	})
	if err != nil {
		return attemptOutcome{}, run.gateRefusal(intent, attempt, err)
	}
	if intent.Kind != bootstrap.IntentIsolationGate {
		evidence, err := run.engine.deps.Adapters.Prover.Prove(run.ctx, authorization, intent, run.resources(intent))
		if err != nil {
			return attemptOutcome{}, run.gateRefusal(intent, attempt, deniedAs(ErrPermissionRevalidation, err.Error()))
		}
		if err := RevalidatePermissions(run.request.Plan, authorization, &evidence); err != nil {
			return attemptOutcome{}, run.gateRefusal(intent, attempt, err)
		}
	}
	return run.dispatch(intent, attempt, authorization, states)
}

// gateRefusal records a mutation-free failed attempt and pauses. Nothing was
// issued to a provider, so the pause is always safe and resumable.
func (run *session) gateRefusal(intent bootstrap.StepIntent, attempt uint32, cause error) error {
	if err := run.recordStep(intent, attempt, domain.StepFailed, false, run.now(), cause.Error()); err != nil {
		return err
	}
	if err := run.pause("authorization refused for " + intent.StepID); err != nil {
		return err
	}
	return fmt.Errorf("%w: %w", ErrOperationPaused, cause)
}

func (run *session) pauseWith(reason string) error {
	if err := run.pause(reason); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrOperationPaused, reason)
}

func (run *session) dispatch(intent bootstrap.StepIntent, attempt uint32, authorization MutationAuthorization, states observationSummary) (attemptOutcome, error) {
	started := run.now()
	ctx := run.ctx
	if !intent.CancelSafe {
		ctx = context.WithoutCancel(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(intent.TimeoutSeconds)*time.Second)
	defer cancel()
	resources := run.resources(intent)
	var result StepResult
	var err error
	if intent.Kind == bootstrap.IntentIsolationGate {
		var evidence isolation.T8Evidence
		evidence, err = run.engine.deps.Adapters.Gate.Verify(ctx, authorization, intent, resources)
		if err == nil {
			run.t8 = &evidence
			result = StepResult{Summary: t8Summary(evidence)}
		}
	} else {
		result, err = run.applyAdapter(ctx, intent, authorization, resources)
	}
	if err != nil {
		return run.recordFailure(intent, attempt, started, err, ctx.Err() != nil)
	}
	for _, id := range result.CreatedResourceIDs {
		if !slices.Contains(states.absent, id) {
			return attemptOutcome{}, run.driftStop("adapter reported creating unclaimed resource " + id)
		}
	}
	if err := run.recordStep(intent, attempt, domain.StepDone, result.MutationOccurred, started, result.Summary); err != nil {
		return attemptOutcome{}, err
	}
	return attemptOutcome{done: true}, nil
}

func (run *session) applyAdapter(ctx context.Context, intent bootstrap.StepIntent, authorization MutationAuthorization, resources []bootstrap.DesiredResource) (StepResult, error) {
	adapters := run.engine.deps.Adapters
	switch intent.Kind {
	case bootstrap.IntentAuditBootstrap, bootstrap.IntentAuditRetention, bootstrap.IntentControlBucket,
		bootstrap.IntentBucketIAM, bootstrap.IntentSeedControl, bootstrap.IntentLockRoundTrip:
		return adapters.Storage.Apply(ctx, authorization, intent, resources)
	case bootstrap.IntentNetwork, bootstrap.IntentSubnet, bootstrap.IntentNAT, bootstrap.IntentFirewall:
		return adapters.Network.Apply(ctx, authorization, intent, resources)
	case bootstrap.IntentIdentities, bootstrap.IntentControlPrefix:
		return adapters.Identity.Apply(ctx, authorization, intent, resources)
	case bootstrap.IntentNightlyWipe:
		return adapters.Wipe.Apply(ctx, authorization, intent, resources)
	default:
		return StepResult{}, &StepFailure{Class: domain.RetryFailureValidation, Mutation: domain.MutationNotOccurred, Summary: "unknown intent kind"}
	}
}

func (run *session) compensateAdapter(ctx context.Context, intent bootstrap.StepIntent, authorization MutationAuthorization, resources []bootstrap.DesiredResource) (StepResult, error) {
	adapters := run.engine.deps.Adapters
	switch intent.Kind {
	case bootstrap.IntentAuditBootstrap, bootstrap.IntentControlBucket, bootstrap.IntentBucketIAM,
		bootstrap.IntentSeedControl, bootstrap.IntentLockRoundTrip:
		return adapters.Storage.Compensate(ctx, authorization, intent, resources)
	case bootstrap.IntentNetwork, bootstrap.IntentSubnet, bootstrap.IntentNAT, bootstrap.IntentFirewall:
		return adapters.Network.Compensate(ctx, authorization, intent, resources)
	case bootstrap.IntentIdentities, bootstrap.IntentControlPrefix:
		return adapters.Identity.Compensate(ctx, authorization, intent, resources)
	case bootstrap.IntentNightlyWipe:
		return adapters.Wipe.Compensate(ctx, authorization, intent, resources)
	default:
		return StepResult{}, &StepFailure{Class: domain.RetryFailureValidation, Mutation: domain.MutationNotOccurred, Summary: "intent has no compensation"}
	}
}

func (run *session) recordFailure(intent bootstrap.StepIntent, attempt uint32, started time.Time, cause error, timedOut bool) (attemptOutcome, error) {
	outcome := attemptOutcome{class: domain.RetryFailureTransient, mutation: domain.MutationUnknown, summary: cause.Error()}
	var failure *StepFailure
	switch {
	case errors.As(cause, &failure) && failure.Class.Valid() && failure.Mutation.Valid():
		outcome.class, outcome.mutation, outcome.summary = failure.Class, failure.Mutation, failure.Summary
	case timedOut:
		outcome.class = domain.RetryFailureTimeout
		if intent.Kind == bootstrap.IntentIsolationGate {
			outcome.mutation = domain.MutationNotOccurred
		}
	}
	journalOutcome := domain.StepFailed
	if outcome.mutation == domain.MutationUnknown {
		journalOutcome = domain.StepUnknown
	}
	if err := run.recordStep(intent, attempt, journalOutcome, outcome.mutation == domain.MutationOccurred, started, outcome.summary); err != nil {
		return attemptOutcome{}, err
	}
	return outcome, nil
}

func (run *session) recordStep(intent bootstrap.StepIntent, attempt uint32, outcome domain.StepOutcome, mutation bool, started time.Time, summary string) error {
	now := run.now()
	if started.After(now) || started.Before(run.lastTime) {
		started = run.lastTime
		if started.IsZero() {
			started = now
		}
	}
	step := &domain.JournalStep{
		ID: intent.StepID, Outcome: outcome, ExecutingIdentity: intent.ExecutingIdentity, Attempt: attempt,
		StartedAt: started, MutationOccurred: mutation, ResultSummary: redact.Sanitize(summary),
	}
	if outcome != domain.StepUnknown {
		ended := now
		step.EndedAt = &ended
	}
	entry := run.baseEntry(domain.JournalEntryStep, run.machine.State())
	entry.RecordedAt = now
	entry.Step = step
	return run.append(entry)
}

func (run *session) routeFailure(intent bootstrap.StepIntent, outcome attemptOutcome) error {
	switch intent.Kind {
	case bootstrap.IntentIsolationGate:
		return run.pauseWith("T8 isolation gate failed; harness remains pending and unusable")
	}
	step := run.contractStep(intent.StepID)
	switch {
	case step.FailureBehavior == domain.FailureRollback && outcome.mutation != domain.MutationUnknown:
		if err := run.transition(domain.OperationRollback, nil); err != nil {
			return err
		}
		return run.compensate()
	case step.FailureBehavior == domain.FailureFail:
		if err := run.transition(domain.OperationFailed, nil); err != nil {
			return err
		}
		run.releaseLock()
		return fmt.Errorf("%w: %s", ErrOperationFailed, outcome.summary)
	default:
		return run.pauseWith("step " + intent.StepID + " failed: " + outcome.summary)
	}
}

func (run *session) contractStep(stepID string) domain.ExecutionStepContract {
	for _, step := range run.contract.Steps() {
		if step.ID == stepID {
			return step
		}
	}
	return domain.ExecutionStepContract{}
}

// finish persists the T8 transition as a compare-and-swap from the exact
// pending/unusable record read, then completes the operation.
func (run *session) finish() error {
	if run.t8 == nil {
		run.t8 = run.recoverT8()
	}
	if run.t8 == nil {
		return run.failVerification("T8 evidence is not recorded in the durable journal")
	}
	if run.machine.State() == domain.OperationExecute {
		if err := run.transition(domain.OperationVerify, nil); err != nil {
			return err
		}
	}
	if run.machine.State() == domain.OperationVerify {
		if err := run.persistOpenTransition(); err != nil {
			return err
		}
		if err := run.transition(domain.OperationDocument, nil); err != nil {
			return err
		}
	}
	if err := run.transition(domain.OperationComplete, nil); err != nil {
		return err
	}
	run.releaseLock()
	return nil
}

// persistOpenTransition performs the pending/unusable -> open/usable change as
// one compare-and-swap on the exact generation read. A resumed run whose
// earlier attempt already persisted this exact evidence continues.
func (run *session) persistOpenTransition() error {
	record, err := run.engine.deps.Store.ReadHarnessState(run.ctx)
	if err != nil {
		return run.failVerification("harness state unreadable at T8 transition")
	}
	if record.State.BootstrapPhase() == isolation.BootstrapPhaseOpen {
		if record.State.TestUsability() == isolation.TestUsabilityUsable && record.State.T8ObservationRevision() == run.t8.Revision {
			return nil
		}
		return run.failVerification("harness state was opened by a different T8 observation")
	}
	opened, err := record.State.OpenAfterT8(*run.t8, run.now())
	if err != nil {
		return run.failVerification("T8 evidence rejected by the harness state contract: " + err.Error())
	}
	if _, err := run.engine.deps.Store.ReplaceHarnessState(run.ctx, record.Generation, opened); err != nil {
		return run.failVerification("harness state changed underneath the T8 transition")
	}
	return nil
}

// t8Summary is the journaled durable form of T8 evidence so a crash between
// the verified gate and the persisted transition can resume without guessing.
func t8Summary(evidence isolation.T8Evidence) string {
	return "t8 " + evidence.Revision + " " + evidence.ObservedAt.UTC().Format(time.RFC3339) + " " +
		evidence.ValidUntil.UTC().Format(time.RFC3339)
}

func (run *session) recoverT8() *isolation.T8Evidence {
	var summary string
	for _, entry := range run.entries {
		if entry.Kind == domain.JournalEntryStep && entry.Step.Outcome == domain.StepDone &&
			entry.Step.ID == isolationGateStepID(run.intents) {
			summary = entry.Step.ResultSummary.String()
		}
	}
	fields := strings.Fields(summary)
	if len(fields) != 4 || fields[0] != "t8" {
		return nil
	}
	observedAt, err := time.Parse(time.RFC3339, fields[2])
	if err != nil {
		return nil
	}
	validUntil, err := time.Parse(time.RFC3339, fields[3])
	if err != nil {
		return nil
	}
	return &isolation.T8Evidence{Revision: fields[1], ObservedAt: observedAt.UTC(), ValidUntil: validUntil.UTC()}
}

func isolationGateStepID(intents []bootstrap.StepIntent) string {
	for _, intent := range intents {
		if intent.Kind == bootstrap.IntentIsolationGate {
			return intent.StepID
		}
	}
	return ""
}

func (run *session) failVerification(reason string) error {
	if run.machine.State() == domain.OperationVerify {
		if err := run.transition(domain.OperationCompleteWithFailedVerification, nil); err != nil {
			return err
		}
	}
	run.releaseLock()
	return fmt.Errorf("%w: %s", ErrOperationFailed, reason)
}
