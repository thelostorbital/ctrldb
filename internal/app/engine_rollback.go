// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

// cancelAtBoundary honours a cancellation request at a safe boundary. The
// engine pauses first so the workflow rules can route the request from the
// journaled observation: no mutation routes to CANCELLED, otherwise ROLLBACK.
func (run *session) cancelAtBoundary() error {
	if run.machine.State() != domain.OperationPaused {
		if err := run.pause(pauseReasonCancellation); err != nil {
			return err
		}
	}
	request := workflow.CancellationRequest{
		OperationID: run.request.OperationID, PlanID: run.reviewed.PlanID,
		Sequence: uint64(len(run.entries) + 1), RequestedAt: run.now().Add(time.Second),
	}
	controller := workflow.CancellationController{}
	_, decision, err := controller.Request(run.machine, request, run.contract, run.entries)
	if err != nil {
		return fmt.Errorf("%w: cancellation refused: %v", ErrOperationPaused, err)
	}
	if decision.Action != workflow.CancellationCancel && decision.Action != workflow.CancellationRollback {
		return fmt.Errorf("%w: cancellation not routable at this boundary", ErrOperationPaused)
	}
	run.lastTime = request.RequestedAt
	entry := run.baseEntry(domain.JournalEntryTransition, decision.Target)
	if err := run.append(entry); err != nil {
		return err
	}
	if err := run.machine.ApplyCancellation(decision); err != nil {
		return fmt.Errorf("%w: %v", ErrJournalInvalid, err)
	}
	if decision.Target == domain.OperationCancelled {
		run.releaseLock()
		return ErrOperationCancelled
	}
	return run.compensate()
}

// compensate is WF-OPS-02 over the recorded claims: reverse order, only
// resources this operation observed absent before it acted, never the
// irreversible retention lock, and nothing at or before a crossed point of no
// return.
func (run *session) compensate() error {
	if run.lock.Generation == 0 {
		if err := run.acquireLock(); err != nil {
			return run.failCleanup("lock unavailable for compensation: " + err.Error())
		}
	}
	crossed := run.pointOfNoReturnCrossed()
	pointIndex := slices.IndexFunc(run.intents, func(intent bootstrap.StepIntent) bool {
		return intent.StepID == run.contract.PointOfNoReturn()
	})
	for index := len(run.intents) - 1; index >= 0; index-- {
		intent := run.intents[index]
		if intent.PointOfNoReturn != bootstrap.PONRReversible || (crossed && index <= pointIndex) {
			continue
		}
		recorded := run.recordedCreations(intent.StepID)
		if len(recorded) == 0 || run.compensated(intent.StepID) {
			continue
		}
		if err := run.compensateStep(intent, recorded); err != nil {
			return err
		}
	}
	if err := run.transition(domain.OperationVerifiedRollback, nil); err != nil {
		return err
	}
	run.releaseLock()
	return fmt.Errorf("%w: rolled back to the recorded boundary", ErrOperationCancelled)
}

// recordedCreations returns the desired resources this operation claimed as
// absent or partial before an attempt that may have mutated. A resource never
// claimed is never a compensation target; the adapter removes only its own
// recorded delta and never deletes a resource it did not create.
func (run *session) recordedCreations(stepID string) []bootstrap.DesiredResource {
	mayHaveMutated := false
	for _, entry := range run.entries {
		if entry.Kind == domain.JournalEntryStep && entry.Step.ID == stepID &&
			(entry.Step.MutationOccurred || entry.Step.Outcome == domain.StepUnknown) {
			mayHaveMutated = true
		}
	}
	if !mayHaveMutated {
		return nil
	}
	ids := make([]string, 0)
	for _, record := range run.claims {
		if record.Claim.StepID != stepID {
			continue
		}
		for _, id := range append(slices.Clone(record.Claim.AbsentResourceIDs), record.Claim.PartialResourceIDs...) {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	resources := make([]bootstrap.DesiredResource, 0, len(ids))
	for _, id := range ids {
		resources = append(resources, run.byID[id])
	}
	return resources
}

func (run *session) compensated(stepID string) bool {
	return run.stepDone(rollbackStepPrefix + stepID)
}

func (run *session) compensateStep(intent bootstrap.StepIntent, recorded []bootstrap.DesiredResource) error {
	rollbackIntent := intent
	rollbackIntent.StepID = rollbackStepPrefix + intent.StepID
	attempt := run.attempts(rollbackIntent.StepID) + 1
	if attempt > intent.Retry.MaxAttempts {
		return run.failCleanup("compensation retry limit reached for " + intent.StepID)
	}
	credential, err := run.engine.deps.Credentials.VerifyHumanCredential(run.ctx, run.reviewed.Principal)
	if err != nil {
		return run.failCleanup("credential revalidation failed for compensation of " + intent.StepID)
	}
	observation, err := run.engine.deps.Observer.Describe(run.ctx, intent, recorded)
	if err != nil || !freshAt(observation.ObservedAt, observation.ValidUntil, run.now()) {
		return run.failCleanup("describe-before-compensate failed for " + intent.StepID)
	}
	now := run.now()
	claim, err := run.engine.deps.Store.ClaimStep(run.ctx, StepClaim{
		OperationID: run.request.OperationID, StepID: rollbackIntent.StepID, Attempt: attempt,
		ObservationRevision: observation.Revision, ObservedAt: observation.ObservedAt, ClaimedAt: now,
	})
	if err != nil {
		return run.failCleanup("durable compensation claim refused for " + intent.StepID)
	}
	harness, err := run.engine.deps.Store.ReadHarnessState(run.ctx)
	if err != nil {
		return run.failCleanup("harness state unreadable before compensation")
	}
	authorization, err := Authorize(AuthorizationRequest{
		Mode: GatewayCompensate, Plan: run.request.Plan, Approval: run.request.Approval, Intent: intent, Claim: claim,
		Observation: observation, Lock: run.lock, Credential: credential, Harness: harness.State, Expected: run.expected, Now: now,
	})
	if err != nil {
		return run.failCleanup("compensation authorization refused for " + intent.StepID + ": " + err.Error())
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(run.ctx), time.Duration(intent.TimeoutSeconds)*time.Second)
	defer cancel()
	result, err := run.compensateAdapter(ctx, intent, authorization, recorded)
	if err != nil {
		if recordErr := run.recordStep(rollbackIntent, attempt, domain.StepFailed, true, now, err.Error()); recordErr != nil {
			return recordErr
		}
		return run.failCleanup("compensation failed for " + intent.StepID)
	}
	return run.recordStep(rollbackIntent, attempt, domain.StepDone, result.MutationOccurred, now, result.Summary)
}

func (run *session) failCleanup(reason string) error {
	if run.machine.State() == domain.OperationRollback {
		if err := run.transition(domain.OperationFailedCleanup, nil); err != nil {
			return err
		}
	}
	run.releaseLock()
	return fmt.Errorf("%w: %s", ErrOperationFailed, reason)
}
