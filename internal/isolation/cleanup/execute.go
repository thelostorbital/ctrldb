// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/redact"
)

var ErrWipeExecution = errors.New("test wipe execution failed")

// Journal is the minimal durable-record surface the wipe needs. Every method
// is create-only; the M1-05 control store adapter implements it without
// exposing deletion. Until that adapter lands, tests use an in-memory value.
type Journal interface {
	RecordPlan(ctx context.Context, record WipeRecordV1) error
	RecordDeletion(ctx context.Context, record DeletionRecordV1) error
}

// Deleter executes one sealed deletion. The provider adapter must refuse an
// unsealed deletion and must not expose any other delete surface.
type Deleter interface {
	Delete(ctx context.Context, deletion Deletion) error
}

// DeletionOutcome is the typed, redacted result of one attempted deletion.
type DeletionOutcome struct {
	Sequence   int
	Capability isolation.CleanupCapability
	Identity   isolation.ResourceIdentity
	Attempt    uint32
	Status     DeletionStatus
	Failure    redact.Text
}

// WipeResult is the typed, redacted outcome of one execution. Counts and
// identities are safe to log; failures are sanitized at construction.
type WipeResult struct {
	Mode              string
	ProjectID         string
	RunNumber         uint64
	Disposition       Disposition
	InventoryRevision string
	RecordIntegrity   string
	Planned           int
	Deleted           int
	Failed            int
	Retained          int
	Deferred          int
	Protected         int
	StartedAt         time.Time
	EndedAt           time.Time
	Deletions         []DeletionOutcome
}

// Execute records the plan, then issues each sealed deletion in order,
// recording it before and after the provider call. It stops at the first
// failure so the next run converges from freshly observed state.
func Execute(ctx context.Context, plan WipePlan, journal Journal, deleter Deleter, clock func() time.Time) (WipeResult, error) {
	if ctx == nil || journal == nil || deleter == nil || clock == nil {
		return WipeResult{}, inputError("execution", "requires context, journal, deleter, and clock")
	}
	record, err := plan.Record()
	if err != nil {
		return WipeResult{}, err
	}
	startedAt := clock().UTC()
	if err := validateNow(startedAt); err != nil {
		return WipeResult{}, err
	}
	result := WipeResult{
		Mode: plan.Mode, ProjectID: plan.ProjectID, RunNumber: plan.RunNumber, Disposition: plan.Disposition,
		InventoryRevision: plan.Selection.InventoryRevision, RecordIntegrity: record.IntegritySHA256,
		Planned: len(plan.Selection.Deletions), Retained: len(plan.Selection.Retained),
		Deferred: len(plan.Selection.Deferred), Protected: len(plan.Selection.Protected), StartedAt: startedAt,
	}
	if err := journal.RecordPlan(ctx, record); err != nil {
		result.EndedAt = clock().UTC()
		return result, fmt.Errorf("%w: plan record was not persisted", ErrWipeExecution)
	}
	if plan.Disposition != DispositionDelete {
		result.EndedAt = clock().UTC()
		return result, nil
	}
	for _, deletion := range plan.Selection.Deletions {
		outcome, err := executeDeletion(ctx, record.IntegritySHA256, deletion, journal, deleter, clock)
		result.Deletions = append(result.Deletions, outcome)
		if err != nil {
			result.Failed++
			result.EndedAt = clock().UTC()
			return result, err
		}
		result.Deleted++
	}
	result.EndedAt = clock().UTC()
	return result, nil
}

func executeDeletion(ctx context.Context, planIntegrity string, deletion Deletion, journal Journal, deleter Deleter, clock func() time.Time) (DeletionOutcome, error) {
	outcome := DeletionOutcome{
		Sequence: deletion.Sequence, Capability: deletion.Capability, Identity: deletion.Identity,
		Attempt: deletion.Attempt, Status: DeletionFailed, Failure: redact.Sanitize(""),
	}
	if !deletion.Sealed() {
		outcome.Failure = redact.Sanitize("deletion is not sealed")
		return outcome, fmt.Errorf("%w: unsealed deletion", ErrWipeExecution)
	}
	if ctx.Err() != nil {
		outcome.Failure = redact.Sanitize("execution canceled before issue")
		return outcome, fmt.Errorf("%w: canceled", ErrWipeExecution)
	}
	issuedAt := clock().UTC()
	issued, err := sealDeletionRecord(DeletionRecordV1{
		PlanIntegrity: planIntegrity, Deletion: plannedDeletion(deletion), Status: DeletionIssued, IssuedAt: issuedAt, Failure: redact.Sanitize(""),
	})
	if err != nil {
		return outcome, err
	}
	if err := journal.RecordDeletion(ctx, issued); err != nil {
		outcome.Failure = redact.Sanitize("deletion intent was not persisted")
		return outcome, fmt.Errorf("%w: deletion intent was not persisted", ErrWipeExecution)
	}
	deleteErr := deleter.Delete(ctx, deletion)
	completedAt := clock().UTC()
	final := issued
	final.CompletedAt = &completedAt
	if deleteErr != nil {
		final.Status = DeletionFailed
		final.Failure = redact.Sanitize(deleteErr.Error())
		outcome.Failure = final.Failure
	} else {
		final.Status = DeletionDeleted
		outcome.Status = DeletionDeleted
	}
	final, err = sealDeletionRecord(final)
	if err != nil {
		return outcome, err
	}
	if err := journal.RecordDeletion(ctx, final); err != nil {
		outcome.Status = DeletionFailed
		outcome.Failure = redact.Sanitize("deletion outcome was not persisted")
		return outcome, fmt.Errorf("%w: deletion outcome was not persisted", ErrWipeExecution)
	}
	if deleteErr != nil {
		return outcome, fmt.Errorf("%w: deletion %d failed", ErrWipeExecution, deletion.Sequence)
	}
	return outcome, nil
}
