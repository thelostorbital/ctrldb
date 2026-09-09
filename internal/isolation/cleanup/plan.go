// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

// Disposition is the closed outcome class of one wipe plan.
type Disposition string

const (
	// DispositionFirstRunObserveOnly records the first execution after
	// bootstrap. It plans and records but deletes nothing.
	DispositionFirstRunObserveOnly Disposition = "first-run-observe-only"
	// DispositionHarnessNotUsable records that the harness is not open and
	// usable; the wipe observes and records but deletes nothing.
	DispositionHarnessNotUsable Disposition = "harness-not-usable"
	// DispositionNothingExpired records a usable harness with no expired
	// owned resource.
	DispositionNothingExpired Disposition = "nothing-expired"
	// DispositionDelete authorizes the sealed, ordered deletions.
	DispositionDelete Disposition = "delete"
)

// OutstandingDeletion is one deletion recorded by an earlier run whose
// completion was never confirmed. Attempts counts the issued attempts.
type OutstandingDeletion struct {
	CanonicalKey string
	Attempts     uint32
}

// History is the durable wipe record summary read before planning. PriorRuns
// counts completed plan records; zero means this is the first execution.
type History struct {
	PriorRuns   uint64
	Outstanding []OutstandingDeletion
}

// PlanInput is everything one wipe execution may consult.
type PlanInput struct {
	Policy          WipePolicy
	State           isolation.HarnessStateV1
	Inventory       Inventory
	LifetimeRecords []LifetimeRecord
	History         History
	Now             time.Time
}

// WipePlan is the sealed result of Plan. Its selection is complete even when
// the disposition forbids deletion so the run can be recorded and reviewed.
type WipePlan struct {
	Mode                   string
	ProjectID              string
	HarnessIntegritySHA256 string
	BootstrapPhase         isolation.BootstrapPhase
	TestUsability          isolation.TestUsability
	Disposition            Disposition
	RunNumber              uint64
	Selection              Selection
	seal                   string
}

// Sealed reports whether the plan and every deletion were produced unchanged
// by Plan.
func (plan WipePlan) Sealed() bool {
	if plan.seal == "" || plan.seal != sealPlan(plan) {
		return false
	}
	for _, deletion := range plan.Selection.Deletions {
		if !deletion.Sealed() {
			return false
		}
	}
	return true
}

// Plan selects deletions from the exhaustive inventory and decides whether
// this execution may issue them. It performs no I/O.
func Plan(input PlanInput) (WipePlan, error) {
	if err := validatePolicy(input.Policy); err != nil {
		return WipePlan{}, err
	}
	if err := validateNow(input.Now); err != nil {
		return WipePlan{}, err
	}
	state := input.State
	if state.IntegritySHA256() == "" || state.ProjectID() != input.Policy.ProjectID || state.EnvironmentClass() != "disposable" {
		return WipePlan{}, inputError("state", "is not the configured project's disposable harness state")
	}
	selection, err := Select(input.Policy, state.CleanupCapabilities(), input.Inventory, input.LifetimeRecords, input.Now)
	if err != nil {
		return WipePlan{}, err
	}
	if err := applyAttempts(&selection, input.History); err != nil {
		return WipePlan{}, err
	}
	plan := WipePlan{
		Mode: ModeTestWipe, ProjectID: input.Policy.ProjectID, HarnessIntegritySHA256: state.IntegritySHA256(),
		BootstrapPhase: state.BootstrapPhase(), TestUsability: state.TestUsability(),
		RunNumber: input.History.PriorRuns + 1, Selection: selection,
	}
	switch {
	case input.History.PriorRuns == 0:
		plan.Disposition = DispositionFirstRunObserveOnly
	case state.BootstrapPhase() != isolation.BootstrapPhaseOpen || state.TestUsability() != isolation.TestUsabilityUsable:
		plan.Disposition = DispositionHarnessNotUsable
	case len(selection.Deletions) == 0:
		plan.Disposition = DispositionNothingExpired
	default:
		plan.Disposition = DispositionDelete
	}
	plan.seal = sealPlan(plan)
	return plan, nil
}

// applyAttempts numbers each deletion from the durable outstanding record so
// a retry after partial completion is visibly a retry, never a first attempt.
func applyAttempts(selection *Selection, history History) error {
	attempts := make(map[string]uint32, len(history.Outstanding))
	for index, outstanding := range history.Outstanding {
		if outstanding.CanonicalKey == "" || outstanding.Attempts == 0 {
			return inputError(indexedField("history.outstanding", index), "must identify one attempted deletion")
		}
		if _, duplicate := attempts[outstanding.CanonicalKey]; duplicate {
			return inputError(indexedField("history.outstanding", index), "duplicates an earlier outstanding deletion")
		}
		attempts[outstanding.CanonicalKey] = outstanding.Attempts
	}
	for index := range selection.Deletions {
		deletion := &selection.Deletions[index]
		deletion.Attempt = attempts[deletion.Identity.CanonicalKey] + 1
		deletion.seal = sealDeletion(*deletion)
	}
	return nil
}

func sealPlan(plan WipePlan) string {
	record := planRecord(plan)
	record.IntegritySHA256 = ""
	fingerprint, err := canonicalFingerprint(record)
	if err != nil {
		return ""
	}
	return fingerprint
}
