// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

const (
	// LockLease is the environment lock lease (ARCHITECTURE "Lock protocol").
	LockLease = 300 * time.Second
	// MaxPause bounds how long a paused operation stays resumable.
	MaxPause = 24 * time.Hour
)

var (
	// ErrInvalidRun is returned when the run request is incomplete.
	ErrInvalidRun = errors.New("invalid WF-TEST-01 run request")
	// ErrLockHeld is returned when another operation holds the lock (exit 5).
	ErrLockHeld = errors.New("environment lock held by another operation")
	// ErrDrift is returned when re-observed state contradicts the journal or
	// the approved desired state (exit 6). Nothing is guessed.
	ErrDrift = errors.New("observed state drifted from the approved plan")
	// ErrOperationPaused is returned when the run stopped at a durable
	// boundary and may be resumed (exit 8).
	ErrOperationPaused = errors.New("operation paused")
	// ErrOperationFailed is returned for a terminal failure.
	ErrOperationFailed = errors.New("operation failed")
	// ErrOperationCancelled is returned when a cancellation was honoured.
	ErrOperationCancelled = errors.New("operation cancelled")
	// ErrOperationTerminal is returned when the journal is already terminal.
	ErrOperationTerminal = errors.New("operation already terminal")
	// ErrJournalInvalid is returned when the durable journal is unusable.
	ErrJournalInvalid = errors.New("durable journal invalid")

	operationIDPattern = regexp.MustCompile(`^op-[0-9a-f]{16}$`)
)

// Dependencies are the complete I/O surfaces the engine drives. Every field
// is required; the engine refuses to start with any nil dependency.
type Dependencies struct {
	Store           ControlStore
	Observer        StepObserver
	Adapters        Adapters
	Credentials     CredentialVerifier
	Clock           func() time.Time
	Sleep           func(ctx context.Context, delay time.Duration) error
	CancelRequested func() bool
}

// Engine executes and resumes one approved WF-TEST-01 bootstrap operation.
type Engine struct {
	deps Dependencies
}

// NewEngine validates the dependency set. It performs no I/O.
func NewEngine(deps Dependencies) (*Engine, error) {
	if deps.Store == nil || deps.Observer == nil || deps.Credentials == nil || deps.Clock == nil || deps.Sleep == nil ||
		deps.CancelRequested == nil || deps.Adapters.Storage == nil || deps.Adapters.Network == nil ||
		deps.Adapters.Identity == nil || deps.Adapters.Wipe == nil || deps.Adapters.Prover == nil || deps.Adapters.Gate == nil {
		return nil, fmt.Errorf("%w: every dependency is required", ErrInvalidRun)
	}
	return &Engine{deps: deps}, nil
}

// RunRequest binds one operation to one approved plan and approval proof.
type RunRequest struct {
	Plan        bootstrap.CompiledPlan
	Approval    ApprovalProof
	OperationID string
}

// StepReport is the per-step outcome summary derived from the journal.
type StepReport struct {
	StepID           string
	Outcome          domain.StepOutcome
	Attempts         uint32
	MutationOccurred bool
}

// RunReport is the durable-journal-derived outcome of Execute.
type RunReport struct {
	OperationID            string
	PlanID                 string
	State                  domain.OperationState
	BootstrapPhase         isolation.BootstrapPhase
	TestUsability          isolation.TestUsability
	PointOfNoReturnCrossed bool
	PauseReason            string
	Resumable              bool
	Steps                  []StepReport
}

// PlanPreview is the non-mutating rendering of an approved plan. Producing it
// touches no store, observer, or adapter.
type PlanPreview struct {
	PlanID              string
	PlanHash            string
	DocumentHash        string
	Steps               []bootstrap.StepIntent
	Risks               bootstrap.RiskSummary
	PointOfNoReturnStep string
}

// Preview renders the plan-only view. It is deliberately a pure function of
// the compiled plan so plan-only can never acquire mutation capability.
func (engine *Engine) Preview(plan bootstrap.CompiledPlan) (PlanPreview, error) {
	if plan.DocumentHash() == "" {
		return PlanPreview{}, fmt.Errorf("%w: plan is not sealed", ErrInvalidRun)
	}
	reviewed := plan.Plan()
	return PlanPreview{
		PlanID: reviewed.PlanID, PlanHash: reviewed.PlanHash, DocumentHash: plan.DocumentHash(),
		Steps: plan.Intents(), Risks: plan.Risks(), PointOfNoReturnStep: plan.ExecutionContract().PointOfNoReturn(),
	}, nil
}

// session is the in-memory view of one Execute call. Every durable change is
// appended to the journal before the in-memory state advances.
type session struct {
	engine   *Engine
	ctx      context.Context
	request  RunRequest
	reviewed domain.Plan
	contract domain.ExecutionContract
	intents  []bootstrap.StepIntent
	byID     map[string]bootstrap.DesiredResource
	seed     isolation.HarnessStateSeed
	expected isolation.HarnessStateExpectation
	machine  *workflow.Machine
	entries  []domain.JournalEntry
	claims   []StepClaimRecord
	lock     LockRecord
	lastTime time.Time
	t8       *isolation.T8Evidence
}

// Execute starts or resumes the operation. It returns the journal-derived
// report together with a sentinel error describing a non-complete outcome.
func (engine *Engine) Execute(ctx context.Context, request RunRequest) (RunReport, error) {
	run, err := engine.openSession(ctx, request)
	if err != nil {
		return RunReport{}, err
	}
	err = run.drive()
	if err != nil && run.machine.State() == domain.OperationLock {
		run.releaseLock()
	}
	return run.report(), err
}

func (engine *Engine) openSession(ctx context.Context, request RunRequest) (*session, error) {
	if ctx == nil || !operationIDPattern.MatchString(request.OperationID) || request.Plan.DocumentHash() == "" {
		return nil, fmt.Errorf("%w: operation ID and sealed plan are required", ErrInvalidRun)
	}
	envelope, err := engine.deps.Store.ReadEnvelope(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: bootstrap envelope: %v", ErrInvalidRun, err)
	}
	seed, err := HarnessSeed(request.Plan, request.OperationID, envelope, request.Approval)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRun, err)
	}
	run := &session{
		engine: engine, ctx: ctx, request: request, reviewed: request.Plan.Plan(),
		contract: request.Plan.ExecutionContract(), intents: request.Plan.Intents(),
		byID: make(map[string]bootstrap.DesiredResource), seed: seed, expected: harnessExpectation(seed),
	}
	for _, resource := range request.Plan.DesiredResources() {
		run.byID[resource.ID] = resource
	}
	if err := run.loadJournal(); err != nil {
		return nil, err
	}
	return run, nil
}

func (run *session) now() time.Time {
	value := utcNow(run.engine.deps.Clock)
	if value.Before(run.lastTime) {
		value = run.lastTime
	}
	return value
}

func (run *session) loadJournal() error {
	entries, err := run.engine.deps.Store.ReadJournal(run.ctx, run.request.OperationID)
	if err != nil && !errors.Is(err, ErrStoreNotFound) {
		return fmt.Errorf("%w: %v", ErrJournalInvalid, err)
	}
	claims, err := run.engine.deps.Store.ListStepClaims(run.ctx, run.request.OperationID)
	if err != nil && !errors.Is(err, ErrStoreNotFound) {
		return fmt.Errorf("%w: claims: %v", ErrJournalInvalid, err)
	}
	run.claims = claims
	if len(entries) == 0 {
		machine, err := workflow.NewMachine(run.request.OperationID, run.reviewed.PlanID)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRun, err)
		}
		run.machine = machine
		return nil
	}
	if err := workflow.ValidateJournal(entries); err != nil {
		return fmt.Errorf("%w: %v", ErrJournalInvalid, err)
	}
	first, last := entries[0], entries[len(entries)-1]
	if first.PlanID != run.reviewed.PlanID || first.ContractHash != run.contract.Digest() {
		return fmt.Errorf("%w: journal binds a different plan or contract", ErrJournalInvalid)
	}
	machine, err := workflow.RestoreMachine(run.request.OperationID, run.reviewed.PlanID, last.OperationState)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJournalInvalid, err)
	}
	run.machine = machine
	run.entries = entries
	run.lastTime = last.RecordedAt
	return nil
}

func (run *session) baseEntry(kind domain.JournalEntryKind, state domain.OperationState) domain.JournalEntry {
	return domain.JournalEntry{
		Schema: domain.JournalSchemaV1, OperationID: run.request.OperationID, PlanID: run.reviewed.PlanID,
		ContractHash: run.contract.Digest(), Sequence: uint64(len(run.entries) + 1), Kind: kind,
		RecordedAt: run.now(), OperationState: state,
	}
}

func (run *session) append(entry domain.JournalEntry) error {
	stream := append(append([]domain.JournalEntry(nil), run.entries...), entry)
	if err := workflow.ValidateJournal(stream); err != nil {
		return fmt.Errorf("%w: %v", ErrJournalInvalid, err)
	}
	if _, err := run.engine.deps.Store.AppendJournalEntry(run.ctx, entry); err != nil {
		return fmt.Errorf("%w: append: %v", ErrJournalInvalid, err)
	}
	run.entries = stream
	run.lastTime = entry.RecordedAt
	return nil
}

// transition journals the next state before the machine advances. A PAUSED
// transition carries complete pause metadata.
func (run *session) transition(next domain.OperationState, pause *domain.JournalPause) error {
	if !workflow.CanTransition(run.machine.State(), next) {
		return fmt.Errorf("%w: %s -> %s", workflow.ErrInvalidTransition, run.machine.State(), next)
	}
	entry := run.baseEntry(domain.JournalEntryTransition, next)
	entry.Pause = pause
	if err := run.append(entry); err != nil {
		return err
	}
	return run.machine.Transition(next)
}

func (run *session) pause(reason string) error {
	now := run.now()
	resumeBy := run.reviewed.ExpiresAt
	if limit := now.Add(MaxPause); limit.Before(resumeBy) {
		resumeBy = limit
	}
	reapproval := false
	if !resumeBy.After(now) {
		resumeBy = now.Add(time.Second)
		reapproval = true
	}
	pause := &domain.JournalPause{
		PausedAt: now, PauseReason: redact.Sanitize(reason), MutationOccurred: run.mutationMayHaveOccurred(),
		ResumeBy: resumeBy, ReapprovalRequired: reapproval,
	}
	if err := run.transition(domain.OperationPaused, pause); err != nil {
		return err
	}
	run.releaseLock()
	return nil
}

func (run *session) mutationMayHaveOccurred() bool {
	for _, entry := range run.entries {
		if entry.Kind == domain.JournalEntryStep && (entry.Step.MutationOccurred || entry.Step.Outcome == domain.StepUnknown) {
			return true
		}
		if entry.Pause != nil && entry.Pause.MutationOccurred {
			return true
		}
	}
	return false
}

func (run *session) pointOfNoReturnCrossed() bool {
	pointID := run.contract.PointOfNoReturn()
	for _, entry := range run.entries {
		if entry.Kind == domain.JournalEntryStep && entry.Step.ID == pointID &&
			(entry.Step.MutationOccurred || entry.Step.Outcome == domain.StepUnknown) {
			return true
		}
	}
	return false
}

func (run *session) releaseLock() {
	if run.lock.Generation == 0 {
		return
	}
	if _, err := run.engine.deps.Store.ReleaseLock(run.ctx, run.lock, run.now()); err == nil {
		run.lock = LockRecord{}
	}
}

func (run *session) report() RunReport {
	report := RunReport{
		OperationID: run.request.OperationID, PlanID: run.reviewed.PlanID, State: run.machine.State(),
		BootstrapPhase: isolation.BootstrapPhasePending, TestUsability: isolation.TestUsabilityUnusable,
		PointOfNoReturnCrossed: run.pointOfNoReturnCrossed(),
	}
	if record, err := run.engine.deps.Store.ReadHarnessState(run.ctx); err == nil {
		report.BootstrapPhase = record.State.BootstrapPhase()
		report.TestUsability = record.State.TestUsability()
	}
	steps := make(map[string]*StepReport)
	order := make([]string, 0)
	for _, entry := range run.entries {
		if entry.Pause != nil {
			report.PauseReason = entry.Pause.PauseReason.String()
			report.Resumable = !entry.Pause.ReapprovalRequired
		}
		if entry.Kind != domain.JournalEntryStep {
			continue
		}
		item, ok := steps[entry.Step.ID]
		if !ok {
			item = &StepReport{StepID: entry.Step.ID}
			steps[entry.Step.ID] = item
			order = append(order, entry.Step.ID)
		}
		item.Outcome = entry.Step.Outcome
		item.Attempts = entry.Step.Attempt
		item.MutationOccurred = item.MutationOccurred || entry.Step.MutationOccurred
	}
	for _, id := range order {
		report.Steps = append(report.Steps, *steps[id])
	}
	if report.State != domain.OperationPaused {
		report.Resumable = false
		report.PauseReason = ""
	}
	return report
}
