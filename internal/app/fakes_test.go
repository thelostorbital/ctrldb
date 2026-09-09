// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

var errFakeCrash = errors.New("simulated process crash")

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(time.Second)
	return clock.now
}

func (clock *fakeClock) Peek() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

// fakeStore is an in-memory generation-preconditioned control store. It can
// simulate a crash at an exact journal sequence and lock loss.
type fakeStore struct {
	mu             sync.Mutex
	envelope       EnvelopeRecord
	journal        []domain.JournalEntry
	lock           LockRecord
	lockGeneration uint64
	harness        *HarnessStateRecord
	claims         []StepClaimRecord
	generation     uint64
	crashAtSeq     uint64
	refreshFails   bool
	foreignHolder  bool
	replaceBumps   bool
	calls          map[string]int
}

func newFakeStore() *fakeStore {
	return &fakeStore{envelope: EnvelopeRecord{Hash: testEnvelope, Generation: 1}, calls: map[string]int{}}
}

func (store *fakeStore) count(name string) {
	store.calls[name]++
}

func (store *fakeStore) next() uint64 {
	store.generation++
	return store.generation
}

func (store *fakeStore) ReadEnvelope(context.Context) (EnvelopeRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.count("ReadEnvelope")
	return store.envelope, nil
}

func (store *fakeStore) ReadJournal(_ context.Context, operationID string) ([]domain.JournalEntry, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.count("ReadJournal")
	result := make([]domain.JournalEntry, 0)
	for _, entry := range store.journal {
		if entry.OperationID == operationID {
			result = append(result, entry)
		}
	}
	return result, nil
}

func (store *fakeStore) AppendJournalEntry(_ context.Context, entry domain.JournalEntry) (uint64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.count("AppendJournalEntry")
	if store.crashAtSeq != 0 && entry.Sequence == store.crashAtSeq {
		store.crashAtSeq = 0
		return 0, errFakeCrash
	}
	if entry.Sequence != uint64(len(store.journal)+1) {
		return 0, ErrStoreConflict
	}
	store.journal = append(store.journal, entry)
	return store.next(), nil
}

func (store *fakeStore) ReadLock(context.Context) (LockRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lockGeneration == 0 {
		return LockRecord{}, ErrStoreNotFound
	}
	return store.lock, nil
}

func (store *fakeStore) AcquireLock(_ context.Context, request LockRequest) (LockRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.count("AcquireLock")
	if store.foreignHolder {
		return LockRecord{}, ErrStoreConflict
	}
	if store.lock.State == LockHeld && store.lock.OperationID != request.OperationID && request.Now.Before(store.lock.LeaseUntil) {
		return LockRecord{}, ErrStoreConflict
	}
	store.lockGeneration = store.next()
	store.lock = LockRecord{
		State: LockHeld, OperationID: request.OperationID, PlanID: request.PlanID, WorkflowID: request.WorkflowID,
		AcquiredAt: request.Now, HeartbeatAt: request.Now, LeaseUntil: request.Now.Add(request.Lease), Generation: store.lockGeneration,
	}
	return store.lock, nil
}

func (store *fakeStore) RefreshLock(_ context.Context, held LockRecord, now time.Time) (LockRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.count("RefreshLock")
	if store.refreshFails || held.Generation != store.lockGeneration || store.lock.State != LockHeld {
		return LockRecord{}, ErrStoreConflict
	}
	store.lockGeneration = store.next()
	store.lock.HeartbeatAt = now
	store.lock.LeaseUntil = now.Add(LockLease)
	store.lock.Generation = store.lockGeneration
	return store.lock, nil
}

func (store *fakeStore) ReleaseLock(_ context.Context, held LockRecord, _ time.Time) (LockRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.count("ReleaseLock")
	if held.Generation != store.lockGeneration {
		return LockRecord{}, ErrStoreConflict
	}
	store.lockGeneration = store.next()
	store.lock.State = LockReleased
	store.lock.Generation = store.lockGeneration
	return store.lock, nil
}

func (store *fakeStore) ReadHarnessState(context.Context) (HarnessStateRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.harness == nil {
		return HarnessStateRecord{}, ErrStoreNotFound
	}
	return *store.harness, nil
}

func (store *fakeStore) CreateHarnessState(_ context.Context, state isolation.HarnessStateV1) (HarnessStateRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.count("CreateHarnessState")
	if store.harness != nil {
		return HarnessStateRecord{}, ErrStoreConflict
	}
	store.harness = &HarnessStateRecord{State: state, Generation: store.next()}
	return *store.harness, nil
}

func (store *fakeStore) ReplaceHarnessState(_ context.Context, expected uint64, state isolation.HarnessStateV1) (HarnessStateRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.count("ReplaceHarnessState")
	if store.replaceBumps {
		store.harness.Generation = store.next()
	}
	if store.harness == nil || store.harness.Generation != expected {
		return HarnessStateRecord{}, ErrStoreConflict
	}
	store.harness = &HarnessStateRecord{State: state, Generation: store.next()}
	return *store.harness, nil
}

func (store *fakeStore) ClaimStep(_ context.Context, claim StepClaim) (StepClaimRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.count("ClaimStep")
	for _, existing := range store.claims {
		if existing.Claim.OperationID == claim.OperationID && existing.Claim.StepID == claim.StepID && existing.Claim.Attempt == claim.Attempt {
			return StepClaimRecord{}, ErrStoreConflict
		}
	}
	record := StepClaimRecord{Claim: claim, Generation: store.next()}
	store.claims = append(store.claims, record)
	return record, nil
}

func (store *fakeStore) ListStepClaims(_ context.Context, operationID string) ([]StepClaimRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]StepClaimRecord, 0)
	for _, record := range store.claims {
		if record.Claim.OperationID == operationID {
			result = append(result, record)
		}
	}
	return result, nil
}

func (store *fakeStore) states() []domain.OperationState {
	result := make([]domain.OperationState, 0)
	for _, entry := range store.journal {
		if entry.Kind == domain.JournalEntryTransition {
			result = append(result, entry.OperationState)
		}
	}
	return result
}

// fakeProvider is the shared observed-world model behind the observer and
// every adapter: which desired resources currently exist.
type fakeProvider struct {
	mu           sync.Mutex
	clock        *fakeClock
	present      map[string]bool
	createdBy    map[string]string
	applied      map[string]bool
	conflicting  map[string]bool
	staleObserve bool
	observeCalls int
	applies      []MutationAuthorization
	compensates  []MutationAuthorization
	compensated  []string
	failures     map[string][]error
	proveDenied  bool
	gateFails    bool
	credFails    bool
	sleeps       []time.Duration
	cancel       bool
}

func newFakeProvider(clock *fakeClock) *fakeProvider {
	return &fakeProvider{clock: clock, present: map[string]bool{}, createdBy: map[string]string{}, applied: map[string]bool{},
		conflicting: map[string]bool{}, failures: map[string][]error{}}
}

func (provider *fakeProvider) Describe(_ context.Context, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepObservation, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.observeCalls++
	now := provider.clock.Peek()
	observation := StepObservation{ObservedAt: now, ValidUntil: now.Add(5 * time.Minute)}
	if provider.staleObserve {
		observation.ObservedAt, observation.ValidUntil = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	parts := make([]string, 0, len(resources))
	for _, resource := range resources {
		state := ResourceAbsent
		if provider.present[resource.ID] {
			state = ResourcePartial
			if provider.applied[intent.StepID] || intent.Kind == bootstrap.IntentIsolationGate {
				state = ResourceDesired
			}
		}
		if provider.conflicting[resource.ID] {
			state = ResourceConflicting
		}
		observation.Resources = append(observation.Resources, ResourceObservation{ResourceID: resource.ID, State: state})
		parts = append(parts, resource.ID+"="+string(state))
	}
	sort.Strings(parts)
	revision, _ := hashJSON(parts)
	observation.Revision = revision
	return observation, nil
}

func (provider *fakeProvider) Apply(_ context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if err := checkAuthorization(authorization, intent); err != nil {
		return StepResult{}, err
	}
	provider.applies = append(provider.applies, authorization)
	if queue := provider.failures[intent.StepID]; len(queue) != 0 {
		failure := queue[0]
		provider.failures[intent.StepID] = queue[1:]
		var typed *StepFailure
		if errors.As(failure, &typed) && typed.Mutation == domain.MutationOccurred {
			for _, resource := range resources[:1] {
				if !provider.present[resource.ID] {
					provider.present[resource.ID] = true
					provider.createdBy[resource.ID] = intent.StepID
				}
			}
		}
		return StepResult{}, failure
	}
	created := make([]string, 0)
	for _, resource := range resources {
		if !provider.present[resource.ID] {
			provider.present[resource.ID] = true
			provider.createdBy[resource.ID] = intent.StepID
			created = append(created, resource.ID)
		}
	}
	provider.applied[intent.StepID] = true
	return StepResult{MutationOccurred: true, CreatedResourceIDs: created, Summary: "applied " + intent.StepID}, nil
}

func (provider *fakeProvider) Compensate(_ context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if err := checkAuthorization(authorization, intent); err != nil {
		return StepResult{}, err
	}
	provider.compensates = append(provider.compensates, authorization)
	for _, resource := range resources {
		if provider.createdBy[resource.ID] == intent.StepID {
			delete(provider.present, resource.ID)
			delete(provider.createdBy, resource.ID)
			provider.compensated = append(provider.compensated, resource.ID)
		}
	}
	delete(provider.applied, intent.StepID)
	return StepResult{MutationOccurred: len(resources) != 0, Summary: "compensated " + intent.StepID}, nil
}

func checkAuthorization(authorization MutationAuthorization, intent bootstrap.StepIntent) error {
	if authorization.PlanDocumentSHA256 == "" || authorization.PlanV1Hash == "" || authorization.OperationID == "" ||
		authorization.StepID != intent.StepID || authorization.Attempt == 0 || authorization.ClaimGeneration == 0 ||
		authorization.EnvelopeBindingSHA256 != intent.EnvelopeBindingSHA256 || authorization.ExecutingIdentity != intent.ExecutingIdentity ||
		authorization.ObservationRevision == "" || authorization.Now.IsZero() || !authorization.Now.Before(authorization.ValidUntil) {
		return fmt.Errorf("adapter received an incomplete authorization: %+v", authorization)
	}
	return nil
}

func (provider *fakeProvider) Prove(_ context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, _ []bootstrap.DesiredResource) (bootstrap.PermissionEvidence, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if err := checkAuthorization(authorization, intent); err != nil {
		return bootstrap.PermissionEvidence{}, err
	}
	if provider.proveDenied {
		return bootstrap.PermissionEvidence{}, errors.New("permission denied")
	}
	step := intent.StepID
	return permissionEvidenceFor(step, authorization.Now), nil
}

func (provider *fakeProvider) Verify(_ context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, _ []bootstrap.DesiredResource) (isolation.T8Evidence, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if err := checkAuthorization(authorization, intent); err != nil {
		return isolation.T8Evidence{}, err
	}
	if provider.gateFails {
		return isolation.T8Evidence{}, &StepFailure{Class: domain.RetryFailureValidation, Mutation: domain.MutationNotOccurred, Summary: "TEST-ISO-03 failed"}
	}
	return isolation.T8Evidence{Revision: strings.Repeat("b", 64), ObservedAt: authorization.Now, ValidUntil: authorization.Now.Add(30 * time.Minute)}, nil
}

func (provider *fakeProvider) VerifyHumanCredential(_ context.Context, account string) (CredentialEvidence, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.credFails {
		return CredentialEvidence{}, errors.New("credential expired")
	}
	now := provider.clock.Peek()
	return CredentialEvidence{Account: account, Identity: domain.IdentityHuman, VerifiedAt: now, ValidUntil: now.Add(10 * time.Minute)}, nil
}

func (provider *fakeProvider) Sleep(_ context.Context, delay time.Duration) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.sleeps = append(provider.sleeps, delay)
	return nil
}

func (provider *fakeProvider) CancelRequested() bool {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.cancel
}

func (provider *fakeProvider) appliedSteps() []string {
	result := make([]string, 0, len(provider.applies))
	for _, authorization := range provider.applies {
		result = append(result, authorization.StepID)
	}
	return result
}

func (provider *fakeProvider) hasApplied(stepID string) bool {
	return slices.Contains(provider.appliedSteps(), stepID)
}

type harness struct {
	clock    *fakeClock
	store    *fakeStore
	provider *fakeProvider
	engine   *Engine
	plan     bootstrap.CompiledPlan
}

func newHarness(t *testing.T) *harness {
	clock := &fakeClock{now: testNow.Add(2 * time.Minute)}
	store := newFakeStore()
	provider := newFakeProvider(clock)
	engine, err := NewEngine(Dependencies{
		Store: store, Observer: provider, Credentials: provider, Clock: clock.Now, Sleep: provider.Sleep, CancelRequested: provider.CancelRequested,
		Adapters: Adapters{Storage: provider, Network: provider, Identity: provider, Wipe: provider, Prover: provider, Gate: provider},
	})
	if err != nil {
		t.Fatalf("NewEngine() unexpected error: %v", err)
	}
	return &harness{clock: clock, store: store, provider: provider, engine: engine, plan: fixturePlan(t)}
}

func (fixture *harness) run() (RunReport, error) {
	return fixture.engine.Execute(context.Background(), RunRequest{
		Plan: fixture.plan, Approval: fixtureApproval(fixture.plan), OperationID: testOperationID,
	})
}

func permissionEvidenceFor(step string, now time.Time) bootstrap.PermissionEvidence {
	evidence := bootstrap.PermissionEvidence{
		Account: testAccount, Project: testProject, Schema: bootstrap.PermissionEvidenceSchemaV1,
		ObservedAt: now, ValidUntil: now.Add(4 * time.Minute), Grants: []bootstrap.PermissionGrant{},
	}
	for _, candidate := range stepPermissions {
		if candidate.step != step {
			continue
		}
		for _, permission := range candidate.permissions {
			evidence.Grants = append(evidence.Grants, bootstrap.PermissionGrant{StepID: step, Identity: domain.IdentityHuman, Permission: permission, Granted: true})
		}
	}
	revision, _ := hashJSON(evidence)
	evidence.Revision = revision
	return evidence
}
