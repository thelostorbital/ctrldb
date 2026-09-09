// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var errSimulatedCrash = errors.New("simulated crash after provider mutation")

// fakeAuditBucket is an in-memory provider with exact typed state. A crash
// hook fires after the named mutation has already been applied, modelling a
// process death between the provider call and the local record.
type fakeAuditBucket struct {
	mutex       sync.Mutex
	clock       func() time.Time
	globalTaken map[string]bool
	buckets     map[string]*BucketState
	objects     map[string]map[string]fakeObject
	generation  Generation
	crashAfter  map[string]bool
	calls       map[string]int
}

type fakeObject struct {
	descriptor ObjectDescriptor
	content    []byte
}

func newFakeAuditBucket(clock func() time.Time) *fakeAuditBucket {
	return &fakeAuditBucket{clock: clock, globalTaken: map[string]bool{}, buckets: map[string]*BucketState{},
		objects: map[string]map[string]fakeObject{}, crashAfter: map[string]bool{}, calls: map[string]int{}}
}

func (fake *fakeAuditBucket) count(name string) int {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	return fake.calls[name]
}

func (fake *fakeAuditBucket) after(name string) error {
	fake.calls[name]++
	if fake.crashAfter[name] {
		delete(fake.crashAfter, name)
		return errSimulatedCrash
	}
	return nil
}

func (fake *fakeAuditBucket) DescribeBucket(_ context.Context, name string) (BucketState, bool, error) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.calls["describe-bucket"]++
	state, exists := fake.buckets[name]
	if !exists {
		return BucketState{}, false, nil
	}
	return *state, true, nil
}

func (fake *fakeAuditBucket) CreateAuditBucket(_ context.Context, identity BucketIdentity) error {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	if fake.globalTaken[identity.Name] || fake.buckets[identity.Name] != nil {
		fake.calls["create-conflict"]++
		return ErrBucketNameConflict
	}
	fake.buckets[identity.Name] = &BucketState{Identity: identity, UniformBucketLevelAccess: true,
		PublicAccessPrevention: PublicAccessPreventionEnforced, StorageClass: AuditStorageClass, Versioning: true,
		Metageneration: 1, TimeCreated: fake.clock().UTC()}
	fake.objects[identity.Name] = map[string]fakeObject{}
	return fake.after("create-bucket")
}

func (fake *fakeAuditBucket) ConfigureArchiveLifecycle(_ context.Context, identity BucketIdentity) error {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	bucket := fake.buckets[identity.Name]
	if bucket == nil {
		return errors.New("fake: lifecycle on absent bucket")
	}
	bucket.LifecycleArchiveAfterDay = AuditArchiveAfterDays
	bucket.Metageneration++
	return fake.after("lifecycle")
}

func (fake *fakeAuditBucket) UploadCreateOnly(_ context.Context, identity BucketIdentity, object AuditObjectName, content []byte) (ObjectDescriptor, error) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	objects := fake.objects[identity.Name]
	if objects == nil {
		return ObjectDescriptor{}, errors.New("fake: upload to absent bucket")
	}
	if _, exists := objects[object.String()]; exists {
		return ObjectDescriptor{}, fmt.Errorf("%w: %s", ErrPreconditionFailed, object)
	}
	fake.generation++
	descriptor := DescribeContent(content)
	descriptor.Generation = fake.generation
	objects[object.String()] = fakeObject{descriptor: descriptor, content: append([]byte(nil), content...)}
	return descriptor, fake.after("upload:" + object.String())
}

func (fake *fakeAuditBucket) DescribeObject(_ context.Context, identity BucketIdentity, object AuditObjectName) (ObjectDescriptor, bool, error) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.calls["describe-object"]++
	stored, exists := fake.objects[identity.Name][object.String()]
	if !exists {
		return ObjectDescriptor{}, false, nil
	}
	return stored.descriptor, true, nil
}

func (fake *fakeAuditBucket) ConfigureRetention(_ context.Context, identity BucketIdentity, seconds int64) error {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	bucket := fake.buckets[identity.Name]
	if bucket == nil || bucket.RetentionLocked {
		return errors.New("fake: retention change refused")
	}
	bucket.RetentionSeconds = seconds
	bucket.Metageneration++
	return fake.after("retention")
}

func (fake *fakeAuditBucket) ReadObject(_ context.Context, identity BucketIdentity, object AuditObjectName) ([]byte, ObjectDescriptor, bool, error) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.calls["read-object"]++
	stored, exists := fake.objects[identity.Name][object.String()]
	if !exists {
		return nil, ObjectDescriptor{}, false, nil
	}
	return append([]byte(nil), stored.content...), stored.descriptor, true, nil
}

func (fake *fakeAuditBucket) LockRetention(_ context.Context, identity BucketIdentity, expectedMetageneration int64) error {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	bucket := fake.buckets[identity.Name]
	if bucket == nil || bucket.RetentionSeconds == 0 {
		return errors.New("fake: lock without retention")
	}
	if bucket.Metageneration != expectedMetageneration {
		fake.calls["lock-precondition-failed"]++
		return fmt.Errorf("%w: bucket metageneration moved before the lock", ErrPreconditionFailed)
	}
	bucket.RetentionLocked = true
	bucket.Metageneration++
	return fake.after("lock")
}

func (fake *fakeAuditBucket) seedForeignObject(bucket, name string, content []byte) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.generation++
	descriptor := DescribeContent(content)
	descriptor.Generation = fake.generation
	fake.objects[bucket][name] = fakeObject{descriptor: descriptor, content: content}
}

func (fake *fakeAuditBucket) seedBucket(identity BucketIdentity, mutate func(*BucketState)) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	state := &BucketState{Identity: identity, UniformBucketLevelAccess: true, PublicAccessPrevention: PublicAccessPreventionEnforced,
		StorageClass: AuditStorageClass, Versioning: true, Metageneration: 3, TimeCreated: fixtureNow.Add(-24 * time.Hour)}
	if mutate != nil {
		mutate(state)
	}
	fake.buckets[identity.Name] = state
	fake.objects[identity.Name] = map[string]fakeObject{}
}

type handoffFixture struct {
	envelope  BootstrapEnvelopeV1
	directory StateDirectory
	fake      *fakeAuditBucket
	handoff   *AuditHandoff
	identity  BucketIdentity
}

func newHandoffFixture(t *testing.T) *handoffFixture {
	t.Helper()
	envelope := fixtureEnvelope(t)
	directory := fixtureStateDirectory(t)
	current := fixtureNow.Add(3 * time.Minute)
	clock := func() time.Time { current = current.Add(time.Second); return current }
	fake := newFakeAuditBucket(clock)
	handoff, err := NewAuditHandoff(directory, fake, clock)
	if err != nil {
		t.Fatalf("NewAuditHandoff() error: %v", err)
	}
	return &handoffFixture{envelope: envelope, directory: directory, fake: fake, handoff: handoff,
		identity: BucketIdentity{Name: envelope.AuditBucket(), Project: envelope.Project(), Location: envelope.AuditBucketLocation()}}
}

func (fixture *handoffFixture) phases(t *testing.T) []HandoffPhase {
	t.Helper()
	directory, _ := fixture.directory.handoffPath(fixtureOperationID)
	records, err := readHandoffRecords(directory, fixture.envelope)
	if err != nil {
		t.Fatalf("readHandoffRecords() error: %v", err)
	}
	result := make([]HandoffPhase, len(records))
	for index, record := range records {
		result[index] = record.Phase
	}
	return result
}

func (fixture *handoffFixture) assertComplete(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	status, err := fixture.handoff.Bootstrap(ctx, fixture.envelope)
	if err != nil || status.Phase.order() < PhaseHandoffVerified.order() {
		t.Fatalf("Bootstrap() = %#v, %v", status, err)
	}
	locked, err := fixture.handoff.LockRetention(ctx, fixture.envelope)
	if err != nil || locked.Phase != PhaseRetentionLocked || !locked.RetentionLocked {
		t.Fatalf("LockRetention() = %#v, %v", locked, err)
	}
	fake := fixture.fake
	if fake.count("create-bucket") != 1 || fake.count("lock") != 1 || fake.count("retention") != 1 || fake.count("lifecycle") != 1 ||
		fake.count("create-conflict") != 0 || fake.count("lock-precondition-failed") != 0 {
		t.Fatalf("mutation counts = %v", fake.calls)
	}
	envelopeName, _ := BootstrapEnvelopeObjectName(fixture.envelope.Environment(), fixtureOperationID)
	if fake.count("upload:"+envelopeName.String()) != 1 || fake.count("upload:"+fixture.envelope.FirstJournalObjectName().String()) != 1 {
		t.Fatalf("upload counts = %v", fake.calls)
	}
	state, _, _ := fake.DescribeBucket(ctx, fixture.identity.Name)
	if !state.RetentionLocked || state.RetentionSeconds != AuditRetentionSeconds || state.LifecycleArchiveAfterDay != AuditArchiveAfterDays || state.LifecycleDeleteRule {
		t.Fatalf("final bucket state = %#v", state)
	}
	want := []HandoffPhase{PhaseEnvelopeSealed, PhaseAuditBucketClaimed, PhaseAuditBucketCreated, PhaseEnvelopeUploaded, PhaseJournalUploaded,
		PhaseLifecycleConfigured, PhaseHandoffVerified, PhaseRetentionConfigured, PhaseRetentionLockClaimed, PhaseRetentionLocked}
	got := fixture.phases(t)
	if len(got) != len(want) {
		t.Fatalf("phases = %v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("phases = %v", got)
		}
	}
	// Re-running both steps is idempotent and performs no further mutation.
	if _, err := fixture.handoff.Bootstrap(ctx, fixture.envelope); err != nil {
		t.Fatalf("idempotent Bootstrap() error: %v", err)
	}
	if again, err := fixture.handoff.LockRetention(ctx, fixture.envelope); err != nil || again.Phase != PhaseRetentionLocked {
		t.Fatalf("idempotent LockRetention() = %#v, %v", again, err)
	}
	if fake.count("create-bucket") != 1 || fake.count("lock") != 1 || fake.count("retention") != 1 {
		t.Fatalf("idempotent rerun mutated: %v", fake.calls)
	}
}

func TestAuditHandoffCompletesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	newHandoffFixture(t).assertComplete(t)
}

func TestAuditHandoffResumesAfterCrashAtEveryBoundary(t *testing.T) {
	t.Parallel()
	envelopeName, _ := BootstrapEnvelopeObjectName("disposable-test", fixtureOperationID)
	journalName := fixtureEnvelope(t).FirstJournalObjectName().String()
	boundaries := []string{"create-bucket", "upload:" + envelopeName.String(), "upload:" + journalName, "lifecycle", "retention", "lock"}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			t.Parallel()
			fixture := newHandoffFixture(t)
			fixture.fake.crashAfter[boundary] = true
			ctx := context.Background()
			_, bootstrapErr := fixture.handoff.Bootstrap(ctx, fixture.envelope)
			if boundary == "retention" || boundary == "lock" {
				if bootstrapErr != nil {
					t.Fatalf("Bootstrap() error: %v", bootstrapErr)
				}
				if _, err := fixture.handoff.LockRetention(ctx, fixture.envelope); !errors.Is(err, errSimulatedCrash) {
					t.Fatalf("LockRetention() error = %v, want the simulated crash", err)
				}
			} else if !errors.Is(bootstrapErr, errSimulatedCrash) {
				t.Fatalf("Bootstrap() error = %v, want the simulated crash", bootstrapErr)
			}
			// A fresh process with the same state directory and provider resumes.
			resumed, err := NewAuditHandoff(fixture.directory, fixture.fake, fixture.handoff.clock)
			if err != nil {
				t.Fatal(err)
			}
			fixture.handoff = resumed
			if boundary == "create-bucket" {
				// The bucket exists but holds no envelope: only an operation-bound
				// remote marker adopts a bucket, so this blocks for explicit
				// recovery without any further mutation (D-158).
				_, err := fixture.handoff.Bootstrap(ctx, fixture.envelope)
				if !errors.Is(err, ErrPartialBootstrapBlocked) {
					t.Fatalf("resume after create crash error = %v, want ErrPartialBootstrapBlocked", err)
				}
				if fixture.fake.count("create-bucket") != 1 || fixture.fake.count("lifecycle") != 0 || fixture.fake.count("lock") != 0 {
					t.Fatalf("blocked resume mutated: %v", fixture.fake.calls)
				}
				return
			}
			fixture.assertComplete(t)
		})
	}
}

func TestAuditHandoffResumesBeforeAndAfterEnvelope(t *testing.T) {
	t.Parallel()
	fixture := newHandoffFixture(t)
	// Crash before the envelope: nothing exists yet; a fresh run proceeds.
	if _, err := os.Stat(filepath.Join(fixture.directory.Path(), "bootstrap-envelope-"+fixtureOperationID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("envelope exists early: %v", err)
	}
	// Crash after the envelope only: the file exists, no records, no bucket.
	if err := WriteBootstrapEnvelope(fixture.directory, fixture.envelope); err != nil {
		t.Fatal(err)
	}
	fixture.assertComplete(t)
}

func TestAuditHandoffRetryAcceptsOnlyTheSameEnvelopeHash(t *testing.T) {
	t.Parallel()
	fixture := newHandoffFixture(t)
	ctx := context.Background()
	if _, err := fixture.handoff.Bootstrap(ctx, fixture.envelope); err != nil {
		t.Fatal(err)
	}
	seed := fixtureSeed(t)
	seed.SealedAt = seed.SealedAt.Add(time.Second)
	different, err := SealBootstrapEnvelope(seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handoff.Bootstrap(ctx, different); !errors.Is(err, ErrEnvelopeConflict) {
		t.Fatalf("Bootstrap(different envelope) error = %v", err)
	}
	if _, err := fixture.handoff.LockRetention(ctx, different); !errors.Is(err, ErrEnvelopeConflict) {
		t.Fatalf("LockRetention(different envelope) error = %v", err)
	}
	if fixture.fake.count("lock") != 0 {
		t.Fatal("a conflicting envelope reached the retention lock")
	}
}

func TestAuditHandoffBucketNameConflictIsAnExplicitPreconditionFailure(t *testing.T) {
	t.Parallel()
	fixture := newHandoffFixture(t)
	fixture.fake.globalTaken[fixture.identity.Name] = true
	_, err := fixture.handoff.Bootstrap(context.Background(), fixture.envelope)
	if !errors.Is(err, ErrBucketNameConflict) || errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("Bootstrap() error = %v, want ErrBucketNameConflict", err)
	}
	if got := fixture.phases(t); len(got) != 2 || got[1] != PhaseAuditBucketClaimed {
		t.Fatalf("phases after conflict = %v (create must never be recorded)", got)
	}
	if fixture.fake.count("lock") != 0 || fixture.fake.count("describe-object") != 0 || fixture.fake.count("read-object") != 0 {
		t.Fatalf("calls after conflict = %v", fixture.fake.calls)
	}
}

func TestAuditHandoffBlocksUnrecordedOrConflictingPartialBuckets(t *testing.T) {
	t.Parallel()
	envelope := fixtureEnvelope(t)
	envelopeJSON, _ := envelope.CanonicalJSON()
	envelopeName, _ := BootstrapEnvelopeObjectName(envelope.Environment(), fixtureOperationID)
	tests := []struct {
		name  string
		seed  func(fixture *handoffFixture)
		wantE error
	}{
		{"unrecorded empty bucket", func(fixture *handoffFixture) { fixture.fake.seedBucket(fixture.identity, nil) }, ErrPartialBootstrapBlocked},
		{"bucket with a different envelope", func(fixture *handoffFixture) {
			fixture.fake.seedBucket(fixture.identity, nil)
			fixture.fake.seedForeignObject(fixture.identity.Name, envelopeName.String(), []byte(`{"foreign":true}`))
		}, ErrPartialBootstrapBlocked},
		{"noncompliant bucket without UBLA", func(fixture *handoffFixture) {
			fixture.fake.seedBucket(fixture.identity, func(state *BucketState) { state.UniformBucketLevelAccess = false })
		}, ErrPartialBootstrapBlocked},
		{"bucket in another project", func(fixture *handoffFixture) {
			fixture.fake.seedBucket(fixture.identity, func(state *BucketState) { state.Identity.Project = "other-project" })
		}, ErrPartialBootstrapBlocked},
		{"bucket in another location", func(fixture *handoffFixture) {
			fixture.fake.seedBucket(fixture.identity, func(state *BucketState) { state.Identity.Location = "europe-west1" })
		}, ErrPartialBootstrapBlocked},
		{"bucket with a delete lifecycle rule", func(fixture *handoffFixture) {
			fixture.fake.seedBucket(fixture.identity, func(state *BucketState) { state.LifecycleDeleteRule = true })
		}, ErrPartialBootstrapBlocked},
		{"bucket already retention locked", func(fixture *handoffFixture) {
			fixture.fake.seedBucket(fixture.identity, func(state *BucketState) {
				state.RetentionSeconds, state.RetentionLocked = AuditRetentionSeconds, true
			})
		}, ErrPartialBootstrapBlocked},
		{"bucket with a foreign retention period", func(fixture *handoffFixture) {
			fixture.fake.seedBucket(fixture.identity, func(state *BucketState) { state.RetentionSeconds = 86400 })
		}, ErrPartialBootstrapBlocked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newHandoffFixture(t)
			test.seed(fixture)
			_, err := fixture.handoff.Bootstrap(context.Background(), fixture.envelope)
			if !errors.Is(err, test.wantE) {
				t.Fatalf("Bootstrap() error = %v, want %v", err, test.wantE)
			}
			if fixture.fake.count("create-bucket") != 0 || fixture.fake.count("lock") != 0 || fixture.fake.count("retention") != 0 {
				t.Fatalf("blocked bootstrap mutated: %v", fixture.fake.calls)
			}
			for _, objects := range fixture.fake.objects {
				for name := range objects {
					if name == envelopeName.String() && string(objects[name].content) == string(envelopeJSON) {
						t.Fatal("blocked bootstrap uploaded the envelope")
					}
				}
			}
		})
	}
}

func TestAuditHandoffAdoptsBucketHoldingTheIdenticalEnvelope(t *testing.T) {
	t.Parallel()
	fixture := newHandoffFixture(t)
	envelopeJSON, _ := fixture.envelope.CanonicalJSON()
	envelopeName, _ := BootstrapEnvelopeObjectName(fixture.envelope.Environment(), fixtureOperationID)
	fixture.fake.seedBucket(fixture.identity, nil)
	fixture.fake.seedForeignObject(fixture.identity.Name, envelopeName.String(), envelopeJSON)
	ctx := context.Background()
	status, err := fixture.handoff.Bootstrap(ctx, fixture.envelope)
	if err != nil || status.Phase != PhaseHandoffVerified {
		t.Fatalf("Bootstrap() = %#v, %v", status, err)
	}
	if fixture.fake.count("create-bucket") != 0 || fixture.fake.count("upload:"+envelopeName.String()) != 0 {
		t.Fatalf("adoption re-created or re-uploaded: %v", fixture.fake.calls)
	}
	if _, err := fixture.handoff.LockRetention(ctx, fixture.envelope); err != nil {
		t.Fatalf("LockRetention() error: %v", err)
	}
}

func TestAuditHandoffLockRequiresVerifiedHandoffAndLocalClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	early := newHandoffFixture(t)
	if _, err := early.handoff.LockRetention(ctx, early.envelope); !errors.Is(err, ErrHandoffOutOfOrder) {
		t.Fatalf("LockRetention() before Bootstrap error = %v", err)
	}
	if early.fake.count("lock") != 0 || early.fake.count("retention") != 0 {
		t.Fatalf("premature lock mutated: %v", early.fake.calls)
	}

	drifted := newHandoffFixture(t)
	if _, err := drifted.handoff.Bootstrap(ctx, drifted.envelope); err != nil {
		t.Fatal(err)
	}
	// Someone else locked retention out of band: no local claim exists.
	drifted.fake.buckets[drifted.identity.Name].RetentionSeconds = AuditRetentionSeconds
	drifted.fake.buckets[drifted.identity.Name].RetentionLocked = true
	if _, err := drifted.handoff.LockRetention(ctx, drifted.envelope); !errors.Is(err, ErrPartialBootstrapBlocked) {
		t.Fatalf("unclaimed observed lock error = %v", err)
	}

	tampered := newHandoffFixture(t)
	if _, err := tampered.handoff.Bootstrap(ctx, tampered.envelope); err != nil {
		t.Fatal(err)
	}
	envelopeName, _ := BootstrapEnvelopeObjectName(tampered.envelope.Environment(), fixtureOperationID)
	stored := tampered.fake.objects[tampered.identity.Name][envelopeName.String()]
	stored.descriptor.Generation++
	tampered.fake.objects[tampered.identity.Name][envelopeName.String()] = stored
	if _, err := tampered.handoff.LockRetention(ctx, tampered.envelope); !errors.Is(err, ErrPartialBootstrapBlocked) {
		t.Fatalf("generation drift before lock error = %v", err)
	}
	if tampered.fake.count("lock") != 0 {
		t.Fatal("lock proceeded despite generation drift")
	}
}

func TestAuditHandoffRejectsTamperedLocalRecords(t *testing.T) {
	t.Parallel()
	fixture := newHandoffFixture(t)
	ctx := context.Background()
	if _, err := fixture.handoff.Bootstrap(ctx, fixture.envelope); err != nil {
		t.Fatal(err)
	}
	directory, _ := fixture.directory.handoffPath(fixtureOperationID)
	names, _ := listStateFiles(directory)
	if len(names) == 0 {
		t.Fatal("no records")
	}
	target := filepath.Join(directory, names[len(names)-1])
	content, _ := os.ReadFile(target)
	content[len(content)/2] ^= 0x04
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handoff.Status(fixture.envelope); !errors.Is(err, ErrInvalidHandoffRecord) {
		t.Fatalf("Status() with a tampered record error = %v", err)
	}
	if _, err := fixture.handoff.LockRetention(ctx, fixture.envelope); !errors.Is(err, ErrInvalidHandoffRecord) {
		t.Fatalf("LockRetention() with a tampered record error = %v", err)
	}
	if fixture.fake.count("lock") != 0 {
		t.Fatal("lock proceeded on a tampered chain")
	}
}

func TestAuditHandoffBlocksForeignRetentionOnLockedBucketAfterCrash(t *testing.T) {
	t.Parallel()
	fixture := newHandoffFixture(t)
	ctx := context.Background()
	fixture.fake.crashAfter["lock"] = true
	if _, err := fixture.handoff.Bootstrap(ctx, fixture.envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handoff.LockRetention(ctx, fixture.envelope); !errors.Is(err, errSimulatedCrash) {
		t.Fatalf("LockRetention() error = %v", err)
	}
	// A foreign actor changed the period on the locked bucket before the retry.
	fixture.fake.buckets[fixture.identity.Name].RetentionSeconds = AuditRetentionSeconds + 86400
	status, err := fixture.handoff.LockRetention(ctx, fixture.envelope)
	if !errors.Is(err, ErrPartialBootstrapBlocked) || status.RetentionLocked {
		t.Fatalf("retry over a foreign period = %#v, %v; want ErrPartialBootstrapBlocked", status, err)
	}
	if fixture.phases(t)[len(fixture.phases(t))-1] == PhaseRetentionLocked {
		t.Fatal("retention-locked was recorded over contradictory state")
	}
}

func TestAuditHandoffLockRefusesWhenMetagenerationMoves(t *testing.T) {
	t.Parallel()
	fixture := newHandoffFixture(t)
	ctx := context.Background()
	if _, err := fixture.handoff.Bootstrap(ctx, fixture.envelope); err != nil {
		t.Fatal(err)
	}
	// The retention period is configured, then the bucket changes underneath
	// the lock call: the port must refuse instead of locking unapproved state.
	fixture.fake.buckets[fixture.identity.Name].RetentionSeconds = AuditRetentionSeconds
	fixture.fake.crashAfter["retention"] = false
	original := fixture.fake.buckets[fixture.identity.Name].Metageneration
	fixture.fake.calls["describe-bucket"] = 0
	racing := &racingPort{fakeAuditBucket: fixture.fake, bump: func() {
		fixture.fake.buckets[fixture.identity.Name].Metageneration = original + 100
	}}
	handoff, err := NewAuditHandoff(fixture.directory, racing, fixture.handoff.clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handoff.LockRetention(ctx, fixture.envelope); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("LockRetention() error = %v, want ErrPreconditionFailed", err)
	}
	if fixture.fake.buckets[fixture.identity.Name].RetentionLocked || fixture.fake.count("lock") != 0 {
		t.Fatal("lock was applied despite a moved metageneration")
	}
}

// racingPort mutates the bucket between the handoff's last observation and the
// lock call.
type racingPort struct {
	*fakeAuditBucket
	bump func()
}

func (port *racingPort) LockRetention(ctx context.Context, identity BucketIdentity, expected int64) error {
	port.bump()
	return port.fakeAuditBucket.LockRetention(ctx, identity, expected)
}

func TestAuditHandoffRefusesExpiredAuthorization(t *testing.T) {
	t.Parallel()
	fixture := newHandoffFixture(t)
	late := fixture.envelope.Approval().ValidUntil
	expired, err := NewAuditHandoff(fixture.directory, fixture.fake, func() time.Time { return late })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := expired.Bootstrap(ctx, fixture.envelope); !errors.Is(err, ErrEnvelopeExpired) {
		t.Fatalf("Bootstrap() after approval expiry error = %v", err)
	}
	if _, err := expired.LockRetention(ctx, fixture.envelope); !errors.Is(err, ErrEnvelopeExpired) {
		t.Fatalf("LockRetention() after approval expiry error = %v", err)
	}
	early, _ := NewAuditHandoff(fixture.directory, fixture.fake, func() time.Time { return fixtureNow })
	if _, err := early.Bootstrap(ctx, fixture.envelope); !errors.Is(err, ErrEnvelopeExpired) {
		t.Fatalf("Bootstrap() before approval error = %v", err)
	}
	if fixture.fake.count("create-bucket") != 0 || fixture.fake.count("describe-bucket") != 0 {
		t.Fatalf("expired authorization reached the provider: %v", fixture.fake.calls)
	}
}

func TestAuditHandoffRefusesBackwardClockBeforePersisting(t *testing.T) {
	t.Parallel()
	envelope := fixtureEnvelope(t)
	directory := fixtureStateDirectory(t)
	// The first record is stamped at T+4m; every later reading regresses to
	// T+3m, so the create claim must be refused before the provider is called.
	index := 0
	clock := func() time.Time {
		index++
		if index <= 2 {
			return fixtureNow.Add(4 * time.Minute)
		}
		return fixtureNow.Add(3 * time.Minute)
	}
	fake := newFakeAuditBucket(clock)
	handoff, err := NewAuditHandoff(directory, fake, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handoff.Bootstrap(context.Background(), envelope); !errors.Is(err, ErrInvalidHandoffRecord) {
		t.Fatalf("Bootstrap() with a regressing clock error = %v", err)
	}
	if fake.count("create-bucket") != 0 {
		t.Fatal("a regressing clock still reached the provider")
	}
}

func TestAuditHandoffReverifiesCompletedBootstrapAndRejectsByteDrift(t *testing.T) {
	t.Parallel()
	fixture := newHandoffFixture(t)
	ctx := context.Background()
	if _, err := fixture.handoff.Bootstrap(ctx, fixture.envelope); err != nil {
		t.Fatal(err)
	}
	envelopeName, _ := BootstrapEnvelopeObjectName(fixture.envelope.Environment(), fixtureOperationID)
	stored := fixture.fake.objects[fixture.identity.Name][envelopeName.String()]
	// Same size and CRC32C descriptor, different bytes: a checksum collision
	// must not pass as the exact envelope.
	stored.content = append([]byte(nil), stored.content...)
	stored.content[10] ^= 0x01
	fixture.fake.objects[fixture.identity.Name][envelopeName.String()] = stored
	if _, err := fixture.handoff.Bootstrap(ctx, fixture.envelope); !errors.Is(err, ErrPartialBootstrapBlocked) {
		t.Fatalf("completed Bootstrap() over drifted bytes error = %v", err)
	}
	if _, err := fixture.handoff.LockRetention(ctx, fixture.envelope); !errors.Is(err, ErrPartialBootstrapBlocked) {
		t.Fatalf("LockRetention() over drifted bytes error = %v", err)
	}
	vanished := newHandoffFixture(t)
	if _, err := vanished.handoff.Bootstrap(ctx, vanished.envelope); err != nil {
		t.Fatal(err)
	}
	delete(vanished.fake.buckets, vanished.identity.Name)
	if _, err := vanished.handoff.Bootstrap(ctx, vanished.envelope); !errors.Is(err, ErrPartialBootstrapBlocked) {
		t.Fatalf("completed Bootstrap() over a vanished bucket error = %v", err)
	}
}
