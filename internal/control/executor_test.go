// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

// fakeStoragePort extends the audit fake with the control-bucket operations.
type fakeStoragePort struct {
	*fakeAuditBucket
	bindings map[string][]BucketBinding
}

func newFakeStoragePort(clock func() time.Time) *fakeStoragePort {
	return &fakeStoragePort{fakeAuditBucket: newFakeAuditBucket(clock), bindings: map[string][]BucketBinding{}}
}

func (fake *fakeStoragePort) CreateControlBucket(_ context.Context, identity BucketIdentity) error {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	if fake.globalTaken[identity.Name] || fake.buckets[identity.Name] != nil {
		fake.calls["create-conflict"]++
		return ErrBucketNameConflict
	}
	fake.buckets[identity.Name] = &BucketState{Identity: identity, UniformBucketLevelAccess: true, PublicAccessPrevention: PublicAccessPreventionEnforced,
		StorageClass: AuditStorageClass, Versioning: true, Metageneration: 1, TimeCreated: fake.clock().UTC()}
	fake.objects[identity.Name] = map[string]fakeObject{}
	return fake.after("create-control-bucket")
}

func (fake *fakeStoragePort) GetBindings(_ context.Context, identity BucketIdentity) ([]BucketBinding, error) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	if fake.buckets[identity.Name] == nil {
		return nil, errors.New("fake: absent bucket")
	}
	return append([]BucketBinding(nil), fake.bindings[identity.Name]...), nil
}

func (fake *fakeStoragePort) AddBinding(_ context.Context, identity BucketIdentity, binding BucketBinding) error {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.bindings[identity.Name] = append(fake.bindings[identity.Name], binding)
	return fake.after("add-binding")
}

func (fake *fakeStoragePort) RemoveBinding(_ context.Context, identity BucketIdentity, binding BucketBinding) error {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	kept := fake.bindings[identity.Name][:0]
	for _, item := range fake.bindings[identity.Name] {
		if item != binding {
			kept = append(kept, item)
		}
	}
	fake.bindings[identity.Name] = kept
	return fake.after("remove-binding")
}

func (fake *fakeStoragePort) UploadControlCreateOnly(ctx context.Context, identity BucketIdentity, object ControlObjectName, content []byte) (ObjectDescriptor, error) {
	return fake.UploadCreateOnly(ctx, identity, AuditObjectName(object), content)
}

func (fake *fakeStoragePort) UploadIfGenerationMatch(_ context.Context, identity BucketIdentity, object ControlObjectName, expected Generation, content []byte) (ObjectDescriptor, error) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	objects := fake.objects[identity.Name]
	stored, exists := objects[object.value]
	if !exists || stored.descriptor.Generation != expected {
		return ObjectDescriptor{}, fmt.Errorf("%w: %s", ErrPreconditionFailed, object.value)
	}
	fake.generation++
	descriptor := DescribeContent(content)
	descriptor.Generation = fake.generation
	objects[object.value] = fakeObject{descriptor: descriptor, content: append([]byte(nil), content...)}
	fake.calls["cas"]++
	return descriptor, nil
}

func (fake *fakeStoragePort) DescribeControlObject(ctx context.Context, identity BucketIdentity, object ControlObjectName) (ObjectDescriptor, bool, error) {
	return fake.DescribeObject(ctx, identity, AuditObjectName(object))
}

func (fake *fakeStoragePort) ReadControlObject(ctx context.Context, identity BucketIdentity, object ControlObjectName) ([]byte, ObjectDescriptor, bool, error) {
	return fake.ReadObject(ctx, identity, AuditObjectName(object))
}

func TestStorageExecutorRunsK1ToK5FromTheSealedEnvelope(t *testing.T) {
	t.Parallel()
	envelope := fixtureEnvelope(t)
	directory := fixtureStateDirectory(t)
	current := fixtureNow.Add(3 * time.Minute)
	clock := func() time.Time { current = current.Add(time.Second); return current }
	port := newFakeStoragePort(clock)
	executor, err := NewStorageExecutor(directory, clock)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	lock := LockRoundTripInput{Holder: LockHolder{Account: fixtureAccount, Hostname: "workstation.example.invalid", PID: 4242}, CLIVersion: "0.0.0-test"}
	intents := envelope.Plan().Intents()
	var outcomes []StepOutcome
	for _, intent := range intents[:6] {
		outcome, err := executor.Execute(ctx, envelope, intent, port, lock)
		if err != nil || !outcome.Verified {
			t.Fatalf("Execute(%s) = %#v, %v", intent.StepID, outcome, err)
		}
		outcomes = append(outcomes, outcome)
	}
	if !outcomes[1].MutationOccurred || !port.buckets[envelope.AuditBucket()].RetentionLocked {
		t.Fatalf("K1b did not lock: %#v", outcomes[1])
	}
	if port.buckets[envelope.ControlBucket()] == nil || port.buckets[envelope.ControlBucket()].RetentionLocked {
		t.Fatal("K2 control bucket state is wrong")
	}
	if len(outcomes[3].AddedBindings) != 8 || len(outcomes[4].SeedOutcomes) != 4 || outcomes[5].LockGenerations[1] <= outcomes[5].LockGenerations[0] {
		t.Fatalf("outcomes = %#v", outcomes[3:])
	}
	// Re-running K2-K5 converges without repeating mutations.
	for _, intent := range intents[2:6] {
		outcome, err := executor.Execute(ctx, envelope, intent, port, lock)
		if err != nil || !outcome.Verified {
			t.Fatalf("second Execute(%s) = %#v, %v", intent.StepID, outcome, err)
		}
		if intent.Kind == bootstrap.IntentBucketIAM && len(outcome.AddedBindings) != 0 {
			t.Fatalf("K3 re-added bindings: %v", outcome.AddedBindings)
		}
		if intent.Kind == bootstrap.IntentSeedControl {
			for _, seed := range outcome.SeedOutcomes {
				if !seed.Preexisting {
					t.Fatalf("K4 reseeded %s", seed.Name)
				}
			}
		}
	}
	if port.count("create-control-bucket") != 1 || port.count("add-binding") != 8 || port.count("create-bucket") != 1 || port.count("lock") != 1 {
		t.Fatalf("mutation counts = %v", port.calls)
	}
	// T-intents and tampered intents are refused before any provider call.
	before := len(port.calls)
	if _, err := executor.Execute(ctx, envelope, intents[6], port, lock); !errors.Is(err, ErrStepNotAdmitted) {
		t.Fatalf("T1 error = %v", err)
	}
	tampered := intents[2]
	tampered.ResourceIDs = []string{"audit-bucket"}
	if _, err := executor.Execute(ctx, envelope, tampered, port, lock); !errors.Is(err, ErrStepNotAdmitted) {
		t.Fatalf("tampered intent error = %v", err)
	}
	foreign := intents[2]
	foreign.EnvelopeBindingSHA256 = repeatHex("9")
	if _, err := executor.Execute(ctx, envelope, foreign, port, lock); !errors.Is(err, ErrStepNotAdmitted) {
		t.Fatalf("foreign binding error = %v", err)
	}
	if len(port.calls) != before {
		t.Fatal("a refused intent reached the provider")
	}
	if _, err := executor.Execute(ctx, envelope, intents[5], port, LockRoundTripInput{Holder: LockHolder{Account: "other@example.invalid", Hostname: "h", PID: 1}}); !errors.Is(err, ErrInvalidStoreRequest) {
		t.Fatalf("foreign lock holder error = %v", err)
	}
}

func TestStorageExecutorK3RemovesNothingAndK5ProvesGenerationSemantics(t *testing.T) {
	t.Parallel()
	envelope := fixtureEnvelope(t)
	current := fixtureNow.Add(3 * time.Minute)
	clock := func() time.Time { current = current.Add(time.Second); return current }
	port := newFakeStoragePort(clock)
	executor, _ := NewStorageExecutor(fixtureStateDirectory(t), clock)
	ctx := context.Background()
	audit := BucketIdentity{Name: envelope.AuditBucket(), Project: envelope.Project(), Location: envelope.AuditBucketLocation()}
	controlBucket := BucketIdentity{Name: envelope.ControlBucket(), Project: envelope.Project(), Location: envelope.AuditBucketLocation()}
	port.seedBucket(audit, nil)
	port.seedBucket(controlBucket, nil)
	policy, _ := RenderBucketPolicy("k3-bucket-iam", envelope.Plan().DesiredState())
	port.bindings[audit.Name] = []BucketBinding{policy.Bindings[0]}
	intents := envelope.Plan().Intents()
	outcome, err := executor.Execute(ctx, envelope, intents[3], port, LockRoundTripInput{})
	if err != nil || len(outcome.AddedBindings) != 7 {
		t.Fatalf("K3 = %#v, %v", outcome, err)
	}
	for _, added := range outcome.AddedBindings {
		if added == policy.Bindings[0] {
			t.Fatal("preexisting binding recorded as added")
		}
	}
	if port.count("remove-binding") != 0 {
		t.Fatal("K3 removed a binding")
	}
	store := NewPortControlStore(port, controlBucket)
	if _, err := store.CompareAndSwap(ctx, HarnessStateObjectName(), 0, []byte("x")); !errors.Is(err, ErrInvalidStoreRequest) {
		t.Fatalf("CAS with zero generation error = %v", err)
	}
	if _, err := store.Read(ctx, HarnessStateObjectName()); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("absent read error = %v", err)
	}
}
