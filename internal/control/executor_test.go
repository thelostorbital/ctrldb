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
	bindings    map[string][]BucketBinding
	binding     string
	operationID string
	stepID      string
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
		StorageClass: AuditStorageClass, Versioning: false, SoftDeleteSeconds: ControlSoftDeleteSeconds, Metageneration: 1, TimeCreated: fake.clock().UTC()}
	fake.objects[identity.Name] = map[string]fakeObject{}
	return fake.after("create-control-bucket")
}

func (fake *fakeStoragePort) AuthorizedStep() (string, string, string) {
	return fake.binding, fake.operationID, fake.stepID
}

func (fake *fakeStoragePort) EnableVersioning(_ context.Context, identity BucketIdentity) error {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	bucket := fake.buckets[identity.Name]
	if bucket == nil {
		return errors.New("fake: absent bucket")
	}
	bucket.Versioning = true
	bucket.Metageneration++
	return fake.after("enable-versioning")
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
	port.binding, port.operationID = envelope.EnvelopeBindingSHA256(), envelope.OperationID()
	var outcomes []StepOutcome
	var completed []string
	// A step whose dependency is not durably complete is refused.
	port.stepID = intents[1].StepID
	if _, err := executor.Execute(ctx, envelope, intents[1], port, StepContext{}); !errors.Is(err, ErrStepNotAdmitted) {
		t.Fatalf("K1b without K1a error = %v", err)
	}
	for _, intent := range intents[:6] {
		port.stepID = intent.StepID
		outcome, err := executor.Execute(ctx, envelope, intent, port, StepContext{CompletedSteps: completed, Lock: lock})
		if err != nil || !outcome.Verified {
			t.Fatalf("Execute(%s) = %#v, %v", intent.StepID, outcome, err)
		}
		outcomes = append(outcomes, outcome)
		completed = append(completed, intent.StepID)
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
		port.stepID = intent.StepID
		outcome, err := executor.Execute(ctx, envelope, intent, port, StepContext{CompletedSteps: completed, Lock: lock})
		if err != nil || !outcome.Verified {
			t.Fatalf("second Execute(%s) = %#v, %v", intent.StepID, outcome, err)
		}
		if intent.Kind == bootstrap.IntentBucketIAM && (len(outcome.AddedBindings) != 0 || outcome.MutationOccurred) {
			t.Fatalf("K3 re-added bindings: %#v", outcome)
		}
		if intent.Kind == bootstrap.IntentSeedControl {
			if outcome.MutationOccurred {
				t.Fatal("K4 reported a mutation for preexisting seeds")
			}
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
	// T-intents, tampered intents, and a port bound elsewhere are refused
	// before any provider call.
	before := len(port.calls)
	port.stepID = intents[6].StepID
	if _, err := executor.Execute(ctx, envelope, intents[6], port, StepContext{CompletedSteps: completed}); !errors.Is(err, ErrStepNotAdmitted) {
		t.Fatalf("T1 error = %v", err)
	}
	port.stepID = intents[2].StepID
	tampered := intents[2]
	tampered.ResourceIDs = []string{"audit-bucket"}
	if _, err := executor.Execute(ctx, envelope, tampered, port, StepContext{CompletedSteps: completed}); !errors.Is(err, ErrStepNotAdmitted) {
		t.Fatalf("tampered intent error = %v", err)
	}
	foreign := intents[2]
	foreign.EnvelopeBindingSHA256 = repeatHex("9")
	if _, err := executor.Execute(ctx, envelope, foreign, port, StepContext{CompletedSteps: completed}); !errors.Is(err, ErrStepNotAdmitted) {
		t.Fatalf("foreign binding error = %v", err)
	}
	port.stepID = intents[3].StepID
	if _, err := executor.Execute(ctx, envelope, intents[2], port, StepContext{CompletedSteps: completed}); !errors.Is(err, ErrStepNotAdmitted) {
		t.Fatalf("port bound to another step error = %v", err)
	}
	port.stepID, port.operationID = intents[2].StepID, "op-fedcba9876543210"
	if _, err := executor.Execute(ctx, envelope, intents[2], port, StepContext{CompletedSteps: completed}); !errors.Is(err, ErrStepNotAdmitted) {
		t.Fatalf("port bound to another operation error = %v", err)
	}
	port.operationID = envelope.OperationID()
	if len(port.calls) != before {
		t.Fatal("a refused intent reached the provider")
	}
	port.stepID = intents[5].StepID
	if _, err := executor.Execute(ctx, envelope, intents[5], port, StepContext{CompletedSteps: completed, Lock: LockRoundTripInput{Holder: LockHolder{Account: "other@example.invalid", Hostname: "h", PID: 1}}}); !errors.Is(err, ErrInvalidStoreRequest) {
		t.Fatalf("foreign lock holder error = %v", err)
	}
}

func TestStorageExecutorK2RequiresOwnershipAndConvergesPartialCreate(t *testing.T) {
	t.Parallel()
	envelope := fixtureEnvelope(t)
	current := fixtureNow.Add(3 * time.Minute)
	clock := func() time.Time { current = current.Add(time.Second); return current }
	ctx := context.Background()
	intents := envelope.Plan().Intents()
	completed := []string{intents[0].StepID, intents[1].StepID}
	controlBucket := BucketIdentity{Name: envelope.ControlBucket(), Project: envelope.Project(), Location: envelope.AuditBucketLocation()}

	// An existing bucket without an operation-bound creation record blocks.
	foreign := newFakeStoragePort(clock)
	foreign.binding, foreign.operationID, foreign.stepID = envelope.EnvelopeBindingSHA256(), envelope.OperationID(), intents[2].StepID
	foreign.seedBucket(controlBucket, func(state *BucketState) { state.SoftDeleteSeconds = ControlSoftDeleteSeconds })
	executor, _ := NewStorageExecutor(fixtureStateDirectory(t), clock)
	if _, err := executor.Execute(ctx, envelope, intents[2], foreign, StepContext{CompletedSteps: completed}); !errors.Is(err, ErrPartialBootstrapBlocked) {
		t.Fatalf("existing unowned control bucket error = %v", err)
	}
	if foreign.count("create-control-bucket") != 0 || foreign.count("enable-versioning") != 0 {
		t.Fatalf("blocked K2 mutated: %v", foreign.calls)
	}

	// A crash between create and the local creation record blocks, exactly
	// like the K1 rule: a bare bucket carries no operation-bound marker.
	unrecorded := newFakeStoragePort(clock)
	unrecorded.binding, unrecorded.operationID, unrecorded.stepID = envelope.EnvelopeBindingSHA256(), envelope.OperationID(), intents[2].StepID
	unrecorded.crashAfter["create-control-bucket"] = true
	unrecordedDir := fixtureStateDirectory(t)
	executor, _ = NewStorageExecutor(unrecordedDir, clock)
	if _, err := executor.Execute(ctx, envelope, intents[2], unrecorded, StepContext{CompletedSteps: completed}); !errors.Is(err, errSimulatedCrash) {
		t.Fatalf("crash error = %v", err)
	}
	if _, err := executor.Execute(ctx, envelope, intents[2], unrecorded, StepContext{CompletedSteps: completed}); !errors.Is(err, ErrPartialBootstrapBlocked) {
		t.Fatalf("resume after unrecorded create error = %v", err)
	}

	// A crash after the creation record (versioning never applied) converges.
	partial := newFakeStoragePort(clock)
	partial.binding, partial.operationID, partial.stepID = envelope.EnvelopeBindingSHA256(), envelope.OperationID(), intents[2].StepID
	partial.crashAfter["enable-versioning"] = true
	directory := fixtureStateDirectory(t)
	executor, _ = NewStorageExecutor(directory, clock)
	if _, err := executor.Execute(ctx, envelope, intents[2], partial, StepContext{CompletedSteps: completed}); !errors.Is(err, errSimulatedCrash) {
		t.Fatalf("crash error = %v", err)
	}
	partial.buckets[controlBucket.Name].Versioning = false
	resumed, _ := NewStorageExecutor(directory, clock)
	outcome, err := resumed.Execute(ctx, envelope, intents[2], partial, StepContext{CompletedSteps: completed})
	if err != nil || !outcome.Verified || !outcome.MutationOccurred {
		t.Fatalf("resumed K2 = %#v, %v", outcome, err)
	}
	if partial.count("create-control-bucket") != 1 || partial.count("enable-versioning") != 2 || !partial.buckets[controlBucket.Name].Versioning {
		t.Fatalf("convergence calls = %v", partial.calls)
	}
	// A wrong soft-delete window fails verification.
	partial.buckets[controlBucket.Name].SoftDeleteSeconds = 86400
	if _, err := resumed.Execute(ctx, envelope, intents[2], partial, StepContext{CompletedSteps: completed}); !errors.Is(err, ErrStepVerificationFailed) {
		t.Fatalf("soft-delete drift error = %v", err)
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
	completed := []string{intents[0].StepID, intents[1].StepID, intents[2].StepID}
	port.binding, port.operationID, port.stepID = envelope.EnvelopeBindingSHA256(), envelope.OperationID(), intents[3].StepID
	outcome, err := executor.Execute(ctx, envelope, intents[3], port, StepContext{CompletedSteps: completed})
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
	// An extra foreign binding fails verification even when every rendered
	// binding is present; an ambiguous add is re-observed and recorded.
	extra := policy.Bindings[0]
	extra.Member = "serviceAccount:intruder@example-project.iam.gserviceaccount.com"
	port.bindings[audit.Name] = append(port.bindings[audit.Name], extra)
	if _, err := executor.Execute(ctx, envelope, intents[3], port, StepContext{CompletedSteps: completed}); !errors.Is(err, ErrStepVerificationFailed) {
		t.Fatalf("extra binding error = %v", err)
	}
	fresh := newFakeStoragePort(clock)
	fresh.binding, fresh.operationID, fresh.stepID = envelope.EnvelopeBindingSHA256(), envelope.OperationID(), intents[3].StepID
	fresh.seedBucket(audit, nil)
	fresh.seedBucket(controlBucket, nil)
	fresh.crashAfter["add-binding"] = true
	ambiguous, err := executor.Execute(ctx, envelope, intents[3], fresh, StepContext{CompletedSteps: completed})
	if !errors.Is(err, errSimulatedCrash) || len(ambiguous.AddedBindings) != 1 {
		t.Fatalf("ambiguous add = %#v, %v", ambiguous, err)
	}
	store := NewPortControlStore(port, controlBucket)
	if _, err := store.CompareAndSwap(ctx, HarnessStateObjectName(), 0, []byte("x")); !errors.Is(err, ErrInvalidStoreRequest) {
		t.Fatalf("CAS with zero generation error = %v", err)
	}
	if _, err := store.Read(ctx, HarnessStateObjectName()); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("absent read error = %v", err)
	}
}
