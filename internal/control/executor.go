// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

var (
	// ErrStepNotAdmitted is returned when an intent is not a K1-K5 storage
	// step or its resources do not match the envelope.
	ErrStepNotAdmitted = errors.New("storage step not admitted")
	// ErrStepVerificationFailed is returned when post-mutation observation
	// does not equal the desired state.
	ErrStepVerificationFailed = errors.New("storage step verification failed")
)

// StorageStepPort is the complete typed surface the K1-K5 executor needs. The
// gcp StorageSession satisfies it structurally; the executor never sees a
// process, an argv, or a bare resource name. There is no delete method.
type StorageStepPort interface {
	AuditBucketPort
	CreateControlBucket(ctx context.Context, identity BucketIdentity) error
	GetBindings(ctx context.Context, identity BucketIdentity) ([]BucketBinding, error)
	AddBinding(ctx context.Context, identity BucketIdentity, binding BucketBinding) error
	RemoveBinding(ctx context.Context, identity BucketIdentity, binding BucketBinding) error
	UploadControlCreateOnly(ctx context.Context, identity BucketIdentity, object ControlObjectName, content []byte) (ObjectDescriptor, error)
	UploadIfGenerationMatch(ctx context.Context, identity BucketIdentity, object ControlObjectName, expected Generation, content []byte) (ObjectDescriptor, error)
	DescribeControlObject(ctx context.Context, identity BucketIdentity, object ControlObjectName) (ObjectDescriptor, bool, error)
	ReadControlObject(ctx context.Context, identity BucketIdentity, object ControlObjectName) ([]byte, ObjectDescriptor, bool, error)
}

// StepOutcome is the executor's durable-record input for one attempt.
type StepOutcome struct {
	StepID           string
	Kind             bootstrap.IntentKind
	MutationOccurred bool
	Verified         bool
	// AddedBindings lists exactly the K3 bindings created by this attempt;
	// compensation may remove only these.
	AddedBindings []BucketBinding
	// SeedOutcomes lists K4 create/preserve results.
	SeedOutcomes []SeedOutcome
	// LockGenerations records the K5 acquire and release generations.
	LockGenerations [2]Generation
}

// StorageExecutor drives the six K-intents from the sealed envelope.
type StorageExecutor struct {
	directory StateDirectory
	clock     func() time.Time
}

// NewStorageExecutor binds the state directory used by the K1 handoff.
func NewStorageExecutor(directory StateDirectory, clock func() time.Time) (*StorageExecutor, error) {
	if directory.path == "" || clock == nil {
		return nil, fmt.Errorf("%w: executor construction", ErrInvalidStoreRequest)
	}
	return &StorageExecutor{directory: directory, clock: clock}, nil
}

// LockHolder for K5 is the operator's explicit identity; hostname and pid are
// caller-supplied observations, never inferred here.
type LockRoundTripInput struct {
	Holder     LockHolder
	CLIVersion string
}

// Execute runs one admitted K-step through port. It re-derives every target
// from the envelope, never from the intent's free fields.
func (executor *StorageExecutor) Execute(ctx context.Context, envelope BootstrapEnvelopeV1, intent bootstrap.StepIntent, port StorageStepPort, lock LockRoundTripInput) (StepOutcome, error) {
	if executor == nil || port == nil {
		return StepOutcome{}, fmt.Errorf("%w: executor or port", ErrInvalidStoreRequest)
	}
	if err := storeContext(ctx); err != nil {
		return StepOutcome{}, err
	}
	if err := admitStep(envelope, intent); err != nil {
		return StepOutcome{}, err
	}
	if err := envelope.validAt(executor.clock().UTC()); err != nil {
		return StepOutcome{}, err
	}
	outcome := StepOutcome{StepID: intent.StepID, Kind: intent.Kind}
	audit := BucketIdentity{Name: envelope.AuditBucket(), Project: envelope.Project(), Location: envelope.AuditBucketLocation()}
	controlBucket := BucketIdentity{Name: envelope.ControlBucket(), Project: envelope.Project(), Location: envelope.AuditBucketLocation()}
	switch intent.Kind {
	case bootstrap.IntentAuditBootstrap:
		handoff, err := NewAuditHandoff(executor.directory, port, executor.clock)
		if err != nil {
			return StepOutcome{}, err
		}
		status, err := handoff.Bootstrap(ctx, envelope)
		outcome.MutationOccurred = true
		if err != nil {
			return outcome, err
		}
		outcome.Verified = status.Phase.order() >= PhaseHandoffVerified.order()
	case bootstrap.IntentAuditRetention:
		handoff, err := NewAuditHandoff(executor.directory, port, executor.clock)
		if err != nil {
			return StepOutcome{}, err
		}
		status, err := handoff.LockRetention(ctx, envelope)
		if err != nil {
			// The irreversible boundary is crossed only when the lock was
			// observed; the handoff records that before returning success.
			locked, statusErr := handoff.Status(envelope)
			outcome.MutationOccurred = statusErr == nil && locked.RetentionLocked
			return outcome, err
		}
		outcome.MutationOccurred, outcome.Verified = status.RetentionLocked, status.RetentionLocked
	case bootstrap.IntentControlBucket:
		return executor.controlBucket(ctx, port, controlBucket, outcome)
	case bootstrap.IntentBucketIAM:
		return executor.bucketIAM(ctx, envelope, port, audit, controlBucket, outcome)
	case bootstrap.IntentSeedControl:
		store := NewPortControlStore(port, controlBucket)
		seeds, err := SeedControlStore(ctx, store, envelope)
		outcome.MutationOccurred = true
		if err != nil {
			return outcome, err
		}
		outcome.SeedOutcomes, outcome.Verified = seeds, true
	case bootstrap.IntentLockRoundTrip:
		return executor.lockRoundTrip(ctx, envelope, port, controlBucket, lock, outcome)
	default:
		return StepOutcome{}, fmt.Errorf("%w: kind %s", ErrStepNotAdmitted, intent.Kind)
	}
	return outcome, nil
}

func admitStep(envelope BootstrapEnvelopeV1, intent bootstrap.StepIntent) error {
	if envelope.hash == "" || intent.EnvelopeBindingSHA256 != envelope.EnvelopeBindingSHA256() ||
		intent.ExecutingIdentity != envelope.Plan().Intents()[0].ExecutingIdentity {
		return fmt.Errorf("%w: intent is not bound to this envelope", ErrStepNotAdmitted)
	}
	var registered *bootstrap.StepIntent
	for _, candidate := range envelope.Plan().Intents() {
		if candidate.StepID == intent.StepID {
			copy := candidate
			registered = &copy
		}
	}
	if registered == nil || !equalCanonicalValue(*registered, intent) {
		return fmt.Errorf("%w: intent differs from the sealed plan", ErrStepNotAdmitted)
	}
	switch intent.Kind {
	case bootstrap.IntentAuditBootstrap, bootstrap.IntentAuditRetention, bootstrap.IntentControlBucket,
		bootstrap.IntentBucketIAM, bootstrap.IntentSeedControl, bootstrap.IntentLockRoundTrip:
		return nil
	}
	return fmt.Errorf("%w: kind %s", ErrStepNotAdmitted, intent.Kind)
}

func (executor *StorageExecutor) controlBucket(ctx context.Context, port StorageStepPort, identity BucketIdentity, outcome StepOutcome) (StepOutcome, error) {
	state, exists, err := port.DescribeBucket(ctx, identity.Name)
	if err != nil {
		return outcome, err
	}
	if !exists {
		outcome.MutationOccurred = true
		if err := port.CreateControlBucket(ctx, identity); err != nil {
			return outcome, err
		}
		state, exists, err = port.DescribeBucket(ctx, identity.Name)
		if err != nil {
			return outcome, err
		}
		if !exists {
			return outcome, fmt.Errorf("%w: created control bucket is not observable", ErrInvalidHandoffPort)
		}
	}
	if err := checkControlBucketState(state, identity); err != nil {
		return outcome, err
	}
	outcome.Verified = true
	return outcome, nil
}

func checkControlBucketState(state BucketState, identity BucketIdentity) error {
	if state.Identity != identity || !state.UniformBucketLevelAccess || state.PublicAccessPrevention != PublicAccessPreventionEnforced ||
		state.StorageClass != AuditStorageClass || !state.Versioning || state.LifecycleDeleteRule || state.RetentionLocked || state.RetentionSeconds != 0 {
		return fmt.Errorf("%w: control bucket state is not the exact desired configuration", ErrStepVerificationFailed)
	}
	return nil
}

func (executor *StorageExecutor) bucketIAM(ctx context.Context, envelope BootstrapEnvelopeV1, port StorageStepPort, audit, controlBucket BucketIdentity, outcome StepOutcome) (StepOutcome, error) {
	policy, err := RenderBucketPolicy("k3-bucket-iam", envelope.Plan().DesiredState())
	if err != nil {
		return outcome, err
	}
	identities := map[string]BucketIdentity{audit.Name: audit, controlBucket.Name: controlBucket}
	observed := make(map[string][]BucketBinding)
	for name, identity := range identities {
		bindings, err := port.GetBindings(ctx, identity)
		if err != nil {
			return outcome, err
		}
		observed[name] = bindings
	}
	preexisting := append(observed[audit.Name], observed[controlBucket.Name]...)
	missing := CompensationBindings(policy.Bindings, preexisting)
	for _, binding := range missing {
		outcome.MutationOccurred = true
		if err := port.AddBinding(ctx, identities[binding.Bucket], binding); err != nil {
			return outcome, err
		}
		outcome.AddedBindings = append(outcome.AddedBindings, binding)
	}
	for name, identity := range identities {
		after, err := port.GetBindings(ctx, identity)
		if err != nil {
			return outcome, err
		}
		if !bindingsCoverPolicy(after, policy.Bindings, name) {
			return outcome, fmt.Errorf("%w: bucket IAM does not equal the rendered policy", ErrStepVerificationFailed)
		}
	}
	outcome.Verified = true
	return outcome, nil
}

func bindingsCoverPolicy(observed, rendered []BucketBinding, bucket string) bool {
	present := make(map[BucketBinding]struct{}, len(observed))
	for _, item := range observed {
		present[item] = struct{}{}
	}
	for _, item := range rendered {
		if item.Bucket != bucket {
			continue
		}
		if _, ok := present[item]; !ok {
			return false
		}
	}
	return true
}

func (executor *StorageExecutor) lockRoundTrip(ctx context.Context, envelope BootstrapEnvelopeV1, port StorageStepPort, controlBucket BucketIdentity, input LockRoundTripInput, outcome StepOutcome) (StepOutcome, error) {
	store := NewPortControlStore(port, controlBucket)
	name, err := LockObjectName(envelope.Environment())
	if err != nil {
		return outcome, err
	}
	current, err := store.Read(ctx, name)
	if err != nil {
		return outcome, err
	}
	var record LockRecordV1
	if err := decodeStrictSeed(current.Content, &record); err != nil || record.Schema != LockRecordSchemaV1 ||
		record.Environment != envelope.Environment() || record.State != LockStateReleased {
		return outcome, fmt.Errorf("%w: lock is not a released record", ErrStepVerificationFailed)
	}
	if input.Holder.Account != envelope.Account() || input.Holder.Hostname == "" || input.Holder.PID <= 0 {
		return outcome, fmt.Errorf("%w: lock holder", ErrInvalidStoreRequest)
	}
	now := executor.clock().UTC()
	held := record
	held.WorkflowID, held.OperationID, held.PlanID = bootstrap.WorkflowID, envelope.OperationID(), envelope.PlanID()
	holder := input.Holder
	held.Holder = &holder
	held.AcquiredAt, held.HeartbeatAt = timePointer(now), timePointer(now)
	lease := now.Add(LockLeaseSeconds * time.Second)
	held.LeaseUntil = timePointer(lease)
	held.State, held.CLIVersion, held.Readers = LockStateHeld, input.CLIVersion, []string{}
	heldJSON, err := json.Marshal(held)
	if err != nil {
		return outcome, fmt.Errorf("%w: lock encoding", ErrInvalidStoreRequest)
	}
	outcome.MutationOccurred = true
	acquired, err := store.CompareAndSwap(ctx, name, current.Descriptor.Generation, heldJSON)
	if err != nil {
		return outcome, err
	}
	// The stale generation must now be refused: this proves ifGenerationMatch.
	if _, err := store.CompareAndSwap(ctx, name, current.Descriptor.Generation, heldJSON); !errors.Is(err, ErrPreconditionFailed) {
		return outcome, fmt.Errorf("%w: stale generation was accepted", ErrStepVerificationFailed)
	}
	released, err := store.CompareAndSwap(ctx, name, acquired.Generation, current.Content)
	if err != nil {
		return outcome, err
	}
	final, err := store.Read(ctx, name)
	if err != nil || final.Descriptor != released || !bytes.Equal(final.Content, current.Content) {
		return outcome, fmt.Errorf("%w: lock was not released to its exact prior content", ErrStepVerificationFailed)
	}
	outcome.LockGenerations = [2]Generation{acquired.Generation, released.Generation}
	outcome.Verified = true
	return outcome, nil
}

// LockLeaseSeconds is ARCHITECTURE `control.lockLeaseSeconds`.
const LockLeaseSeconds = 300

// PortControlStore adapts a StorageStepPort bound to the control bucket into
// the ControlStore interface. Create is create-only, CompareAndSwap needs a
// positive generation, and there is no delete.
type PortControlStore struct {
	port     StorageStepPort
	identity BucketIdentity
}

// NewPortControlStore binds port to the control bucket identity.
func NewPortControlStore(port StorageStepPort, identity BucketIdentity) *PortControlStore {
	return &PortControlStore{port: port, identity: identity}
}

func (store *PortControlStore) Create(ctx context.Context, name ControlObjectName, content []byte) (ObjectDescriptor, error) {
	if store == nil || store.port == nil || name.value == "" {
		return ObjectDescriptor{}, ErrInvalidStoreRequest
	}
	return store.port.UploadControlCreateOnly(ctx, store.identity, name, content)
}

func (store *PortControlStore) Read(ctx context.Context, name ControlObjectName) (StoredObject, error) {
	if store == nil || store.port == nil || name.value == "" {
		return StoredObject{}, ErrInvalidStoreRequest
	}
	content, descriptor, exists, err := store.port.ReadControlObject(ctx, store.identity, name)
	if err != nil {
		return StoredObject{}, err
	}
	if !exists {
		return StoredObject{}, fmt.Errorf("%w: %s", ErrObjectNotFound, name)
	}
	return StoredObject{Descriptor: descriptor, Content: content}, nil
}

func (store *PortControlStore) CompareAndSwap(ctx context.Context, name ControlObjectName, expected Generation, content []byte) (ObjectDescriptor, error) {
	if store == nil || store.port == nil || name.value == "" || expected == 0 {
		return ObjectDescriptor{}, ErrInvalidStoreRequest
	}
	return store.port.UploadIfGenerationMatch(ctx, store.identity, name, expected, content)
}

var _ ControlStore = (*PortControlStore)(nil)

func timePointer(value time.Time) *time.Time { return &value }
