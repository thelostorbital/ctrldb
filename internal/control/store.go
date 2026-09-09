// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"sync"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

var (
	// ErrInvalidObjectName is returned when a name cannot be formed from the
	// closed ARCHITECTURE prefix layout.
	ErrInvalidObjectName = errors.New("invalid control-plane object name")
	// ErrObjectNotFound is returned by reads of an absent object.
	ErrObjectNotFound = errors.New("control-plane object not found")
	// ErrPreconditionFailed is returned when a create finds an existing object
	// or a compare-and-swap generation no longer matches.
	ErrPreconditionFailed = errors.New("control-plane generation precondition failed")
	// ErrInvalidStoreRequest is returned for an unusable store argument.
	ErrInvalidStoreRequest = errors.New("invalid control-plane store request")

	crc32cTable = crc32.MakeTable(crc32.Castagnoli)
)

// Generation is a server object generation. Zero means "must not exist".
type Generation uint64

// ObjectDescriptor is the integrity view of one stored object: the server
// generation plus the size and CRC32C that `objects describe` exposes.
type ObjectDescriptor struct {
	Generation Generation `json:"generation"`
	Size       int64      `json:"size"`
	CRC32C     uint32     `json:"crc32c"`
}

// DescribeContent computes the descriptor fields a compliant store must report
// for content, excluding the server-assigned generation.
func DescribeContent(content []byte) ObjectDescriptor {
	return ObjectDescriptor{Size: int64(len(content)), CRC32C: crc32.Checksum(content, crc32cTable)}
}

// MatchesContent reports whether descriptor has exactly the size and CRC32C of
// content. It never treats a missing checksum as a match.
func (descriptor ObjectDescriptor) MatchesContent(content []byte) bool {
	expected := DescribeContent(content)
	return descriptor.Generation != 0 && descriptor.Size == expected.Size && descriptor.CRC32C == expected.CRC32C
}

// StoredObject is one read result.
type StoredObject struct {
	Descriptor ObjectDescriptor
	Content    []byte
}

// ControlObjectName is a validated name in the mutable control bucket. It can
// be produced only by the typed constructors below.
type ControlObjectName struct{ value string }

func (name ControlObjectName) String() string { return name.value }

// AuditObjectName is a validated name in the append-only audit bucket.
type AuditObjectName struct{ value string }

func (name AuditObjectName) String() string { return name.value }

// LockObjectName is `locks/<env>.json` (ARCHITECTURE lock protocol).
func LockObjectName(environment string) (ControlObjectName, error) {
	if !environmentPattern.MatchString(environment) {
		return ControlObjectName{}, invalidName("environment")
	}
	return ControlObjectName{value: "locks/" + environment + ".json"}, nil
}

// HarnessStateObjectName is the WF-TEST-01 T8 flag object.
func HarnessStateObjectName() ControlObjectName {
	return ControlObjectName{value: "test/harness-state.json"}
}

// OwnershipRecordObjectName is the D-157 durable ownership record of one
// permanent harness singleton, kept under the disposable `test/` subtree.
func OwnershipRecordObjectName(environment, resourceID string) (ControlObjectName, error) {
	if !environmentPattern.MatchString(environment) || !canonicalIDPattern.MatchString(resourceID) {
		return ControlObjectName{}, invalidName("ownership record")
	}
	return ControlObjectName{value: "test/ownership/" + environment + "/" + resourceID + ".json"}, nil
}

// LifetimeRecordObjectName is the immutable D-157 run lifetime record.
func LifetimeRecordObjectName(environment, runID string) (ControlObjectName, error) {
	if !environmentPattern.MatchString(environment) || !canonicalIDPattern.MatchString(runID) {
		return ControlObjectName{}, invalidName("lifetime record")
	}
	return ControlObjectName{value: "test/lifetime/" + environment + "/" + runID + ".json"}, nil
}

// AdoptionObjectName is `adoption/<env>.json` (K4 seed).
func AdoptionObjectName(environment string) (ControlObjectName, error) {
	if !environmentPattern.MatchString(environment) {
		return ControlObjectName{}, invalidName("environment")
	}
	return ControlObjectName{value: "adoption/" + environment + ".json"}, nil
}

// ApprovedPolicyObjectName is `policy/<env>/manifest-approved.json` (K4 seed).
func ApprovedPolicyObjectName(environment string) (ControlObjectName, error) {
	if !environmentPattern.MatchString(environment) {
		return ControlObjectName{}, invalidName("environment")
	}
	return ControlObjectName{value: "policy/" + environment + "/manifest-approved.json"}, nil
}

// CostCeilingObjectName is `policy/<env>/cost-ceiling.json` (K4 seed).
func CostCeilingObjectName(environment string) (ControlObjectName, error) {
	if !environmentPattern.MatchString(environment) {
		return ControlObjectName{}, invalidName("environment")
	}
	return ControlObjectName{value: "policy/" + environment + "/cost-ceiling.json"}, nil
}

// PlanObjectName is the immutable `plans/<env>/<planId>.json` audit object.
func PlanObjectName(environment, planID string) (AuditObjectName, error) {
	if !environmentPattern.MatchString(environment) || !planIDPattern.MatchString(planID) {
		return AuditObjectName{}, invalidName("plan")
	}
	return AuditObjectName{value: "plans/" + environment + "/" + planID + ".json"}, nil
}

// PlanApprovalObjectName is `plans/<env>/<planId>-approval.json`.
func PlanApprovalObjectName(environment, planID string) (AuditObjectName, error) {
	if !environmentPattern.MatchString(environment) || !planIDPattern.MatchString(planID) {
		return AuditObjectName{}, invalidName("plan approval")
	}
	return AuditObjectName{value: "plans/" + environment + "/" + planID + "-approval.json"}, nil
}

// OperationRecordObjectName is the final `operations/<env>/<opId>.json` record.
func OperationRecordObjectName(environment, operationID string) (AuditObjectName, error) {
	if !environmentPattern.MatchString(environment) || !operationIDPattern.MatchString(operationID) {
		return AuditObjectName{}, invalidName("operation record")
	}
	return AuditObjectName{value: "operations/" + environment + "/" + operationID + ".json"}, nil
}

// BootstrapEnvelopeObjectName is the audit copy of the D-158 envelope, kept
// beside the operation's journal entries.
func BootstrapEnvelopeObjectName(environment, operationID string) (AuditObjectName, error) {
	if !environmentPattern.MatchString(environment) || !operationIDPattern.MatchString(operationID) {
		return AuditObjectName{}, invalidName("bootstrap envelope")
	}
	return AuditObjectName{value: "operations/" + environment + "/" + operationID + "/bootstrap-envelope.json"}, nil
}

// JournalEntryObjectName is `operations/<env>/<opId>/steps/<seq>-<entryId>.json`
// using the workflow package's lexically sortable immutable file name.
func JournalEntryObjectName(environment string, entry domain.JournalEntry) (AuditObjectName, error) {
	if !environmentPattern.MatchString(environment) {
		return AuditObjectName{}, invalidName("environment")
	}
	fileName, err := workflow.JournalObjectName(entry)
	if err != nil {
		return AuditObjectName{}, invalidName("journal entry")
	}
	return AuditObjectName{value: "operations/" + environment + "/" + entry.OperationID + "/steps/" + fileName}, nil
}

// ControlStore is the normal generation-preconditioned durable store. It has
// no unconstrained delete: every write is create-only or a compare-and-swap.
type ControlStore interface {
	Create(ctx context.Context, name ControlObjectName, content []byte) (ObjectDescriptor, error)
	Read(ctx context.Context, name ControlObjectName) (StoredObject, error)
	CompareAndSwap(ctx context.Context, name ControlObjectName, expected Generation, content []byte) (ObjectDescriptor, error)
}

// AuditStore is the append-only store. It deliberately has no overwrite,
// compare-and-swap, or delete method.
type AuditStore interface {
	Create(ctx context.Context, name AuditObjectName, content []byte) (ObjectDescriptor, error)
	Read(ctx context.Context, name AuditObjectName) (StoredObject, error)
}

type memoryObject struct {
	descriptor ObjectDescriptor
	content    []byte
}

type memoryObjects struct {
	mutex      sync.Mutex
	generation Generation
	objects    map[string]memoryObject
}

func (store *memoryObjects) create(name string, content []byte) (ObjectDescriptor, error) {
	if name == "" {
		return ObjectDescriptor{}, ErrInvalidStoreRequest
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if _, exists := store.objects[name]; exists {
		return ObjectDescriptor{}, fmt.Errorf("%w: %s exists", ErrPreconditionFailed, name)
	}
	return store.put(name, content), nil
}

func (store *memoryObjects) put(name string, content []byte) ObjectDescriptor {
	store.generation++
	descriptor := DescribeContent(content)
	descriptor.Generation = store.generation
	store.objects[name] = memoryObject{descriptor: descriptor, content: append([]byte(nil), content...)}
	return descriptor
}

func (store *memoryObjects) read(name string) (StoredObject, error) {
	if name == "" {
		return StoredObject{}, ErrInvalidStoreRequest
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	object, exists := store.objects[name]
	if !exists {
		return StoredObject{}, fmt.Errorf("%w: %s", ErrObjectNotFound, name)
	}
	return StoredObject{Descriptor: object.descriptor, Content: append([]byte(nil), object.content...)}, nil
}

func (store *memoryObjects) compareAndSwap(name string, expected Generation, content []byte) (ObjectDescriptor, error) {
	if name == "" || expected == 0 {
		return ObjectDescriptor{}, ErrInvalidStoreRequest
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	object, exists := store.objects[name]
	if !exists {
		return ObjectDescriptor{}, fmt.Errorf("%w: %s", ErrObjectNotFound, name)
	}
	if object.descriptor.Generation != expected {
		return ObjectDescriptor{}, fmt.Errorf("%w: %s generation moved", ErrPreconditionFailed, name)
	}
	return store.put(name, content), nil
}

func (store *memoryObjects) names() []string {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	result := make([]string, 0, len(store.objects))
	for name := range store.objects {
		result = append(result, name)
	}
	return result
}

// MemoryControlStore is the in-memory ControlStore used by tests and by the
// I/O-free orchestration core.
type MemoryControlStore struct{ objects memoryObjects }

// NewMemoryControlStore returns an empty store with monotonic generations.
func NewMemoryControlStore() *MemoryControlStore {
	return &MemoryControlStore{objects: memoryObjects{objects: make(map[string]memoryObject)}}
}

func (store *MemoryControlStore) Create(ctx context.Context, name ControlObjectName, content []byte) (ObjectDescriptor, error) {
	if err := storeContext(ctx); err != nil {
		return ObjectDescriptor{}, err
	}
	return store.objects.create(name.value, content)
}

func (store *MemoryControlStore) Read(ctx context.Context, name ControlObjectName) (StoredObject, error) {
	if err := storeContext(ctx); err != nil {
		return StoredObject{}, err
	}
	return store.objects.read(name.value)
}

func (store *MemoryControlStore) CompareAndSwap(ctx context.Context, name ControlObjectName, expected Generation, content []byte) (ObjectDescriptor, error) {
	if err := storeContext(ctx); err != nil {
		return ObjectDescriptor{}, err
	}
	return store.objects.compareAndSwap(name.value, expected, content)
}

// Names lists stored object names for assertions. It exposes no mutation.
func (store *MemoryControlStore) Names() []string { return store.objects.names() }

// MemoryAuditStore is the in-memory append-only AuditStore.
type MemoryAuditStore struct{ objects memoryObjects }

// NewMemoryAuditStore returns an empty append-only store.
func NewMemoryAuditStore() *MemoryAuditStore {
	return &MemoryAuditStore{objects: memoryObjects{objects: make(map[string]memoryObject)}}
}

func (store *MemoryAuditStore) Create(ctx context.Context, name AuditObjectName, content []byte) (ObjectDescriptor, error) {
	if err := storeContext(ctx); err != nil {
		return ObjectDescriptor{}, err
	}
	return store.objects.create(name.value, content)
}

func (store *MemoryAuditStore) Read(ctx context.Context, name AuditObjectName) (StoredObject, error) {
	if err := storeContext(ctx); err != nil {
		return StoredObject{}, err
	}
	return store.objects.read(name.value)
}

// Names lists stored object names for assertions. It exposes no mutation.
func (store *MemoryAuditStore) Names() []string { return store.objects.names() }

var (
	_ ControlStore = (*MemoryControlStore)(nil)
	_ AuditStore   = (*MemoryAuditStore)(nil)
)

func storeContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidStoreRequest
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidStoreRequest, err)
	}
	return nil
}

func invalidName(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidObjectName, strings.TrimSpace(field))
}
