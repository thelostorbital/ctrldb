// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
)

var (
	// ErrStoreConflict is returned by a ControlStore when a create-only or
	// compare-and-swap precondition fails. The engine never retries blindly
	// through a conflict; it re-reads and classifies.
	ErrStoreConflict = errors.New("control store precondition failed")
	// ErrStoreNotFound is returned when a typed record does not exist.
	ErrStoreNotFound = errors.New("control store record not found")
)

// EnvelopeRecord is the durable BootstrapEnvelopeV1 binding written by the
// M1-05 control bootstrap. Only its hash and generation are consumed here.
type EnvelopeRecord struct {
	Hash       string
	Generation uint64
}

// LockState is the closed environment lock state.
type LockState string

const (
	LockHeld     LockState = "held"
	LockReleased LockState = "released"
)

// LockRecord is the generation-bearing environment lock (ARCHITECTURE "Lock
// protocol"). Holder identity fields are omitted; the operation binding is
// what the gateway checks.
type LockRecord struct {
	State       LockState
	OperationID string
	PlanID      string
	WorkflowID  string
	AcquiredAt  time.Time
	HeartbeatAt time.Time
	LeaseUntil  time.Time
	Generation  uint64
}

// LockRequest asks the store to acquire or refresh the lock for one exact
// operation. Acquisition succeeds only when the lock is absent, released, or
// already held by the same operation; every other case is ErrStoreConflict.
type LockRequest struct {
	OperationID string
	PlanID      string
	WorkflowID  string
	Now         time.Time
	Lease       time.Duration
}

// HarnessStateRecord is the durable, generation-bearing HarnessStateV1.
type HarnessStateRecord struct {
	State      isolation.HarnessStateV1
	Generation uint64
}

// StepClaim is the durable operation/step/attempt claim written before every
// provider mutation. It records the exact fresh observation the attempt is
// based on and which desired resources were observed absent, so recorded
// compensation can never touch a resource that already existed.
type StepClaim struct {
	OperationID         string
	StepID              string
	Attempt             uint32
	ObservationRevision string
	ObservedAt          time.Time
	ClaimedAt           time.Time
	AbsentResourceIDs   []string
	PartialResourceIDs  []string
}

// StepClaimRecord is a stored claim and its generation.
type StepClaimRecord struct {
	Claim      StepClaim
	Generation uint64
}

// ControlStore is the typed, generation-preconditioned durable record surface
// the engine and gateway require. It exposes no unconstrained deletion. The
// M1-05 implementation supplies the local-envelope-then-bucket persistence
// beneath these operations; this package only relies on their semantics.
type ControlStore interface {
	ReadEnvelope(ctx context.Context) (EnvelopeRecord, error)

	ReadJournal(ctx context.Context, operationID string) ([]domain.JournalEntry, error)
	// AppendJournalEntry is create-only: the entry sequence must equal the
	// current stream length plus one, otherwise ErrStoreConflict.
	AppendJournalEntry(ctx context.Context, entry domain.JournalEntry) (uint64, error)

	ReadLock(ctx context.Context) (LockRecord, error)
	AcquireLock(ctx context.Context, request LockRequest) (LockRecord, error)
	// RefreshLock is a compare-and-swap heartbeat on the exact generation held.
	RefreshLock(ctx context.Context, held LockRecord, now time.Time) (LockRecord, error)
	ReleaseLock(ctx context.Context, held LockRecord, now time.Time) (LockRecord, error)

	ReadHarnessState(ctx context.Context) (HarnessStateRecord, error)
	// CreateHarnessState is create-only (ifGenerationMatch: 0).
	CreateHarnessState(ctx context.Context, state isolation.HarnessStateV1) (HarnessStateRecord, error)
	// ReplaceHarnessState is a compare-and-swap on the exact generation read.
	ReplaceHarnessState(ctx context.Context, expectedGeneration uint64, state isolation.HarnessStateV1) (HarnessStateRecord, error)

	// ClaimStep is create-only per (operation, step, attempt).
	ClaimStep(ctx context.Context, claim StepClaim) (StepClaimRecord, error)
	ListStepClaims(ctx context.Context, operationID string) ([]StepClaimRecord, error)
}
