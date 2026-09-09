// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

var (
	// ErrAuthorizationDenied is returned when the gateway refuses to issue a
	// mutation authorization. The wrapped detail names the failed gate.
	ErrAuthorizationDenied = errors.New("mutation authorization denied")
	// ErrApprovalInvalid is returned when the approval proof does not bind the
	// exact approved plan or is outside its validity window.
	ErrApprovalInvalid = errors.New("approval proof invalid")
	// ErrPlanExpired is returned when the approved plan validity has elapsed.
	ErrPlanExpired = errors.New("approved plan expired")
	// ErrObservationStale is returned when a provider observation is not fresh
	// at the authorization time.
	ErrObservationStale = errors.New("provider observation stale")
	// ErrLockLost is returned when the environment lock is not held by the
	// executing operation at the authorization time.
	ErrLockLost = errors.New("environment lock lost")
	// ErrIdentityMismatch is returned when the fresh credential does not match
	// the executing identity required by the approved intent.
	ErrIdentityMismatch = errors.New("executing identity mismatch")
	// ErrPermissionRevalidation is returned when fresh permission evidence does
	// not prove every permission the approved plan declares for a step.
	ErrPermissionRevalidation = errors.New("permission revalidation failed")
)

// MutationAuthorization is the one per-step value the gateway issues. Its
// exported fields are exactly the uniform mutation-authorization fields fixed
// by the M-1 parallel board; every provider adapter defines its own prefixed
// struct with these same fields and validates them before any process runs.
type MutationAuthorization struct {
	PlanDocumentSHA256    string
	PlanV1Hash            string
	EnvelopeBindingSHA256 string
	OperationID           string
	StepID                string
	Attempt               uint32
	ClaimGeneration       uint64
	ExecutingIdentity     domain.ExecutionIdentity
	ObservationRevision   string
	ObservedAt            time.Time
	ValidUntil            time.Time
	Now                   time.Time
}

// ApprovalProof is the AP-3 approval bound to one exact compiled plan. The
// positional plan identifier and the approval token must both name the plan;
// the document hash binds the complete compiled document and the PlanV1 hash
// binds the reviewed plan (UX §10, SECURITY §1.3).
type ApprovalProof struct {
	PlanID             string
	ApprovalToken      string
	PlanDocumentSHA256 string
	PlanV1Hash         string
	Principal          string
	ApprovalClass      domain.ApprovalClass
	ApprovedAt         time.Time
	ValidUntil         time.Time
}

// CredentialEvidence is the fresh human-credential revalidation result. The
// live verifier is wired in M1-09b; this package only consumes the evidence.
type CredentialEvidence struct {
	Account    string
	Identity   domain.ExecutionIdentity
	VerifiedAt time.Time
	ValidUntil time.Time
}

func denied(gate string) error {
	return &gateError{kind: ErrAuthorizationDenied, gate: gate}
}

func deniedAs(kind error, gate string) error {
	return &gateError{kind: kind, gate: gate}
}

type gateError struct {
	kind error
	gate string
}

func (err *gateError) Error() string { return err.kind.Error() + ": " + err.gate }
func (err *gateError) Unwrap() error { return err.kind }

func validUTC(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func freshAt(observedAt, validUntil, now time.Time) bool {
	return validUTC(observedAt) && validUTC(validUntil) && validUTC(now) &&
		observedAt.Before(validUntil) && !now.Before(observedAt) && now.Before(validUntil)
}
