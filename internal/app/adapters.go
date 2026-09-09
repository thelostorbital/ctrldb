// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

// ResourceState is the closed describe-before-act classification of one
// desired resource. Anything outside this set is a conflict.
type ResourceState string

const (
	// ResourceAbsent: the exact provider identity does not exist.
	ResourceAbsent ResourceState = "absent"
	// ResourceDesired: the resource exists at this step's exact desired state.
	ResourceDesired ResourceState = "desired"
	// ResourcePartial: the resource exists, is owned by this plan's sequence,
	// and has not yet received this step's mutation (for example a bucket
	// created by K1 whose retention is not yet locked). The adapter converges.
	ResourcePartial ResourceState = "partial"
	// ResourceConflicting: an unexpected or foreign state; execution stops.
	ResourceConflicting ResourceState = "conflicting"
	// ResourceUnknown: the observation could not classify the resource.
	ResourceUnknown ResourceState = "unknown"
)

// ResourceObservation is one exact, freshly observed desired resource.
type ResourceObservation struct {
	ResourceID string
	State      ResourceState
}

// StepObservation is the complete fresh observation of one step's desired
// resources. Revision is the canonical content fingerprint; ObservedAt and
// ValidUntil bound its freshness.
type StepObservation struct {
	Revision   string
	ObservedAt time.Time
	ValidUntil time.Time
	Resources  []ResourceObservation
}

// StepObserver is the read-only describe-before-act hook. It is typed to one
// intent and its desired resources and never receives argument vectors.
type StepObserver interface {
	Describe(ctx context.Context, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepObservation, error)
}

// StepResult is what an adapter observed after one authorized attempt.
// MutationOccurred must be true whenever any provider write was issued, even
// when the step then failed; CreatedResourceIDs lists the desired resources
// this attempt created.
type StepResult struct {
	MutationOccurred   bool
	CreatedResourceIDs []string
	Summary            string
}

// StepFailure is the typed adapter failure. Adapters classify the failure and
// state exactly what is known about mutation; an untyped error is treated as
// an unknown mutation and never retried.
type StepFailure struct {
	Class    domain.RetryFailureClass
	Mutation domain.MutationObservation
	Summary  string
}

func (failure *StepFailure) Error() string {
	if failure == nil {
		return "step failed"
	}
	return "step failed: " + string(failure.Class) + " (" + string(failure.Mutation) + ")"
}

// ErrStepFailed is the sentinel every StepFailure unwraps to.
var ErrStepFailed = errors.New("step failed")

func (failure *StepFailure) Unwrap() error { return ErrStepFailed }

// StorageAdapter applies the D-158 K1–K5 control/audit storage intents.
type StorageAdapter interface {
	Apply(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error)
	Compensate(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error)
}

// NetworkAdapter applies the T1–T4 Compute network intents.
type NetworkAdapter interface {
	Apply(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error)
	Compensate(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error)
}

// IdentityAdapter applies the T5/T6 IAM intents.
type IdentityAdapter interface {
	Apply(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error)
	Compensate(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error)
}

// WipeAdapter applies the T7 Cloud Run job and Scheduler intents.
type WipeAdapter interface {
	Apply(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error)
	Compensate(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (StepResult, error)
}

// PermissionProver produces fresh exact permission evidence for one step of
// the approved plan immediately before its mutation.
type PermissionProver interface {
	Prove(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (bootstrap.PermissionEvidence, error)
}

// IsolationGateVerifier runs the complete T8 TEST-ISO proof set and returns
// one bounded T8 evidence window. The live verifier is wired in M1-09b.
type IsolationGateVerifier interface {
	Verify(ctx context.Context, authorization MutationAuthorization, intent bootstrap.StepIntent, resources []bootstrap.DesiredResource) (isolation.T8Evidence, error)
}

// CredentialVerifier performs the final fresh human-credential revalidation
// for the explicit account the plan binds. The live verifier is M1-09b.
type CredentialVerifier interface {
	VerifyHumanCredential(ctx context.Context, account string) (CredentialEvidence, error)
}

// Adapters is the closed set of provider surfaces the engine dispatches to.
// Every entry is required; a missing adapter fails closed before any step.
type Adapters struct {
	Storage  StorageAdapter
	Network  NetworkAdapter
	Identity IdentityAdapter
	Wipe     WipeAdapter
	Prover   PermissionProver
	Gate     IsolationGateVerifier
}
