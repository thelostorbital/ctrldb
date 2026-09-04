// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain

// Execution limits keep malformed workflow definitions from expressing an
// effectively unbounded operation.
const (
	MaxStepAttempts        uint32 = 10
	MaxRetryBackoffSeconds int64  = 3600
	MaxStepTimeoutSeconds  int64  = 86400
)

// RetryPolicy is the complete bounded retry contract for one step.
// MaxAttempts includes the initial attempt. A value of one explicitly means
// that the step is never retried.
type RetryPolicy struct {
	MaxAttempts           uint32 `json:"maxAttempts"`
	InitialBackoffSeconds int64  `json:"initialBackoffSeconds"`
	MaxBackoffSeconds     int64  `json:"maxBackoffSeconds"`
}

// Valid reports whether the policy is finite and internally consistent.
func (policy RetryPolicy) Valid() bool {
	if policy.MaxAttempts == 0 || policy.MaxAttempts > MaxStepAttempts {
		return false
	}
	if policy.MaxAttempts == 1 {
		return policy.InitialBackoffSeconds == 0 && policy.MaxBackoffSeconds == 0
	}

	return policy.InitialBackoffSeconds > 0 &&
		policy.InitialBackoffSeconds <= policy.MaxBackoffSeconds &&
		policy.MaxBackoffSeconds <= MaxRetryBackoffSeconds
}

// FailureBehavior is the declared engine route when a step cannot succeed.
type FailureBehavior string

const (
	FailureFail     FailureBehavior = "fail"
	FailurePause    FailureBehavior = "pause"
	FailureRollback FailureBehavior = "rollback"
)

// Valid reports whether behavior is a supported engine route.
func (behavior FailureBehavior) Valid() bool {
	return behavior == FailureFail || behavior == FailurePause || behavior == FailureRollback
}

// RetryFailureClass describes why one attempt failed. Safety and freshness
// failures are deliberately distinct from transient provider failures.
type RetryFailureClass string

const (
	RetryFailureTransient        RetryFailureClass = "transient"
	RetryFailureTimeout          RetryFailureClass = "timeout"
	RetryFailureValidation       RetryFailureClass = "validation"
	RetryFailurePermission       RetryFailureClass = "permission"
	RetryFailureStaleFingerprint RetryFailureClass = "stale-fingerprint"
)

// Valid reports whether class is part of the closed retry decision contract.
func (class RetryFailureClass) Valid() bool {
	switch class {
	case RetryFailureTransient, RetryFailureTimeout, RetryFailureValidation,
		RetryFailurePermission, RetryFailureStaleFingerprint:
		return true
	default:
		return false
	}
}

// MutationObservation records what is known after a failed attempt.
type MutationObservation string

const (
	MutationNotOccurred MutationObservation = "not-occurred"
	MutationOccurred    MutationObservation = "occurred"
	MutationUnknown     MutationObservation = "unknown"
)

// Valid reports whether observation is a supported durable value.
func (observation MutationObservation) Valid() bool {
	return observation == MutationNotOccurred || observation == MutationOccurred || observation == MutationUnknown
}
