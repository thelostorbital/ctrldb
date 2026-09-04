// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

// RetryDecision is a pure description of whether and when another attempt may
// start. A zero delay always accompanies a refusal.
type RetryDecision struct {
	Retry  bool
	Delay  time.Duration
	Reason string
}

// DecideRetry makes a side-effect-free retry decision for the just-completed
// one-based attempt. Invalid input fails closed.
func DecideRetry(
	contract domain.ExecutionContract,
	stepID string,
	attempt uint32,
	failure domain.RetryFailureClass,
	mutation domain.MutationObservation,
) RetryDecision {
	var matched *domain.ExecutionStepContract
	for _, step := range contract.Steps() {
		if step.ID == stepID {
			if matched != nil {
				return noRetry("ambiguous retry step")
			}
			stepCopy := step
			matched = &stepCopy
		}
	}
	if matched == nil || !matched.Retry.Valid() || attempt == 0 || !failure.Valid() || !mutation.Valid() {
		return noRetry("invalid retry input")
	}
	if failure == domain.RetryFailureValidation {
		return noRetry("validation failures require a new plan")
	}
	if failure == domain.RetryFailurePermission {
		return noRetry("permission failures require revalidation")
	}
	if failure == domain.RetryFailureStaleFingerprint {
		return noRetry("stale fingerprints require rediscovery and a new plan")
	}
	if mutation == domain.MutationUnknown {
		return noRetry("unknown mutation state requires rediscovery")
	}
	if !matched.Idempotent && mutation == domain.MutationOccurred {
		return noRetry("non-idempotent mutation was not proven absent")
	}
	if attempt >= matched.Retry.MaxAttempts {
		return noRetry("retry limit reached")
	}

	delaySeconds := matched.Retry.InitialBackoffSeconds
	for exponent := uint32(1); exponent < attempt; exponent++ {
		if delaySeconds >= matched.Retry.MaxBackoffSeconds/2 {
			delaySeconds = matched.Retry.MaxBackoffSeconds
			break
		}
		delaySeconds *= 2
	}
	if delaySeconds > matched.Retry.MaxBackoffSeconds {
		delaySeconds = matched.Retry.MaxBackoffSeconds
	}

	return RetryDecision{Retry: true, Delay: time.Duration(delaySeconds) * time.Second, Reason: "bounded transient retry"}
}

func noRetry(reason string) RetryDecision { return RetryDecision{Reason: reason} }
