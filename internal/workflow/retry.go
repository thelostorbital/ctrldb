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
func DecideRetry(step StepDefinition, attempt uint32, failure domain.RetryFailureClass, mutation domain.MutationObservation) RetryDecision {
	if !step.Retry.Valid() || attempt == 0 || !failure.Valid() || !mutation.Valid() {
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
	if !step.Idempotent && mutation != domain.MutationNotOccurred {
		return noRetry("non-idempotent mutation was not proven absent")
	}
	if attempt >= step.Retry.MaxAttempts {
		return noRetry("retry limit reached")
	}

	delaySeconds := step.Retry.InitialBackoffSeconds
	for exponent := uint32(1); exponent < attempt; exponent++ {
		if delaySeconds >= step.Retry.MaxBackoffSeconds/2 {
			delaySeconds = step.Retry.MaxBackoffSeconds
			break
		}
		delaySeconds *= 2
	}
	if delaySeconds > step.Retry.MaxBackoffSeconds {
		delaySeconds = step.Retry.MaxBackoffSeconds
	}

	return RetryDecision{Retry: true, Delay: time.Duration(delaySeconds) * time.Second, Reason: "bounded transient retry"}
}

func noRetry(reason string) RetryDecision { return RetryDecision{Reason: reason} }
