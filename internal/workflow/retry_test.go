// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

func TestRetryDecisionsArePureAndBounded(t *testing.T) {
	t.Parallel()

	step := validDefinitionStep()
	contract := retryContract(t, step)
	want := workflow.RetryDecision{Retry: true, Delay: 4 * time.Second, Reason: "bounded transient retry"}
	first := workflow.DecideRetry(contract, step.ID, 2, domain.RetryFailureTransient, domain.MutationOccurred)
	second := workflow.DecideRetry(contract, step.ID, 2, domain.RetryFailureTransient, domain.MutationOccurred)
	if !reflect.DeepEqual(first, want) || !reflect.DeepEqual(second, want) {
		t.Fatalf("DecideRetry() = %#v / %#v, want %#v", first, second, want)
	}

	if got := workflow.DecideRetry(contract, step.ID, 3, domain.RetryFailureTimeout, domain.MutationUnknown); got.Retry || got.Delay != 0 {
		t.Fatalf("attempt at limit retried: %#v", got)
	}
}

func TestRetryExcludesSafetyFailuresAndUnobservedNonIdempotentMutation(t *testing.T) {
	t.Parallel()

	step := validDefinitionStep()
	contract := retryContract(t, step)
	if got := workflow.DecideRetry(contract, step.ID, 1, domain.RetryFailureTransient, domain.MutationUnknown); got.Retry || got.Delay != 0 {
		t.Fatalf("DecideRetry(idempotent, unknown mutation) = %#v, want refusal", got)
	}
	for _, failure := range []domain.RetryFailureClass{
		domain.RetryFailureValidation,
		domain.RetryFailurePermission,
		domain.RetryFailureStaleFingerprint,
	} {
		if got := workflow.DecideRetry(contract, step.ID, 1, failure, domain.MutationNotOccurred); got.Retry || got.Delay != 0 {
			t.Errorf("DecideRetry(%s) = %#v, want refusal", failure, got)
		}
	}

	step.Idempotent = false
	contract = retryContract(t, step)
	for _, mutation := range []domain.MutationObservation{domain.MutationOccurred, domain.MutationUnknown} {
		if got := workflow.DecideRetry(contract, step.ID, 1, domain.RetryFailureTransient, mutation); got.Retry || got.Delay != 0 {
			t.Errorf("DecideRetry(non-idempotent, %s) = %#v, want refusal", mutation, got)
		}
	}
	if got := workflow.DecideRetry(contract, step.ID, 1, domain.RetryFailureTransient, domain.MutationNotOccurred); !got.Retry {
		t.Fatalf("proven non-mutation was not retried: %#v", got)
	}

	if got := workflow.DecideRetry(contract, step.ID, 0, domain.RetryFailureTransient, domain.MutationNotOccurred); got.Retry {
		t.Fatalf("invalid zero attempt retried: %#v", got)
	}
}

func TestRetryUsesImmutableContractStep(t *testing.T) {
	t.Parallel()

	step := validDefinitionStep()
	step.Idempotent = false
	contract := retryContract(t, step)
	step.Idempotent = true
	if got := workflow.DecideRetry(
		contract, step.ID, 1, domain.RetryFailureTransient, domain.MutationOccurred,
	); got.Retry {
		t.Fatalf("detached idempotence mutation weakened retry contract: %#v", got)
	}
	for _, stepID := range []string{"", "missing-step", "STOP-INSTANCE"} {
		if got := workflow.DecideRetry(
			contract, stepID, 1, domain.RetryFailureTransient, domain.MutationNotOccurred,
		); got.Retry {
			t.Fatalf("DecideRetry(stepID=%q) = %#v, want refusal", stepID, got)
		}
	}
}

func retryContract(t *testing.T, step workflow.StepDefinition) domain.ExecutionContract {
	t.Helper()
	definition, err := workflow.NewDefinition(
		"WF-VM-02", "before-old-instance-delete", step.ID, []workflow.StepDefinition{step},
	)
	if err != nil {
		t.Fatalf("NewDefinition() returned an error: %v", err)
	}

	return definition.ExecutionContract()
}
