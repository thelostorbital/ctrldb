// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestOperationStateJSONRoundTrip(t *testing.T) {
	t.Parallel()

	type document struct {
		State domain.OperationState `json:"state"`
	}

	encoded, err := json.Marshal(document{State: domain.OperationExecute})
	if err != nil {
		t.Fatalf("json.Marshal() returned an error: %v", err)
	}
	if string(encoded) != `{"state":"EXECUTE"}` {
		t.Fatalf("json.Marshal() = %s, want canonical operation state", encoded)
	}

	var decoded document
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() returned an error: %v", err)
	}
	if decoded.State != domain.OperationExecute {
		t.Fatalf("decoded state = %q, want %q", decoded.State, domain.OperationExecute)
	}
}

func TestOperationStateRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "execute", " EXECUTE", "LOCK_CONFLICT", "VERIFY_FAILED"} {
		_, err := domain.ParseOperationState(value)
		if !errors.Is(err, domain.ErrInvalidOperationState) {
			t.Errorf("ParseOperationState(%q) error = %v, want ErrInvalidOperationState", value, err)
		}
	}

	var state domain.OperationState
	err := json.Unmarshal([]byte(`"LOCK_CONFLICT"`), &state)
	if !errors.Is(err, domain.ErrInvalidOperationState) {
		t.Fatalf("json.Unmarshal() error = %v, want ErrInvalidOperationState", err)
	}
}

func TestTerminalOperationStates(t *testing.T) {
	t.Parallel()

	terminal := []domain.OperationState{
		domain.OperationComplete,
		domain.OperationCompleteWithFailedVerification,
		domain.OperationCompleteWithDocumentationError,
		domain.OperationVerifiedRollback,
		domain.OperationCancelled,
		domain.OperationFailed,
		domain.OperationFailedCleanup,
	}

	for _, state := range terminal {
		if !state.Terminal() {
			t.Errorf("OperationState(%q).Terminal() = false, want true", state)
		}
	}

	if domain.OperationExecute.Terminal() {
		t.Fatal("OperationExecute.Terminal() = true, want false")
	}
}
