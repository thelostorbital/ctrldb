// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestApprovalClassRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		class domain.ApprovalClass
	}{
		{name: "read", class: domain.ApprovalRead},
		{name: "safe-write", class: domain.ApprovalSafeWrite},
		{name: "protected", class: domain.ApprovalProtected},
		{name: "security-sensitive", class: domain.ApprovalSecuritySensitive},
		{name: "destructive", class: domain.ApprovalDestructive},
		{name: "data-destructive", class: domain.ApprovalDataDestructive},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := domain.ParseApprovalClass(test.name)
			if err != nil {
				t.Fatalf("ParseApprovalClass(%q) returned an error: %v", test.name, err)
			}
			if parsed != test.class {
				t.Fatalf("ParseApprovalClass(%q) = %v, want %v", test.name, parsed, test.class)
			}
			if parsed.String() != test.name {
				t.Fatalf("ApprovalClass.String() = %q, want %q", parsed.String(), test.name)
			}
		})
	}
}

func TestApprovalClassRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "protected ", "PROTECTED", "ap-2", "unknown"} {
		_, err := domain.ParseApprovalClass(value)
		if !errors.Is(err, domain.ErrInvalidApprovalClass) {
			t.Errorf("ParseApprovalClass(%q) error = %v, want ErrInvalidApprovalClass", value, err)
		}
	}
}

func TestApprovalClassJSONRoundTrip(t *testing.T) {
	t.Parallel()

	type document struct {
		Class domain.ApprovalClass `json:"class"`
	}

	encoded, err := json.Marshal(document{Class: domain.ApprovalProtected})
	if err != nil {
		t.Fatalf("json.Marshal() returned an error: %v", err)
	}
	if string(encoded) != `{"class":"protected"}` {
		t.Fatalf("json.Marshal() = %s, want a stable class name", encoded)
	}

	var decoded document
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() returned an error: %v", err)
	}
	if decoded.Class != domain.ApprovalProtected {
		t.Fatalf("decoded class = %v, want %v", decoded.Class, domain.ApprovalProtected)
	}
}

func TestApprovalClassJSONRejectsUnknownValue(t *testing.T) {
	t.Parallel()

	var class domain.ApprovalClass
	err := json.Unmarshal([]byte(`"unsafe"`), &class)
	if !errors.Is(err, domain.ErrInvalidApprovalClass) {
		t.Fatalf("json.Unmarshal() error = %v, want ErrInvalidApprovalClass", err)
	}
}

func TestMaxApprovalClassCannotWeakenClassification(t *testing.T) {
	t.Parallel()

	class, err := domain.MaxApprovalClass(
		domain.ApprovalProtected,
		domain.ApprovalRead,
		domain.ApprovalSecuritySensitive,
	)
	if err != nil {
		t.Fatalf("MaxApprovalClass() returned an error: %v", err)
	}
	if class != domain.ApprovalSecuritySensitive {
		t.Fatalf("MaxApprovalClass() = %v, want %v", class, domain.ApprovalSecuritySensitive)
	}
}

func TestMaxApprovalClassRejectsInvalidOrEmptyInput(t *testing.T) {
	t.Parallel()

	if _, err := domain.MaxApprovalClass(); !errors.Is(err, domain.ErrInvalidApprovalClass) {
		t.Fatalf("MaxApprovalClass() empty input error = %v, want ErrInvalidApprovalClass", err)
	}

	invalid := domain.ApprovalClass(255)
	if _, err := domain.MaxApprovalClass(domain.ApprovalRead, invalid); !errors.Is(err, domain.ErrInvalidApprovalClass) {
		t.Fatalf("MaxApprovalClass() invalid input error = %v, want ErrInvalidApprovalClass", err)
	}
}
