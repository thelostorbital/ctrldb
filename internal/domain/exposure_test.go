// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestExposureDeltaRoundTrip(t *testing.T) {
	t.Parallel()

	for _, want := range []domain.ExposureDelta{
		domain.ExposureNone,
		domain.ExposurePrivate,
		domain.ExposureTunnel,
		domain.ExposureExternal,
	} {
		parsed, err := domain.ParseExposureDelta(string(want))
		if err != nil {
			t.Fatalf("ParseExposureDelta(%q) returned an error: %v", want, err)
		}
		if parsed != want {
			t.Fatalf("ParseExposureDelta(%q) = %q", want, parsed)
		}

		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("json.Marshal(%q) returned an error: %v", want, err)
		}

		var decoded domain.ExposureDelta
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("json.Unmarshal(%s) returned an error: %v", encoded, err)
		}
		if decoded != want {
			t.Fatalf("decoded exposure = %q, want %q", decoded, want)
		}
	}
}

func TestExposureDeltaRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "NONE", "public", "external "} {
		_, err := domain.ParseExposureDelta(value)
		if !errors.Is(err, domain.ErrInvalidExposureDelta) {
			t.Errorf("ParseExposureDelta(%q) error = %v, want ErrInvalidExposureDelta", value, err)
		}
	}

	invalid := domain.ExposureDelta("invalid")
	if _, err := invalid.MarshalText(); !errors.Is(err, domain.ErrInvalidExposureDelta) {
		t.Fatalf("MarshalText() error = %v, want ErrInvalidExposureDelta", err)
	}

	var decoded domain.ExposureDelta
	if err := json.Unmarshal([]byte(`"public"`), &decoded); !errors.Is(err, domain.ErrInvalidExposureDelta) {
		t.Fatalf("json.Unmarshal() error = %v, want ErrInvalidExposureDelta", err)
	}

	var destination *domain.ExposureDelta
	if err := destination.UnmarshalText([]byte("none")); !errors.Is(err, domain.ErrInvalidExposureDelta) {
		t.Fatalf("UnmarshalText() error = %v, want ErrInvalidExposureDelta", err)
	}
}
