// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestValidateManifestIdentity(t *testing.T) {
	t.Parallel()

	if config.ManifestAPIVersion != "ctrldb.ctrlboard.dev/v1alpha1" {
		t.Fatalf("ManifestAPIVersion = %q", config.ManifestAPIVersion)
	}
	if config.ManifestKind != "MongoEnvironment" {
		t.Fatalf("ManifestKind = %q", config.ManifestKind)
	}

	for _, class := range domain.EnvironmentClasses() {
		identity := validManifestIdentity()
		identity.Metadata.Class = class
		if err := config.ValidateManifestIdentity(identity); err != nil {
			t.Errorf("ValidateManifestIdentity(class %q) error = %v", class, err)
		}
	}
}

func TestValidateManifestIdentityRejectsInvalidHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*config.ManifestIdentity)
	}{
		{name: "empty api version", mutate: func(identity *config.ManifestIdentity) { identity.APIVersion = "" }},
		{name: "future api version", mutate: func(identity *config.ManifestIdentity) { identity.APIVersion = "ctrldb.ctrlboard.dev/v1" }},
		{name: "wrong kind", mutate: func(identity *config.ManifestIdentity) { identity.Kind = "Environment" }},
		{name: "empty name", mutate: func(identity *config.ManifestIdentity) { identity.Metadata.Name = "" }},
		{name: "uppercase name", mutate: func(identity *config.ManifestIdentity) { identity.Metadata.Name = "Production" }},
		{name: "leading hyphen", mutate: func(identity *config.ManifestIdentity) { identity.Metadata.Name = "-production" }},
		{name: "trailing hyphen", mutate: func(identity *config.ManifestIdentity) { identity.Metadata.Name = "production-" }},
		{name: "underscore", mutate: func(identity *config.ManifestIdentity) { identity.Metadata.Name = "production_main" }},
		{name: "too long", mutate: func(identity *config.ManifestIdentity) { identity.Metadata.Name = strings.Repeat("a", 64) }},
		{name: "reserved test name", mutate: func(identity *config.ManifestIdentity) { identity.Metadata.Name = "test" }},
		{name: "reserved test prefix", mutate: func(identity *config.ManifestIdentity) { identity.Metadata.Name = "test-east" }},
		{name: "unknown class", mutate: func(identity *config.ManifestIdentity) { identity.Metadata.Class = "prod" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			identity := validManifestIdentity()
			test.mutate(&identity)
			if err := config.ValidateManifestIdentity(identity); !errors.Is(err, config.ErrInvalidManifestIdentity) {
				t.Fatalf("ValidateManifestIdentity() error = %v", err)
			}
		})
	}
}

func TestValidateManifestIdentityAcceptsNameBoundary(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"p", "prod-1", strings.Repeat("a", 63)} {
		identity := validManifestIdentity()
		identity.Metadata.Name = name
		if err := config.ValidateManifestIdentity(identity); err != nil {
			t.Errorf("ValidateManifestIdentity(name %q) error = %v", name, err)
		}
	}
}

func validManifestIdentity() config.ManifestIdentity {
	return config.ManifestIdentity{
		APIVersion: config.ManifestAPIVersion,
		Kind:       config.ManifestKind,
		Metadata: config.ManifestMetadata{
			Name:  "production",
			Class: domain.EnvironmentProduction,
		},
	}
}
