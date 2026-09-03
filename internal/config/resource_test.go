// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"errors"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestValidateGeneratedEnvironmentResource(t *testing.T) {
	t.Parallel()

	labels, err := config.ExpectedLabels("production", domain.EnvironmentProduction)
	if err != nil {
		t.Fatalf("ExpectedLabels() error = %v", err)
	}
	labels["service"] = "mongodb"
	resource := config.GeneratedResource{Name: "ctrldb-production-backup", Labels: labels}

	if err := config.ValidateGeneratedResource(resource, "production", domain.EnvironmentProduction); err != nil {
		t.Fatalf("ValidateGeneratedResource() error = %v", err)
	}
}

func TestValidateGeneratedEnvironmentResourceRejectsUnsafeIdentity(t *testing.T) {
	t.Parallel()

	validLabels := map[string]string{
		config.LabelManagedBy:   config.LabelManagedByValue,
		config.LabelEnvironment: "production",
	}
	tests := []struct {
		name        string
		resource    config.GeneratedResource
		environment string
		class       domain.EnvironmentClass
	}{
		{name: "unsafe name", resource: config.GeneratedResource{Name: "ctrldb-Production", Labels: validLabels}, environment: "production", class: domain.EnvironmentProduction},
		{name: "foreign namespace", resource: config.GeneratedResource{Name: "database-production", Labels: validLabels}, environment: "production", class: domain.EnvironmentProduction},
		{name: "reserved test namespace", resource: config.GeneratedResource{Name: "ctrldb-test-run1-vm", Labels: validLabels}, environment: "production", class: domain.EnvironmentProduction},
		{name: "wrong environment label", resource: config.GeneratedResource{Name: "ctrldb-production-vm", Labels: map[string]string{config.LabelManagedBy: config.LabelManagedByValue, config.LabelEnvironment: "staging"}}, environment: "production", class: domain.EnvironmentProduction},
		{name: "missing managed label", resource: config.GeneratedResource{Name: "ctrldb-production-vm", Labels: map[string]string{config.LabelEnvironment: "production"}}, environment: "production", class: domain.EnvironmentProduction},
		{name: "invalid environment", resource: config.GeneratedResource{Name: "ctrldb-production-vm", Labels: validLabels}, environment: "Production", class: domain.EnvironmentProduction},
		{name: "reserved environment", resource: config.GeneratedResource{Name: "ctrldb-test-east-vm", Labels: validLabels}, environment: "test-east", class: domain.EnvironmentStaging},
		{name: "invalid class", resource: config.GeneratedResource{Name: "ctrldb-production-vm", Labels: validLabels}, environment: "production", class: "prod"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := config.ValidateGeneratedResource(test.resource, test.environment, test.class); !errors.Is(err, config.ErrInvalidGeneratedResource) {
				t.Fatalf("ValidateGeneratedResource() error = %v", err)
			}
		})
	}
}

func TestValidateGeneratedTestResourceRequiresPrefixAndLabels(t *testing.T) {
	t.Parallel()

	valid := config.GeneratedResource{
		Name: "ctrldb-test-run1-vm",
		Labels: map[string]string{
			config.LabelManagedBy:   config.LabelManagedByValue,
			config.LabelEnvironment: config.TestEnvironmentLabel,
			config.LabelPurpose:     config.TestResourcePurposeLabel,
		},
	}
	if err := config.ValidateGeneratedResource(valid, "lab", domain.EnvironmentDisposable); err != nil {
		t.Fatalf("ValidateGeneratedResource() error = %v", err)
	}
	if !config.IsTestResource(valid) {
		t.Fatal("IsTestResource() = false for exact test identity")
	}

	tests := []struct {
		name     string
		resource config.GeneratedResource
	}{
		{name: "labels without prefix", resource: config.GeneratedResource{Name: "ctrldb-lab-vm", Labels: valid.Labels}},
		{name: "prefix without labels", resource: config.GeneratedResource{Name: valid.Name, Labels: map[string]string{}}},
		{name: "wrong environment", resource: config.GeneratedResource{Name: valid.Name, Labels: map[string]string{config.LabelManagedBy: config.LabelManagedByValue, config.LabelEnvironment: "lab", config.LabelPurpose: config.TestResourcePurposeLabel}}},
		{name: "wrong purpose", resource: config.GeneratedResource{Name: valid.Name, Labels: map[string]string{config.LabelManagedBy: config.LabelManagedByValue, config.LabelEnvironment: config.TestEnvironmentLabel, config.LabelPurpose: "rehearsal"}}},
		{name: "wrong manager", resource: config.GeneratedResource{Name: valid.Name, Labels: map[string]string{config.LabelManagedBy: "other", config.LabelEnvironment: config.TestEnvironmentLabel, config.LabelPurpose: config.TestResourcePurposeLabel}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if config.IsTestResource(test.resource) {
				t.Fatal("IsTestResource() accepted an incomplete test selector")
			}
		})
	}
}

func TestExpectedLabelsReturnsDetachedMaps(t *testing.T) {
	t.Parallel()

	first, err := config.ExpectedLabels("production", domain.EnvironmentProduction)
	if err != nil {
		t.Fatalf("ExpectedLabels() error = %v", err)
	}
	second, err := config.ExpectedLabels("production", domain.EnvironmentProduction)
	if err != nil {
		t.Fatalf("ExpectedLabels() error = %v", err)
	}
	first[config.LabelManagedBy] = "changed"
	if second[config.LabelManagedBy] != config.LabelManagedByValue {
		t.Fatal("ExpectedLabels() returned shared mutable storage")
	}

	testLabels, err := config.ExpectedLabels("lab", domain.EnvironmentDisposable)
	if err != nil {
		t.Fatalf("ExpectedLabels(disposable) error = %v", err)
	}
	if testLabels[config.LabelEnvironment] != config.TestEnvironmentLabel || testLabels[config.LabelPurpose] != config.TestResourcePurposeLabel {
		t.Fatalf("ExpectedLabels(disposable) = %#v", testLabels)
	}
}
