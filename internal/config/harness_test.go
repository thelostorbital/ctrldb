// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHarnessConfigurationFromManifestPreservesExplicitValues(t *testing.T) {
	t.Parallel()

	manifest := validHarnessManifest(t)
	document, err := DecodeManifest(marshalManifest(t, manifest))
	if err != nil {
		t.Fatalf("DecodeManifest() unexpected error: %v", err)
	}
	configuration, err := HarnessConfigurationFromManifest(document)
	if err != nil {
		t.Fatalf("HarnessConfigurationFromManifest() unexpected error: %v", err)
	}

	checks := map[string][2]string{
		"environment":    {configuration.Environment(), "disposable-test"},
		"project":        {configuration.Project(), "example-project"},
		"region":         {configuration.Region(), "us-central1"},
		"zone":           {configuration.Zone(), "us-central1-a"},
		"control bucket": {configuration.ControlBucket(), "example-project-ctrldb-state"},
		"audit bucket":   {configuration.AuditBucket(), "example-project-ctrldb-audit"},
		"prefix":         {configuration.NamePrefix(), "ctrldb-test-"},
		"operator":       {configuration.OperatorPrincipal(), "ctrldb-test-operator@example-project.iam.gserviceaccount.com"},
		"destructive":    {configuration.DestructivePrincipal(), "ctrldb-test-destructive@example-project.iam.gserviceaccount.com"},
		"vm":             {configuration.VMPrincipal(), "ctrldb-test-vm@example-project.iam.gserviceaccount.com"},
		"ci":             {configuration.CIPrincipal(), "principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/attribute.repository/example-org/ctrldb"},
		"vpc":            {configuration.VPC(), "ctrldb-test-vpc"},
		"subnet":         {configuration.Subnet(), "ctrldb-test-subnet"},
		"cidr":           {configuration.CIDR(), "10.40.0.0/24"},
		"router":         {configuration.Router(), TestRouterName},
		"nat":            {configuration.NAT(), "ctrldb-test-nat"},
		"scheduler":      {configuration.WipeSchedulerJob(), "ctrldb-test-wipe-schedule"},
		"run job":        {configuration.WipeRunJob(), "ctrldb-test-wipe"},
		"wipe identity":  {configuration.WipeServiceAccount(), "ctrldb-test-wipe@example-project.iam.gserviceaccount.com"},
		"image":          {configuration.ImageDigest(), "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
		"machine type":   {configuration.Caps().MaxMachineType(), "e2-medium"},
	}
	for name, check := range checks {
		if check[0] != check[1] {
			t.Errorf("%s = %q; want %q", name, check[0], check[1])
		}
	}
	if configuration.Identity() != document.Identity() {
		t.Fatal("Identity() did not preserve the validated manifest identity")
	}
	if configuration.ManifestHash() == "" {
		t.Fatal("ManifestHash() is empty")
	}
	if !configuration.ReconcilerEnabled() {
		t.Fatal("ReconcilerEnabled() = false; disposable harness requires the wipe reconciler")
	}
	if got := configuration.Caps().MaxDiskGiB(); got != 100 {
		t.Errorf("MaxDiskGiB() = %d; want 100", got)
	}
	if got := configuration.Caps().MaxInstances(); got != 3 {
		t.Errorf("MaxInstances() = %d; want 3", got)
	}
	if got := configuration.Caps().MaxLifetime(); got != 8*time.Hour {
		t.Errorf("MaxLifetime() = %s; want 8h", got)
	}
	if got := configuration.Caps().MaxEstimatedCostMicros(); got != 25_000_000 {
		t.Errorf("MaxEstimatedCostMicros() = %d; want 25000000", got)
	}
}

func TestHarnessConfigurationAcceptsSchemaDayLifetime(t *testing.T) {
	t.Parallel()

	manifest := validHarnessManifest(t)
	nestedMap(t, manifest, "spec", "testIsolation", "caps")["maxLifetime"] = "1d"
	document, err := DecodeManifest(marshalManifest(t, manifest))
	if err != nil {
		t.Fatalf("DecodeManifest(1d) unexpected error: %v", err)
	}
	configuration, err := HarnessConfigurationFromManifest(document)
	if err != nil {
		t.Fatalf("HarnessConfigurationFromManifest(1d) unexpected error: %v", err)
	}
	if got := configuration.Caps().MaxLifetime(); got != 24*time.Hour {
		t.Fatalf("MaxLifetime() = %s; want %s", got, 24*time.Hour)
	}
}

func TestHarnessConfigurationDoesNotAliasManifestOrReturnedLabels(t *testing.T) {
	t.Parallel()

	manifest := validHarnessManifest(t)
	document, err := DecodeManifest(marshalManifest(t, manifest))
	if err != nil {
		t.Fatalf("DecodeManifest() unexpected error: %v", err)
	}
	configuration, err := HarnessConfigurationFromManifest(document)
	if err != nil {
		t.Fatalf("HarnessConfigurationFromManifest() unexpected error: %v", err)
	}

	labels := configuration.Labels()
	labels[LabelManagedBy] = "changed"
	if got := configuration.Labels()[LabelManagedBy]; got != LabelManagedByValue {
		t.Fatalf("Labels() aliases immutable configuration: got %q", got)
	}
	manifestLabels := nestedMap(t, manifest, "spec", "testIsolation", "labels")
	manifestLabels[LabelPurpose] = "changed"
	if got := configuration.Labels()[LabelPurpose]; got != TestResourcePurposeLabel {
		t.Fatalf("configuration aliases decoded manifest: got %q", got)
	}
}

func TestHarnessConfigurationRoundsFractionalMicroUSDUp(t *testing.T) {
	t.Parallel()

	manifest := validHarnessManifest(t)
	nestedMap(t, manifest, "spec", "testIsolation", "caps")["maxEstimatedUSDPerRun"] = 1.0000001
	document, err := DecodeManifest(marshalManifest(t, manifest))
	if err != nil {
		t.Fatalf("DecodeManifest() unexpected error: %v", err)
	}
	configuration, err := HarnessConfigurationFromManifest(document)
	if err != nil {
		t.Fatalf("HarnessConfigurationFromManifest() unexpected error: %v", err)
	}
	if got := configuration.Caps().MaxEstimatedCostMicros(); got != 1_000_001 {
		t.Fatalf("MaxEstimatedCostMicros() = %d; want upward-rounded 1000001", got)
	}
}

func TestHarnessConfigurationRequiresCompleteValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*testing.T, map[string]any)
	}{
		{name: "non disposable", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "metadata")["class"] = "staging"
		}},
		{name: "schema invalid", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "testIsolation", "network")["unexpected"] = true
		}},
		{name: "policy invalid", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "testIsolation", "network")["cidr"] = "10.30.0.0/25"
		}},
		{name: "impersonated discovery identity", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "gcp", "identity")["discovery"] = "impersonate"
		}},
		{name: "shared VPC host project", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "gcp", "sharedVpc")["hostProject"] = "shared-host-project"
		}},
		{name: "public CI principal", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "testIsolation")["ciPrincipal"] = "allUsers"
		}},
		{name: "unscoped CI principal", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "testIsolation")["ciPrincipal"] = "principalSet://example-ci"
		}},
		{name: "disabled wipe reconciler", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "reconciler")["enabled"] = false
		}},
		{name: "shared operator and destructive identity", mutate: func(t *testing.T, manifest map[string]any) {
			isolation := nestedMap(t, manifest, "spec", "testIsolation")
			isolation["destructiveServiceAccount"] = isolation["operatorServiceAccount"]
		}},
		{name: "operator is database VM identity", mutate: func(t *testing.T, manifest map[string]any) {
			isolation := nestedMap(t, manifest, "spec", "testIsolation")
			isolation["operatorServiceAccount"] = nestedMap(t, manifest, "spec", "host")["serviceAccount"]
		}},
		{name: "destructive is database VM identity", mutate: func(t *testing.T, manifest map[string]any) {
			isolation := nestedMap(t, manifest, "spec", "testIsolation")
			isolation["destructiveServiceAccount"] = nestedMap(t, manifest, "spec", "host")["serviceAccount"]
		}},
		{name: "wipe is database VM identity", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "reconciler")["serviceAccount"] = nestedMap(t, manifest, "spec", "host")["serviceAccount"]
		}},
		{name: "wipe is operator identity", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "reconciler")["serviceAccount"] = nestedMap(t, manifest, "spec", "testIsolation")["operatorServiceAccount"]
		}},
		{name: "wipe is destructive identity", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "reconciler")["serviceAccount"] = nestedMap(t, manifest, "spec", "testIsolation")["destructiveServiceAccount"]
		}},
		{name: "operator belongs to another project", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "testIsolation")["operatorServiceAccount"] = "ctrldb-test-operator@foreign-project.iam.gserviceaccount.com"
		}},
		{name: "destructive belongs to another project", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "testIsolation")["destructiveServiceAccount"] = "ctrldb-test-destructive@foreign-project.iam.gserviceaccount.com"
		}},
		{name: "wipe belongs to another project", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "reconciler")["serviceAccount"] = "ctrldb-test-wipe@foreign-project.iam.gserviceaccount.com"
		}},
		{name: "operator has provider-invalid identity", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "testIsolation")["operatorServiceAccount"] = "BAD@example-project.iam.gserviceaccount.com"
		}},
		{name: "subnet has trailing hyphen", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "testIsolation", "network")["subnet"] = "ctrldb-test-invalid-"
		}},
		{name: "subnet exceeds provider length", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "testIsolation", "network")["subnet"] = "ctrldb-test-" + strings.Repeat("a", 53)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			manifest := validHarnessManifest(t)
			test.mutate(t, manifest)
			document, err := DecodeManifestEnvelope(marshalManifest(t, manifest))
			if err != nil {
				t.Fatalf("DecodeManifestEnvelope() unexpected error: %v", err)
			}
			if _, err := HarnessConfigurationFromManifest(document); !errors.Is(err, ErrInvalidHarnessConfiguration) {
				t.Fatalf("HarnessConfigurationFromManifest() error = %v; want ErrInvalidHarnessConfiguration", err)
			}
		})
	}
}

func validHarnessManifest(t *testing.T) map[string]any {
	t.Helper()

	manifest := manifestFixtureMap(t)
	metadata := nestedMap(t, manifest, "metadata")
	metadata["name"] = "disposable-test"
	metadata["class"] = "disposable"
	nestedMap(t, manifest, "spec")["testIsolation"] = validTestIsolation()
	nestedMap(t, manifest, "spec", "host")["serviceAccount"] = "ctrldb-test-vm@example-project.iam.gserviceaccount.com"
	reconciler := nestedMap(t, manifest, "spec", "reconciler")
	reconciler["schedulerJob"] = "ctrldb-test-wipe-schedule"
	reconciler["runJob"] = "ctrldb-test-wipe"
	reconciler["serviceAccount"] = "ctrldb-test-wipe@example-project.iam.gserviceaccount.com"
	nestedMap(t, manifest, "spec", "testIsolation")["ciPrincipal"] = "principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/attribute.repository/example-org/ctrldb"
	return manifest
}
