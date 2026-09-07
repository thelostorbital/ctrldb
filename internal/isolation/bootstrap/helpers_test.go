// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

const (
	testAccount = "operator@example.invalid"
	testProject = "example-project"
	testRegion  = "us-central1"
	testZone    = "us-central1-a"
)

var testNow = time.Date(2026, 9, 7, 12, 1, 0, 0, time.UTC)

func validCompileRequest(t *testing.T) CompileRequest {
	t.Helper()

	return CompileRequest{
		Configuration:      validHarnessConfiguration(t),
		Preflight:          validPreflight(t, testProject, testRegion, testZone, nil, nil, nil),
		PlanID:             "plan-0123456789abcdef",
		CreatedAt:          testNow,
		ExpiresAt:          testNow.Add(31 * time.Minute),
		LocalPolicyHash:    repeatedHex("a"),
		ApprovedPolicyHash: repeatedHex("a"),
		Pricing: PricingEvidence{
			MachineType:        "e2-medium",
			GuestCPUs:          2,
			MemoryMiB:          4096,
			EstimatedRunMicros: 5_000_000,
			PriceTableDate:     "2026-09-07",
			Schema:             PricingSchemaV1,
			Revision:           repeatedHex("b"),
			ObservedAt:         testNow.Add(-time.Minute),
			ValidUntil:         testNow.Add(4 * time.Minute),
		},
	}
}

func validHarnessConfiguration(t *testing.T) config.HarnessConfiguration {
	t.Helper()

	manifest := fixtureManifest(t)
	metadata := nestedObject(t, manifest, "metadata")
	metadata["name"] = "disposable-test"
	metadata["class"] = "disposable"
	nestedObject(t, manifest, "spec")["testIsolation"] = map[string]any{
		"namePrefix":                config.TestResourcePrefix,
		"labels":                    map[string]any{"managed-by": "ctrldb", "environment": "disposable", "purpose": "test"},
		"operatorServiceAccount":    "ctrldb-test-operator@example-project.iam.gserviceaccount.com",
		"destructiveServiceAccount": "ctrldb-test-destructive@example-project.iam.gserviceaccount.com",
		"network": map[string]any{
			"vpc": "ctrldb-test-vpc", "subnet": "ctrldb-test-subnet", "cidr": "10.40.0.0/24", "nat": "ctrldb-test-nat",
		},
		"ciPrincipal": "principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/attribute.repository/example-org/ctrldb",
		"caps": map[string]any{
			"maxMachineType": "e2-medium", "maxDiskGiB": 100, "maxInstances": 3,
			"maxLifetime": "8h", "maxEstimatedUSDPerRun": 25,
		},
		"monitoringTests": "manual-only",
	}
	nestedObject(t, manifest, "spec", "host")["serviceAccount"] = "ctrldb-test-vm@example-project.iam.gserviceaccount.com"
	reconciler := nestedObject(t, manifest, "spec", "reconciler")
	reconciler["schedulerJob"] = "ctrldb-test-wipe-schedule"
	reconciler["runJob"] = "ctrldb-test-wipe"
	reconciler["serviceAccount"] = "ctrldb-test-wipe@example-project.iam.gserviceaccount.com"

	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal(manifest) unexpected error: %v", err)
	}
	document, err := config.DecodeManifest(encoded)
	if err != nil {
		t.Fatalf("config.DecodeManifest() unexpected error: %v", err)
	}
	configuration, err := config.HarnessConfigurationFromManifest(document)
	if err != nil {
		t.Fatalf("config.HarnessConfigurationFromManifest() unexpected error: %v", err)
	}
	return configuration
}

func fixtureManifest(t *testing.T) map[string]any {
	t.Helper()

	encoded := mustReadFile(t, "../../config/testdata/manifest-v1alpha1.yaml")
	document, err := config.DecodeManifestEnvelope(encoded)
	if err != nil {
		t.Fatalf("config.DecodeManifestEnvelope() unexpected error: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(document.JSON(), &manifest); err != nil {
		t.Fatalf("json.Unmarshal(manifest) unexpected error: %v", err)
	}
	return manifest
}

func nestedObject(t *testing.T, value map[string]any, path ...string) map[string]any {
	t.Helper()

	current := value
	for _, token := range path {
		next, ok := current[token].(map[string]any)
		if !ok {
			t.Fatalf("fixture path %q is not an object", path)
		}
		current = next
	}
	return current
}

func validPreflight(
	t *testing.T,
	project, region, zone string,
	resources []observation.Resource,
	subnets []observation.SubnetRange,
	firewalls []observation.FirewallRule,
) observation.HarnessPreflight {
	t.Helper()

	seed := validPreflightSeed(project, region, zone, resources, subnets, firewalls)
	result, err := observation.NewHarnessPreflight(seed)
	if err != nil {
		t.Fatalf("observation.NewHarnessPreflight() unexpected error: %v", err)
	}
	return result
}

func validPreflightSeed(
	project, region, zone string,
	resources []observation.Resource,
	subnets []observation.SubnetRange,
	firewalls []observation.FirewallRule,
) observation.Seed {
	services := make([]observation.APIService, len(requiredAPIs))
	for index, service := range requiredAPIs {
		services[index] = observation.APIService{Name: service, State: observation.APIEnabled}
	}
	return observation.Seed{
		Account: testAccount, Project: project, Region: region, Zone: zone,
		GcloudVersion: observation.SupportedGcloudVersion, CompletenessPolicy: observation.GcloudCompletenessPolicy,
		ObservedAt: testNow.Add(-time.Minute), ValidUntil: testNow.Add(4 * time.Minute),
		Schemas: observation.RequiredSchemas(),
		Regions: []observation.Region{{Name: region, Availability: observation.AvailabilityUp, ProviderID: provider(project, "regions", region)}},
		Zones:   []observation.Zone{{Name: zone, Region: region, Availability: observation.AvailabilityUp, ProviderID: provider(project, "zones", zone)}},
		MachineTypes: []observation.MachineType{{
			Name: "e2-medium", Zone: zone, GuestCPUs: 2, MemoryMiB: 4096,
			ProviderID: provider(project, "zones", zone, "machineTypes", "e2-medium"),
		}},
		SubnetRanges: subnets, Resources: resources, APIs: services, Firewalls: firewalls, Exhaustive: true,
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()

	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) unexpected error: %v", path, err)
	}
	return encoded
}

func repeatedHex(character string) string {
	return strings.Repeat(character, 64)
}

func mustCompile(t *testing.T, request CompileRequest) CompiledPlan {
	t.Helper()

	result, err := Compile(request)
	if err != nil {
		t.Fatalf("Compile() unexpected error: %v", err)
	}
	return result
}

func mustCanonical(t *testing.T, plan CompiledPlan) []byte {
	t.Helper()

	encoded, err := plan.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() unexpected error: %v", err)
	}
	return encoded
}
