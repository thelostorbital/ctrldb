// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

// storagePermissionCatalog mirrors the M1-04 step registry; a permission
// prover would emit exactly this list.
var storagePermissionCatalog = []struct {
	step        string
	permissions []string
}{
	{"k1-audit-bootstrap", []string{"storage.buckets.create", "storage.buckets.get", "storage.objects.create", "storage.objects.get"}},
	{"k1-retention-lock", []string{"storage.buckets.get", "storage.buckets.update"}},
	{"k2-control-bucket", []string{"storage.buckets.create", "storage.buckets.get", "storage.buckets.update"}},
	{"k3-bucket-iam", []string{"storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"}},
	{"k4-seed-control", []string{"storage.objects.create", "storage.objects.get"}},
	{"k5-lock-round-trip", []string{"storage.objects.create", "storage.objects.get", "storage.objects.update"}},
	{"t1-network", []string{"compute.networks.create", "compute.networks.get"}},
	{"t2-subnet", []string{"compute.subnetworks.create", "compute.subnetworks.get"}},
	{"t3-nat", []string{"compute.routers.create", "compute.routers.get", "compute.routers.update"}},
	{"t4-firewall", []string{"compute.firewalls.create", "compute.firewalls.get"}},
	{"t5-identities", []string{"iam.roles.create", "iam.roles.get", "iam.roles.update", "iam.serviceAccounts.create", "iam.serviceAccounts.get", "iam.serviceAccounts.setIamPolicy", "resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"}},
	{"t6-control-prefix", []string{"storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"}},
	{"t7-nightly-wipe", []string{"cloudscheduler.jobs.create", "cloudscheduler.jobs.get", "iam.serviceAccounts.actAs", "run.jobs.create", "run.jobs.get", "run.jobs.run"}},
	{"t8-isolation-gate", []string{"cloudscheduler.jobs.get", "compute.firewalls.get", "compute.networks.get", "compute.routers.get", "compute.subnetworks.get", "iam.roles.get", "iam.serviceAccounts.get", "iam.serviceAccounts.getIamPolicy", "resourcemanager.projects.getIamPolicy", "run.jobs.get", "storage.buckets.get", "storage.buckets.getIamPolicy"}},
}

func storageFixturePlan(t *testing.T) bootstrap.CompiledPlan {
	t.Helper()
	createdAt := storageTestNow.Add(-10 * time.Minute)
	configuration := validHarnessConfiguration(t)
	services := make([]observation.APIService, 0)
	for _, service := range bootstrap.RequiredAPIs() {
		services = append(services, observation.APIService{Name: service, State: observation.APIEnabled})
	}
	preflight, err := observation.NewHarnessPreflight(observation.Seed{
		Account: storageTestAccount, Project: storageTestProject, Region: storageTestRegion, Zone: "us-central1-a",
		GcloudVersion: observation.SupportedGcloudVersion, CompletenessPolicy: observation.GcloudCompletenessPolicy,
		ObservedAt: createdAt.Add(-time.Minute), ValidUntil: createdAt.Add(4 * time.Minute), Schemas: observation.RequiredSchemas(),
		Regions: []observation.Region{{Name: storageTestRegion, Availability: observation.AvailabilityUp, ProviderID: "projects/example-project/regions/us-central1"}},
		Zones:   []observation.Zone{{Name: "us-central1-a", Region: storageTestRegion, Availability: observation.AvailabilityUp, ProviderID: "projects/example-project/zones/us-central1-a"}},
		MachineTypes: []observation.MachineType{{Name: "e2-medium", Zone: "us-central1-a", GuestCPUs: 2, MemoryMiB: 4096,
			ProviderID: "projects/example-project/zones/us-central1-a/machineTypes/e2-medium"}},
		APIs: services, Exhaustive: true,
	})
	if err != nil {
		t.Fatalf("NewHarnessPreflight() error = %v", err)
	}
	request := bootstrap.CompileRequest{
		Configuration: configuration, Preflight: preflight, PlanID: "plan-0123456789abcdef",
		CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour), LocalPolicyHash: hexRepeat("a"), ApprovedPolicyHash: hexRepeat("a"),
		Pricing: bootstrap.PricingEvidence{MachineType: "e2-medium", Region: storageTestRegion, Zone: "us-central1-a", GuestCPUs: 2, MemoryMiB: 4096,
			DiskGiB: 100, Instances: 3, LifetimeSeconds: int64((8 * time.Hour) / time.Second), EstimatedRunMicros: 5_000_000, Currency: "USD",
			PriceTableDate: "2026-09-09", Schema: bootstrap.PricingSchemaV1, ObservedAt: createdAt.Add(-time.Minute), ValidUntil: createdAt.Add(4 * time.Minute)},
	}
	request.Pricing.Revision = revisionOf(t, request.Pricing)
	grants := make([]bootstrap.PermissionGrant, 0)
	for _, step := range storagePermissionCatalog {
		for _, permission := range step.permissions {
			grants = append(grants, bootstrap.PermissionGrant{StepID: step.step, Identity: domain.IdentityHuman, Permission: permission, Granted: true})
		}
	}
	request.Permissions = bootstrap.PermissionEvidence{Account: storageTestAccount, Project: storageTestProject, Schema: bootstrap.PermissionEvidenceSchemaV1,
		ObservedAt: createdAt.Add(-time.Minute), ValidUntil: createdAt.Add(4 * time.Minute), Grants: grants}
	request.Permissions.Revision = revisionOf(t, request.Permissions)
	plan, err := bootstrap.Compile(request)
	if err != nil {
		t.Fatalf("bootstrap.Compile() error = %v", err)
	}
	return plan
}

func revisionOf(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func hexRepeat(character string) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = character[0]
	}
	return string(result)
}
