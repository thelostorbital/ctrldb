// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

const (
	testAccount     = "operator@example.invalid"
	testProject     = "example-project"
	testRegion      = "us-central1"
	testZone        = "us-central1-a"
	testPlanID      = "plan-0123456789abcdef"
	testOperationID = "op-00000000000000aa"
	testEnvelope    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

var testNow = time.Date(2026, 9, 7, 12, 1, 0, 0, time.UTC)

// stepPermissions mirrors the frozen M1-04 registry so the fixture can
// present exact fresh permission evidence through the public compiler API.
var stepPermissions = []struct {
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

var (
	fixtureOnce    sync.Once
	fixtureEncoded []byte
	fixtureErr     error
)

// fixturePlan compiles the fixture once and hands every test its own parsed
// copy, so tests also exercise the saved-plan parser on every run.
func fixturePlan(t *testing.T) bootstrap.CompiledPlan {
	t.Helper()
	fixtureOnce.Do(func() {
		plan, err := bootstrap.Compile(fixtureCompileRequest(t))
		if err != nil {
			fixtureErr = err
			return
		}
		fixtureEncoded, fixtureErr = plan.CanonicalJSON()
	})
	if fixtureErr != nil {
		t.Fatalf("fixture plan: %v", fixtureErr)
	}
	plan, err := bootstrap.ParseCompiledPlan(fixtureEncoded)
	if err != nil {
		t.Fatalf("bootstrap.ParseCompiledPlan() unexpected error: %v", err)
	}
	return plan
}

func fixtureCompileRequest(t *testing.T) bootstrap.CompileRequest {
	t.Helper()
	request := bootstrap.CompileRequest{
		Configuration: fixtureConfiguration(t), Preflight: fixturePreflight(t),
		PlanID: testPlanID, CreatedAt: testNow, ExpiresAt: testNow.Add(time.Hour),
		LocalPolicyHash: strings.Repeat("a", 64), ApprovedPolicyHash: strings.Repeat("a", 64),
		Pricing: bootstrap.PricingEvidence{
			MachineType: "e2-medium", Region: testRegion, Zone: testZone, GuestCPUs: 2, MemoryMiB: 4096, DiskGiB: 100,
			Instances: 3, LifetimeSeconds: int64((8 * time.Hour) / time.Second), EstimatedRunMicros: 5_000_000,
			Currency: "USD", PriceTableDate: "2026-09-07", Schema: bootstrap.PricingSchemaV1,
			ObservedAt: testNow.Add(-time.Minute), ValidUntil: testNow.Add(4 * time.Minute),
		},
	}
	request.Pricing.Revision = revisionOf(t, request.Pricing)
	request.Permissions = fixturePermissionEvidence(t, testNow.Add(-time.Minute), testNow.Add(4*time.Minute), nil)
	return request
}

// fixturePermissionEvidence returns exact fresh evidence for every step, or
// for only the named step when stepFilter is set.
func fixturePermissionEvidence(t *testing.T, observedAt, validUntil time.Time, stepFilter *string) bootstrap.PermissionEvidence {
	t.Helper()
	evidence := bootstrap.PermissionEvidence{
		Account: testAccount, Project: testProject, Schema: bootstrap.PermissionEvidenceSchemaV1,
		ObservedAt: observedAt, ValidUntil: validUntil, Grants: []bootstrap.PermissionGrant{},
	}
	for _, step := range stepPermissions {
		if stepFilter != nil && *stepFilter != step.step {
			continue
		}
		for _, permission := range step.permissions {
			evidence.Grants = append(evidence.Grants, bootstrap.PermissionGrant{
				StepID: step.step, Identity: domain.IdentityHuman, Permission: permission, Granted: true,
			})
		}
	}
	evidence.Revision = revisionOf(t, evidence)
	return evidence
}

func revisionOf(t *testing.T, value any) string {
	t.Helper()
	switch typed := value.(type) {
	case bootstrap.PricingEvidence:
		typed.Revision = ""
		value = typed
	case bootstrap.PermissionEvidence:
		typed.Revision = ""
		value = typed
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %v", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func fixtureConfiguration(t *testing.T) config.HarnessConfiguration {
	t.Helper()
	encoded, err := os.ReadFile("../config/testdata/manifest-v1alpha1.yaml")
	if err != nil {
		t.Fatalf("os.ReadFile() unexpected error: %v", err)
	}
	document, err := config.DecodeManifestEnvelope(encoded)
	if err != nil {
		t.Fatalf("config.DecodeManifestEnvelope() unexpected error: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(document.JSON(), &manifest); err != nil {
		t.Fatalf("json.Unmarshal(manifest) unexpected error: %v", err)
	}
	metadata := manifest["metadata"].(map[string]any)
	metadata["name"] = "disposable-test"
	metadata["class"] = "disposable"
	spec := manifest["spec"].(map[string]any)
	spec["testIsolation"] = map[string]any{
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
	spec["host"].(map[string]any)["serviceAccount"] = "ctrldb-test-vm@example-project.iam.gserviceaccount.com"
	reconciler := spec["reconciler"].(map[string]any)
	reconciler["schedulerJob"] = "ctrldb-test-wipe-schedule"
	reconciler["runJob"] = "ctrldb-test-wipe"
	reconciler["serviceAccount"] = "ctrldb-test-wipe@example-project.iam.gserviceaccount.com"
	rewritten, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal(manifest) unexpected error: %v", err)
	}
	decoded, err := config.DecodeManifest(rewritten)
	if err != nil {
		t.Fatalf("config.DecodeManifest() unexpected error: %v", err)
	}
	configuration, err := config.HarnessConfigurationFromManifest(decoded)
	if err != nil {
		t.Fatalf("config.HarnessConfigurationFromManifest() unexpected error: %v", err)
	}
	return configuration
}

func fixturePreflight(t *testing.T) observation.HarnessPreflight {
	t.Helper()
	required := bootstrap.RequiredAPIs()
	services := make([]observation.APIService, len(required))
	for index, service := range required {
		services[index] = observation.APIService{Name: service, State: observation.APIEnabled}
	}
	provider := func(parts ...string) string {
		return strings.Join(append([]string{"projects", testProject}, parts...), "/")
	}
	seed := observation.Seed{
		Account: testAccount, Project: testProject, Region: testRegion, Zone: testZone,
		GcloudVersion: observation.SupportedGcloudVersion, CompletenessPolicy: observation.GcloudCompletenessPolicy,
		ObservedAt: testNow.Add(-time.Minute), ValidUntil: testNow.Add(4 * time.Minute),
		Schemas: observation.RequiredSchemas(),
		Regions: []observation.Region{{Name: testRegion, Availability: observation.AvailabilityUp, ProviderID: provider("regions", testRegion)}},
		Zones:   []observation.Zone{{Name: testZone, Region: testRegion, Availability: observation.AvailabilityUp, ProviderID: provider("zones", testZone)}},
		MachineTypes: []observation.MachineType{{
			Name: "e2-medium", Zone: testZone, GuestCPUs: 2, MemoryMiB: 4096,
			ProviderID: provider("zones", testZone, "machineTypes", "e2-medium"),
		}},
		APIs: services, Exhaustive: true,
	}
	result, err := observation.NewHarnessPreflight(seed)
	if err != nil {
		t.Fatalf("observation.NewHarnessPreflight() unexpected error: %v", err)
	}
	return result
}

func fixtureApproval(plan bootstrap.CompiledPlan) ApprovalProof {
	reviewed := plan.Plan()
	return ApprovalProof{
		PlanID: reviewed.PlanID, ApprovalToken: reviewed.PlanID, PlanDocumentSHA256: plan.DocumentHash(),
		PlanV1Hash: reviewed.PlanHash, Principal: reviewed.Principal, ApprovalClass: domain.ApprovalSecuritySensitive,
		ApprovedAt: testNow.Add(time.Minute), ValidUntil: testNow.Add(time.Hour),
	}
}
