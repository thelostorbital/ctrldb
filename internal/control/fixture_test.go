// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

const (
	fixtureAccount     = "operator@example.invalid"
	fixtureProject     = "example-project"
	fixtureRegion      = "us-central1"
	fixtureZone        = "us-central1-a"
	fixtureOperationID = "op-0123456789abcdef"
	fixturePlanID      = "plan-0123456789abcdef"
)

var fixtureNow = time.Date(2026, 9, 9, 12, 1, 0, 0, time.UTC)

// fixturePermissions mirrors the M1-04 step registry exactly; a provider
// permission prover would emit this list.
var fixturePermissions = []struct {
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

func fixturePlan(t *testing.T) bootstrap.CompiledPlan {
	t.Helper()
	request := bootstrap.CompileRequest{
		Configuration: fixtureConfiguration(t), Preflight: fixturePreflight(t), PlanID: fixturePlanID,
		CreatedAt: fixtureNow, ExpiresAt: fixtureNow.Add(time.Hour),
		LocalPolicyHash: repeatHex("a"), ApprovedPolicyHash: repeatHex("a"),
		Pricing: bootstrap.PricingEvidence{
			MachineType: "e2-medium", Region: fixtureRegion, Zone: fixtureZone, GuestCPUs: 2, MemoryMiB: 4096,
			DiskGiB: 100, Instances: 3, LifetimeSeconds: int64((8 * time.Hour) / time.Second), EstimatedRunMicros: 5_000_000,
			Currency: "USD", PriceTableDate: "2026-09-09", Schema: bootstrap.PricingSchemaV1,
			ObservedAt: fixtureNow.Add(-time.Minute), ValidUntil: fixtureNow.Add(4 * time.Minute),
		},
	}
	request.Pricing.Revision = fixtureRevision(t, request.Pricing)
	grants := make([]bootstrap.PermissionGrant, 0)
	for _, step := range fixturePermissions {
		for _, permission := range step.permissions {
			grants = append(grants, bootstrap.PermissionGrant{StepID: step.step, Identity: domain.IdentityHuman, Permission: permission, Granted: true})
		}
	}
	request.Permissions = bootstrap.PermissionEvidence{
		Account: fixtureAccount, Project: fixtureProject, Schema: bootstrap.PermissionEvidenceSchemaV1,
		ObservedAt: fixtureNow.Add(-time.Minute), ValidUntil: fixtureNow.Add(4 * time.Minute), Grants: grants,
	}
	request.Permissions.Revision = fixtureRevision(t, request.Permissions)
	plan, err := bootstrap.Compile(request)
	if err != nil {
		t.Fatalf("bootstrap.Compile() unexpected error: %v", err)
	}
	return plan
}

func fixtureRevision(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(revision input) unexpected error: %v", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func fixtureConfiguration(t *testing.T) config.HarnessConfiguration {
	t.Helper()
	encoded, err := os.ReadFile("../config/testdata/manifest-v1alpha1.yaml")
	if err != nil {
		t.Fatalf("read manifest fixture: %v", err)
	}
	envelope, err := config.DecodeManifestEnvelope(encoded)
	if err != nil {
		t.Fatalf("config.DecodeManifestEnvelope() unexpected error: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(envelope.JSON(), &manifest); err != nil {
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
		"network":                   map[string]any{"vpc": "ctrldb-test-vpc", "subnet": "ctrldb-test-subnet", "cidr": "10.40.0.0/24", "nat": "ctrldb-test-nat"},
		"ciPrincipal":               "principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/attribute.repository/example-org/ctrldb",
		"caps":                      map[string]any{"maxMachineType": "e2-medium", "maxDiskGiB": 100, "maxInstances": 3, "maxLifetime": "8h", "maxEstimatedUSDPerRun": 25},
		"monitoringTests":           "manual-only",
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
	document, err := config.DecodeManifest(rewritten)
	if err != nil {
		t.Fatalf("config.DecodeManifest() unexpected error: %v", err)
	}
	configuration, err := config.HarnessConfigurationFromManifest(document)
	if err != nil {
		t.Fatalf("config.HarnessConfigurationFromManifest() unexpected error: %v", err)
	}
	return configuration
}

func fixturePreflight(t *testing.T) observation.HarnessPreflight {
	t.Helper()
	services := make([]observation.APIService, 0)
	for _, service := range bootstrap.RequiredAPIs() {
		services = append(services, observation.APIService{Name: service, State: observation.APIEnabled})
	}
	seed := observation.Seed{
		Account: fixtureAccount, Project: fixtureProject, Region: fixtureRegion, Zone: fixtureZone,
		GcloudVersion: observation.SupportedGcloudVersion, CompletenessPolicy: observation.GcloudCompletenessPolicy,
		ObservedAt: fixtureNow.Add(-time.Minute), ValidUntil: fixtureNow.Add(4 * time.Minute),
		Schemas: observation.RequiredSchemas(),
		Regions: []observation.Region{{Name: fixtureRegion, Availability: observation.AvailabilityUp, ProviderID: "projects/" + fixtureProject + "/regions/" + fixtureRegion}},
		Zones:   []observation.Zone{{Name: fixtureZone, Region: fixtureRegion, Availability: observation.AvailabilityUp, ProviderID: "projects/" + fixtureProject + "/zones/" + fixtureZone}},
		MachineTypes: []observation.MachineType{{
			Name: "e2-medium", Zone: fixtureZone, GuestCPUs: 2, MemoryMiB: 4096,
			ProviderID: "projects/" + fixtureProject + "/zones/" + fixtureZone + "/machineTypes/e2-medium",
		}},
		APIs: services, Exhaustive: true,
	}
	preflight, err := observation.NewHarnessPreflight(seed)
	if err != nil {
		t.Fatalf("observation.NewHarnessPreflight() unexpected error: %v", err)
	}
	return preflight
}

func fixtureJournalEntry(plan bootstrap.CompiledPlan, recordedAt time.Time) domain.JournalEntry {
	return domain.JournalEntry{
		Schema: domain.JournalSchemaV1, OperationID: fixtureOperationID, PlanID: plan.Plan().PlanID,
		ContractHash: plan.ExecutionContract().Digest(), Sequence: 1, Kind: domain.JournalEntryTransition,
		RecordedAt: recordedAt, OperationState: domain.OperationDiscover,
	}
}

func fixtureSeed(t *testing.T) EnvelopeSeed {
	t.Helper()
	plan := fixturePlan(t)
	approval, err := NewApprovalProof(plan, fixtureAccount, fixtureNow.Add(time.Minute), fixtureNow.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("NewApprovalProof() unexpected error: %v", err)
	}
	return EnvelopeSeed{
		Plan: plan, OperationID: fixtureOperationID, Approval: approval,
		FirstJournalEntry: fixtureJournalEntry(plan, fixtureNow.Add(2*time.Minute)), SealedAt: fixtureNow.Add(2 * time.Minute),
	}
}

func fixtureEnvelope(t *testing.T) BootstrapEnvelopeV1 {
	t.Helper()
	envelope, err := SealBootstrapEnvelope(fixtureSeed(t))
	if err != nil {
		t.Fatalf("SealBootstrapEnvelope() unexpected error: %v", err)
	}
	return envelope
}

func fixtureStateDirectory(t *testing.T) StateDirectory {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp directory: %v", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("chmod state directory: %v", err)
	}
	directory, err := NewStateDirectory(path)
	if err != nil {
		t.Fatalf("NewStateDirectory() unexpected error: %v", err)
	}
	return directory
}

func repeatHex(character string) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = character[0]
	}
	return string(result)
}
