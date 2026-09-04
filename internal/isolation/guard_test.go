// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation_test

import (
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
)

func TestValidateRunRequestAcceptsExactCaps(t *testing.T) {
	t.Parallel()

	limits := defaultLimits()
	request := isolation.RunRequest{
		Machine:             limits.MaxMachine,
		DiskGiB:             limits.MaxDiskGiB,
		Instances:           limits.MaxInstances,
		Lifetime:            limits.MaxLifetime,
		EstimatedCostMicros: limits.MaxEstimatedCostMicros,
	}
	if err := isolation.ValidateRunRequest(limits, request); err != nil {
		t.Fatalf("ValidateRunRequest() unexpected error: %v", err)
	}
}

func TestValidateRunRequestRejectsEveryExceededCap(t *testing.T) {
	t.Parallel()

	limits := defaultLimits()
	base := isolation.RunRequest{
		Machine:             isolation.MachineShape{VCPUs: 2, MemoryMB: 8 * 1024},
		DiskGiB:             100,
		Instances:           1,
		Lifetime:            2 * time.Hour,
		EstimatedCostMicros: 2_000_000,
	}
	tests := []struct {
		name   string
		mutate func(*isolation.RunRequest)
	}{
		{name: "vCPUs", mutate: func(request *isolation.RunRequest) { request.Machine.VCPUs = 8 }},
		{name: "memory", mutate: func(request *isolation.RunRequest) { request.Machine.MemoryMB = 32 * 1024 }},
		{name: "disk", mutate: func(request *isolation.RunRequest) { request.DiskGiB = 251 }},
		{name: "instances", mutate: func(request *isolation.RunRequest) { request.Instances = 3 }},
		{name: "lifetime", mutate: func(request *isolation.RunRequest) { request.Lifetime = 6*time.Hour + time.Second }},
		{name: "cost", mutate: func(request *isolation.RunRequest) { request.EstimatedCostMicros = 5_000_001 }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := base
			test.mutate(&request)
			if err := isolation.ValidateRunRequest(limits, request); !errors.Is(err, isolation.ErrCapacityExceeded) {
				t.Fatalf("ValidateRunRequest() error = %v; want ErrCapacityExceeded", err)
			}
		})
	}
}

func TestValidateRunRequestRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	validLimits := defaultLimits()
	validRequest := isolation.RunRequest{
		Machine:   isolation.MachineShape{VCPUs: 2, MemoryMB: 8 * 1024},
		Instances: 1,
		Lifetime:  time.Hour,
	}
	tests := []struct {
		name    string
		limits  isolation.RunLimits
		request isolation.RunRequest
	}{
		{name: "empty limits", limits: isolation.RunLimits{}, request: validRequest},
		{name: "zero request vCPUs", limits: validLimits, request: func() isolation.RunRequest {
			request := validRequest
			request.Machine.VCPUs = 0
			return request
		}()},
		{name: "zero request memory", limits: validLimits, request: func() isolation.RunRequest {
			request := validRequest
			request.Machine.MemoryMB = 0
			return request
		}()},
		{name: "negative disk", limits: validLimits, request: func() isolation.RunRequest {
			request := validRequest
			request.DiskGiB = -1
			return request
		}()},
		{name: "negative instances", limits: validLimits, request: func() isolation.RunRequest {
			request := validRequest
			request.Instances = -1
			return request
		}()},
		{name: "zero instances", limits: validLimits, request: func() isolation.RunRequest {
			request := validRequest
			request.Instances = 0
			return request
		}()},
		{name: "zero lifetime", limits: validLimits, request: func() isolation.RunRequest {
			request := validRequest
			request.Lifetime = 0
			return request
		}()},
		{name: "negative cost", limits: validLimits, request: func() isolation.RunRequest {
			request := validRequest
			request.EstimatedCostMicros = -1
			return request
		}()},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := isolation.ValidateRunRequest(test.limits, test.request); !errors.Is(err, isolation.ErrInvalidGuardInput) {
				t.Fatalf("ValidateRunRequest() error = %v; want ErrInvalidGuardInput", err)
			}
		})
	}
}

func TestValidateCleanupTargetsRequiresPrefixAndAllLabels(t *testing.T) {
	t.Parallel()

	valid := testTarget("ctrldb-test-run1-vm", "run1")
	if err := isolation.ValidateCleanupTargets(validCleanupPolicy(), []isolation.MutationTarget{valid}); err != nil {
		t.Fatalf("ValidateCleanupTargets() unexpected error: %v", err)
	}

	tests := []struct {
		name     string
		resource isolation.MutationTarget
	}{
		{name: "production prefix", resource: targetWithName(valid, "ctrldb-production-vm")},
		{name: "missing labels", resource: func() isolation.MutationTarget { value := valid; value.Labels = map[string]string{}; return value }()},
		{name: "production label", resource: func() isolation.MutationTarget {
			value := valid
			value.Labels = map[string]string{
				config.LabelManagedBy: config.LabelManagedByValue, config.LabelEnvironment: "production", config.LabelPurpose: config.TestResourcePurposeLabel,
			}
			return value
		}()},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := isolation.ValidateCleanupTargets(validCleanupPolicy(), []isolation.MutationTarget{test.resource})
			if !errors.Is(err, isolation.ErrUnsafeTarget) {
				t.Fatalf("ValidateCleanupTargets() error = %v; want ErrUnsafeTarget", err)
			}
		})
	}
	if err := isolation.ValidateCleanupTargets(isolation.CleanupPolicy{}, []isolation.MutationTarget{valid}); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateCleanupTargets(missing project policy) error = %v; want ErrInvalidGuardInput", err)
	}
	crossProject := valid
	moveResourceProject(&crossProject.Identity, "another-test-project")
	if err := isolation.ValidateCleanupTargets(validCleanupPolicy(), []isolation.MutationTarget{crossProject}); !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("ValidateCleanupTargets(cross-project target) error = %v; want ErrUnsafeTarget", err)
	}
}

func TestTESTISO02RunScopedMutationSelectorIsStrictAndDetached(t *testing.T) {
	t.Parallel()

	resources := []isolation.MutationTarget{
		testTarget("ctrldb-test-run-42-z", "run-42"),
		testTarget("ctrldb-test-run-42-a", "run-42"),
	}
	selected, err := isolation.SelectRunMutationTargets("run-42", resources)
	if err != nil {
		t.Fatalf("SelectRunMutationTargets() unexpected error: %v", err)
	}
	if got, want := []string{selected[0].Identity.Name, selected[1].Identity.Name}, []string{"ctrldb-test-run-42-a", "ctrldb-test-run-42-z"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SelectRunMutationTargets() names = %v; want %v", got, want)
	}
	selected[0].Labels[config.LabelPurpose] = "changed"
	if resources[1].Labels[config.LabelPurpose] != config.TestResourcePurposeLabel {
		t.Fatal("SelectRunMutationTargets() result aliases caller labels")
	}

	for _, invalid := range []string{"", "Run-42", "run--42", "-run", "run-", "run_42", strings.Repeat("a", 33)} {
		if _, err := isolation.SelectRunMutationTargets(invalid, resources); !errors.Is(err, isolation.ErrInvalidRunID) {
			t.Errorf("SelectRunMutationTargets(invalid run ID) error = %v; want ErrInvalidRunID", err)
		}
	}
	if _, err := isolation.SelectRunMutationTargets("run-4", resources); !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("SelectRunMutationTargets(prefix collision) error = %v; want ErrUnsafeTarget", err)
	}
	if _, err := isolation.SelectRunMutationTargets("run-42", append(resources, resources[0])); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("SelectRunMutationTargets(duplicate) error = %v; want ErrInvalidGuardInput", err)
	}
	crossRun := testTarget("ctrldb-test-run-42-vm", "run-42")
	if _, err := isolation.SelectRunMutationTargets("run", []isolation.MutationTarget{crossRun}); !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("SelectRunMutationTargets(cross-run prefix) error = %v; want ErrUnsafeTarget", err)
	}
}

func TestRunMutationTargetsBindCompleteCrossProjectIdentity(t *testing.T) {
	t.Parallel()

	first := testTarget("ctrldb-test-run1-vm", "run1")
	second := testTarget("ctrldb-test-run1-vm", "run1")
	second.Identity.Project = "another-test-project"
	second.Identity.CanonicalKey = mustCanonicalTargetKey(second.Identity)
	selected, err := isolation.SelectRunMutationTargets("run1", []isolation.MutationTarget{second, first})
	if err != nil {
		t.Fatalf("SelectRunMutationTargets(cross-project names) unexpected error: %v", err)
	}
	if selected[0].Identity.CanonicalKey == selected[1].Identity.CanonicalKey {
		t.Fatal("cross-project targets collapsed to one identity")
	}

	tests := []struct {
		name   string
		mutate func(*isolation.MutationTarget)
	}{
		{name: "missing project", mutate: func(target *isolation.MutationTarget) { target.Identity.Project = "" }},
		{name: "ambient location", mutate: func(target *isolation.MutationTarget) { target.Identity.Location = "" }},
		{name: "scope mismatch", mutate: func(target *isolation.MutationTarget) { target.Identity.Scope = isolation.ResourceScopeGlobal }},
		{name: "malformed region", mutate: func(target *isolation.MutationTarget) {
			target.Identity.Scope = isolation.ResourceScopeRegion
			target.Identity.Location = "asia-south"
		}},
		{name: "malformed zone", mutate: func(target *isolation.MutationTarget) { target.Identity.Location = "asia-south1" }},
		{name: "swapped canonical key", mutate: func(target *isolation.MutationTarget) { target.Identity.CanonicalKey = second.Identity.CanonicalKey }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			target := first
			test.mutate(&target)
			if _, err := isolation.SelectRunMutationTargets("run1", []isolation.MutationTarget{target}); !errors.Is(err, isolation.ErrInvalidGuardInput) {
				t.Fatalf("SelectRunMutationTargets() error = %v; want ErrInvalidGuardInput", err)
			}
		})
	}
}

func TestResourceIdentityAcceptsDiscoveredMultiDigitRegionsAndKnownComputeScopes(t *testing.T) {
	t.Parallel()

	multiDigitZone := testResourceIdentity("ctrldb-test-run1-vm", isolation.ComputeInstanceKind, isolation.ResourceScopeZone, "europe-west10-a")
	if _, err := isolation.SelectRunMutationTargets("run1", []isolation.MutationTarget{testTargetWithIdentity(multiDigitZone, "run1")}); err != nil {
		t.Fatalf("SelectRunMutationTargets(multi-digit zone) unexpected error: %v", err)
	}
	regionalDisk := testResourceIdentity("ctrldb-test-run1-disk", isolation.ComputeDiskKind, isolation.ResourceScopeRegion, "europe-west10")
	if _, err := isolation.SelectRunMutationTargets("run1", []isolation.MutationTarget{testTargetWithIdentity(regionalDisk, "run1")}); err != nil {
		t.Fatalf("SelectRunMutationTargets(regional disk) unexpected error: %v", err)
	}

	invalid := []isolation.ResourceIdentity{
		{Project: "example-test-project", Service: isolation.ComputeServiceName, Kind: isolation.ComputeInstanceKind, Scope: isolation.ResourceScopeGlobal, Location: "global", Name: "ctrldb-test-run1-vm"},
		{Project: "example-test-project", Service: isolation.ComputeServiceName, Kind: isolation.ComputeInstanceKind, Scope: isolation.ResourceScopeRegion, Location: "europe-west10", Name: "ctrldb-test-run1-vm"},
		{Project: "example-test-project", Service: isolation.ComputeServiceName, Kind: isolation.ComputeDiskKind, Scope: isolation.ResourceScopeGlobal, Location: "global", Name: "ctrldb-test-run1-disk"},
	}
	for _, identity := range invalid {
		if _, err := isolation.CanonicalTargetKey(identity); !errors.Is(err, isolation.ErrInvalidGuardInput) {
			t.Errorf("CanonicalTargetKey(impossible Compute scope) error = %v; want ErrInvalidGuardInput", err)
		}
	}
}

func TestComputeResourceIdentityEnforcesProviderNameGrammar(t *testing.T) {
	t.Parallel()

	type computeIdentityShape struct {
		kind     isolation.ResourceKind
		scope    isolation.ResourceScope
		location string
	}
	shapes := []computeIdentityShape{
		{kind: isolation.ComputeInstanceKind, scope: isolation.ResourceScopeZone, location: "asia-south1-a"},
		{kind: isolation.ComputeDiskKind, scope: isolation.ResourceScopeRegion, location: "asia-south1"},
		{kind: isolation.ComputeFirewallKind, scope: isolation.ResourceScopeGlobal, location: "global"},
		{kind: isolation.ComputeNetworkKind, scope: isolation.ResourceScopeGlobal, location: "global"},
		{kind: "snapshots", scope: isolation.ResourceScopeGlobal, location: "global"},
	}
	validNames := []string{"a", "a-" + strings.Repeat("b", 60) + "9"}
	for _, shape := range shapes {
		for _, name := range validNames {
			identity := isolation.ResourceIdentity{
				Project: "example-test-project", Service: isolation.ComputeServiceName,
				Kind: shape.kind, Scope: shape.scope, Location: shape.location, Name: name,
			}
			if _, err := isolation.CanonicalTargetKey(identity); err != nil {
				t.Errorf("CanonicalTargetKey(%s, %d-character name) unexpected error: %v", shape.kind, len(name), err)
			}
		}
	}

	invalidNames := []string{
		"1-ctrldb-test-run1-vm",
		"ctrldb-test-run1_vm",
		"CtrlDB-test-run1-vm",
		"-ctrldb-test-run1-vm",
		"ctrldb-test-run1-vm-",
		strings.Repeat("a", 64),
	}
	for _, shape := range shapes {
		for _, name := range invalidNames {
			identity := isolation.ResourceIdentity{
				Project: "example-test-project", Service: isolation.ComputeServiceName,
				Kind: shape.kind, Scope: shape.scope, Location: shape.location, Name: name,
			}
			if _, err := isolation.CanonicalTargetKey(identity); !errors.Is(err, isolation.ErrInvalidGuardInput) {
				t.Errorf("CanonicalTargetKey(%s, invalid name %q) error = %v; want ErrInvalidGuardInput", shape.kind, name, err)
			}
		}
	}

	nonCompute := isolation.ResourceIdentity{
		Project: "example-test-project", Service: "example.googleapis.com", Kind: "widgets",
		Scope: isolation.ResourceScopeGlobal, Location: "global", Name: "provider_name.with-dot",
	}
	if _, err := isolation.CanonicalTargetKey(nonCompute); err != nil {
		t.Fatalf("CanonicalTargetKey(non-Compute provider grammar) unexpected error: %v", err)
	}
}

func TestMaxLengthRunIDProducesValidComputeNamesAndTags(t *testing.T) {
	t.Parallel()

	runID := strings.Repeat("a", 32)
	for _, purpose := range []isolation.FirewallPurpose{isolation.FirewallPurposeIAPSSH, isolation.FirewallPurposeInternalMongo} {
		name, err := isolation.RunFirewallRuleName(runID, purpose)
		if err != nil {
			t.Fatalf("RunFirewallRuleName(%q) unexpected error: %v", purpose, err)
		}
		if len(name) > 63 {
			t.Fatalf("RunFirewallRuleName(%q) length = %d; want at most 63", purpose, len(name))
		}
		identity := isolation.ResourceIdentity{
			Project: "example-test-project", Service: isolation.ComputeServiceName,
			Kind: isolation.ComputeFirewallKind, Scope: isolation.ResourceScopeGlobal, Location: "global", Name: name,
		}
		if _, err := isolation.CanonicalTargetKey(identity); err != nil {
			t.Fatalf("CanonicalTargetKey(generated firewall name) unexpected error: %v", err)
		}
	}

	tag, err := isolation.RunNodeTag(validLifetimeFingerprint(runID))
	if err != nil {
		t.Fatalf("RunNodeTag() unexpected error: %v", err)
	}
	if len(tag) > 63 {
		t.Fatalf("RunNodeTag() length = %d; want at most 63", len(tag))
	}
	if err := isolation.ValidateFirewallTags([]string{tag}, []string{tag}); err != nil {
		t.Fatalf("ValidateFirewallTags(generated tag) unexpected error: %v", err)
	}
}

func TestSelectExpiredTargetsFailsClosedAndReturnsDetachedSortedResults(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	candidates := []isolation.ExpirableTarget{
		{Target: testTarget("ctrldb-test-run1-z", "run1"), CreatedAt: now.Add(-7 * time.Hour)},
		{Target: testTarget("ctrldb-test-run1-young", "run1"), CreatedAt: now.Add(-time.Hour)},
		{Target: testTarget("ctrldb-test-run1-a", "run1"), CreatedAt: now.Add(-6 * time.Hour)},
	}
	selected, err := isolation.SelectExpiredTargets(validCleanupPolicy(), candidates, now, 6*time.Hour)
	if err != nil {
		t.Fatalf("SelectExpiredTargets() unexpected error: %v", err)
	}
	wantNames := []string{"ctrldb-test-run1-a", "ctrldb-test-run1-z"}
	gotNames := []string{selected[0].Target.Identity.Name, selected[1].Target.Identity.Name}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("SelectExpiredTargets() names = %v; want %v", gotNames, wantNames)
	}

	selected[0].Target.Labels[config.LabelPurpose] = "changed"
	if got := candidates[2].Target.Labels[config.LabelPurpose]; got != config.TestResourcePurposeLabel {
		t.Fatalf("SelectExpiredTargets() result aliases caller labels: got %q", got)
	}

	unsafeYoung := []isolation.ExpirableTarget{{
		Target: func() isolation.MutationTarget {
			value := testTarget("ctrldb-test-run2-young", "run2")
			value.Labels = nil
			return value
		}(),
		CreatedAt: now.Add(-time.Minute),
	}}
	if _, err := isolation.SelectExpiredTargets(validCleanupPolicy(), unsafeYoung, now, 6*time.Hour); !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("SelectExpiredTargets(unsafe young target) error = %v; want ErrUnsafeTarget", err)
	}
	mixedProjects := append([]isolation.ExpirableTarget(nil), candidates...)
	moveResourceProject(&mixedProjects[1].Target.Identity, "another-test-project")
	if _, err := isolation.SelectExpiredTargets(validCleanupPolicy(), mixedProjects, now, 6*time.Hour); !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("SelectExpiredTargets(cross-project young target) error = %v; want ErrUnsafeTarget", err)
	}
}

func TestSelectExpiredTargetsRejectsInvalidTimeBoundaries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	valid := []isolation.ExpirableTarget{{Target: testTarget("ctrldb-test-run1-vm", "run1"), CreatedAt: now.Add(-time.Hour)}}
	if _, err := isolation.SelectExpiredTargets(validCleanupPolicy(), valid, time.Time{}, time.Hour); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("SelectExpiredTargets(zero now) error = %v; want ErrInvalidGuardInput", err)
	}
	if _, err := isolation.SelectExpiredTargets(validCleanupPolicy(), valid, now, 0); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("SelectExpiredTargets(zero lifetime) error = %v; want ErrInvalidGuardInput", err)
	}
	future := []isolation.ExpirableTarget{{Target: testTarget("ctrldb-test-run1-vm", "run1"), CreatedAt: now.Add(time.Second)}}
	if _, err := isolation.SelectExpiredTargets(validCleanupPolicy(), future, now, time.Hour); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("SelectExpiredTargets(future target) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestValidateFirewallTagsAllowsOnlyReservedTestTags(t *testing.T) {
	t.Parallel()

	if err := isolation.ValidateFirewallTags(nil, []string{"ctrldb-test-node"}); err != nil {
		t.Fatalf("ValidateFirewallTags(CIDR source) unexpected error: %v", err)
	}
	if err := isolation.ValidateFirewallTags([]string{"ctrldb-test-client"}, []string{"ctrldb-test-node"}); err != nil {
		t.Fatalf("ValidateFirewallTags(tag source) unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		source []string
		target []string
		kind   error
	}{
		{name: "missing target", kind: isolation.ErrInvalidGuardInput},
		{name: "production source", source: []string{"api-server"}, target: []string{"ctrldb-test-node"}, kind: isolation.ErrUnsafeTarget},
		{name: "production target", target: []string{"mongodb"}, kind: isolation.ErrUnsafeTarget},
		{name: "duplicate target", target: []string{"ctrldb-test-node", "ctrldb-test-node"}, kind: isolation.ErrInvalidGuardInput},
		{name: "overlong tag", target: []string{"ctrldb-test-" + strings.Repeat("a", 52)}, kind: isolation.ErrUnsafeTarget},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := isolation.ValidateFirewallTags(test.source, test.target); !errors.Is(err, test.kind) {
				t.Fatalf("ValidateFirewallTags() error = %v; want %v", err, test.kind)
			}
		})
	}
}

func TestValidateNetworkCIDRAcceptsPrivateNonOverlappingRanges(t *testing.T) {
	t.Parallel()

	for _, cidr := range []string{"10.20.0.0/24", "172.16.0.0/16", "192.168.50.0/24", "10.30.0.0/29"} {
		if err := isolation.ValidateNetworkCIDR(cidr, []string{"10.10.0.0/16", "172.20.0.0/16"}); err != nil {
			t.Errorf("ValidateNetworkCIDR(%q) unexpected error: %v", cidr, err)
		}
	}
}

func TestValidateNetworkCIDRRejectsPublicOverlapAndMalformedDiscovery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		testCIDR  string
		forbidden []string
		kind      error
	}{
		{name: "public", testCIDR: "203.0.113.0/24", kind: isolation.ErrNetworkOverlap},
		{name: "IPv6", testCIDR: "fd00::/64", kind: isolation.ErrInvalidGuardInput},
		{name: "host bits", testCIDR: "10.20.0.1/24", kind: isolation.ErrInvalidGuardInput},
		{name: "prefix 30", testCIDR: "10.20.0.0/30", kind: isolation.ErrInvalidGuardInput},
		{name: "prefix 31", testCIDR: "10.20.0.0/31", kind: isolation.ErrInvalidGuardInput},
		{name: "prefix 32", testCIDR: "10.20.0.1/32", kind: isolation.ErrInvalidGuardInput},
		{name: "invalid", testCIDR: "not-a-cidr", kind: isolation.ErrInvalidGuardInput},
		{name: "test contains existing", testCIDR: "10.20.0.0/16", forbidden: []string{"10.20.1.0/24"}, kind: isolation.ErrNetworkOverlap},
		{name: "existing contains test", testCIDR: "10.20.1.0/24", forbidden: []string{"10.20.0.0/16"}, kind: isolation.ErrNetworkOverlap},
		{name: "equal", testCIDR: "10.20.0.0/24", forbidden: []string{"10.20.0.0/24"}, kind: isolation.ErrNetworkOverlap},
		{name: "malformed discovered CIDR", testCIDR: "10.20.0.0/24", forbidden: []string{"unknown"}, kind: isolation.ErrInvalidGuardInput},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := isolation.ValidateNetworkCIDR(test.testCIDR, test.forbidden); !errors.Is(err, test.kind) {
				t.Fatalf("ValidateNetworkCIDR() error = %v; want %v", err, test.kind)
			}
		})
	}
}

func TestValidateHarnessLocksRequiresExactCompleteSetAndRunOwnership(t *testing.T) {
	t.Parallel()

	locks, expected := validLockProof()
	if err := isolation.ValidateHarnessLocks(locks, expected, "run1", operatorPrincipal()); err != nil {
		t.Fatalf("ValidateHarnessLocks() unexpected error: %v", err)
	}
	if err := isolation.ValidateHarnessLocks(locks, expected, "run1", isolation.Principal{}); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(empty holder) error = %v; want ErrInvalidGuardInput", err)
	}
	principalSet := isolation.Principal{Kind: "principalSet", Subject: "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/attribute.repository/example/repo"}
	if err := isolation.ValidateHarnessLocks(locks, expected, "run1", principalSet); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(principalSet runtime actor) error = %v; want ErrInvalidGuardInput", err)
	}
	activeProduction := append([]isolation.EnvironmentLock(nil), locks...)
	activeProduction[0].Active = true
	activeProduction[0].Holder = destructivePrincipal()
	if err := isolation.ValidateHarnessLocks(activeProduction, expected, "run1", operatorPrincipal()); err != nil {
		t.Fatalf("ValidateHarnessLocks(active production lock held by operator) unexpected error: %v", err)
	}
	inactiveWithHolder := append([]isolation.EnvironmentLock(nil), locks...)
	inactiveWithHolder[0].Holder = operatorPrincipal()
	if err := isolation.ValidateHarnessLocks(inactiveWithHolder, expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(inactive with holder) error = %v; want ErrInvalidGuardInput", err)
	}
	invalidActive := append([]isolation.EnvironmentLock(nil), locks...)
	invalidActive[0].Active = true
	if err := isolation.ValidateHarnessLocks(invalidActive, expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(active without holder) error = %v; want ErrInvalidGuardInput", err)
	}
	aliasHolder := append([]isolation.EnvironmentLock(nil), activeProduction...)
	aliasHolder[0].Holder.Subject = "user:" + aliasHolder[0].Holder.Subject
	if err := isolation.ValidateHarnessLocks(aliasHolder, expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(alias holder) error = %v; want ErrInvalidGuardInput", err)
	}
	duplicate := append(append([]isolation.EnvironmentLock(nil), locks...), locks[0])
	if err := isolation.ValidateHarnessLocks(duplicate, expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(duplicate) error = %v; want ErrInvalidGuardInput", err)
	}
	if err := isolation.ValidateHarnessLocks(locks[:1], expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrRunLockNotHeld) {
		t.Fatalf("ValidateHarnessLocks(missing run lock) error = %v; want ErrRunLockNotHeld", err)
	}
	lost := append([]isolation.EnvironmentLock(nil), locks...)
	lost[1].Holder = isolation.Principal{Kind: isolation.PrincipalKindServiceAccount, Subject: "other-runner@example-test-project.iam.gserviceaccount.com"}
	if err := isolation.ValidateHarnessLocks(lost, expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrRunLockNotHeld) {
		t.Fatalf("ValidateHarnessLocks(lock loss) error = %v; want ErrRunLockNotHeld", err)
	}
	absentRunLock := append([]isolation.EnvironmentLock(nil), locks...)
	absentRunLock[1].Active = false
	absentRunLock[1].Holder = isolation.Principal{}
	if err := isolation.ValidateHarnessLocks(absentRunLock, expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrRunLockNotHeld) {
		t.Fatalf("ValidateHarnessLocks(absent run lock) error = %v; want ErrRunLockNotHeld", err)
	}
	missingProduction := []isolation.EnvironmentLock{locks[1]}
	if err := isolation.ValidateHarnessLocks(missingProduction, expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(missing environment) error = %v; want ErrInvalidGuardInput", err)
	}
	unexpected := append(append([]isolation.EnvironmentLock(nil), locks...), isolation.EnvironmentLock{
		Environment: "staging", Class: domain.EnvironmentStaging,
	})
	if err := isolation.ValidateHarnessLocks(unexpected, expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(unexpected environment) error = %v; want ErrInvalidGuardInput", err)
	}
	heldProduction := append([]isolation.EnvironmentLock(nil), locks...)
	heldProduction[0].Active = true
	heldProduction[0].Holder = operatorPrincipal()
	if err := isolation.ValidateHarnessLocks(heldProduction, expected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrNonDisposableLock) {
		t.Fatalf("ValidateHarnessLocks(non-disposable holder) error = %v; want ErrNonDisposableLock", err)
	}
	ambiguousExpected := append(append([]isolation.EnvironmentIdentity(nil), expected...), isolation.EnvironmentIdentity{
		Environment: "production", Class: domain.EnvironmentStaging,
	})
	if err := isolation.ValidateHarnessLocks(locks, ambiguousExpected, "run1", operatorPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(ambiguous expectation) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestPreMutationGateRequiresEveryLocalProofFamily(t *testing.T) {
	t.Parallel()

	input := validPreMutationInput()
	policy := validPreMutationPolicy()
	decision, err := isolation.AuthorizePreMutation(policy, input, authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	boundary, err := isolation.RevalidatePreMutation(decision, policy, freshPreMutationInput(), revalidationNow())
	if err != nil {
		t.Fatalf("RevalidatePreMutation() unexpected error: %v", err)
	}
	boundaryIntents := boundary.Intents()
	boundaryTarget := boundaryIntents[0].Target()
	boundaryTarget.Labels[config.LabelPurpose] = "changed"
	for _, target := range input.Targets {
		if target.Labels[config.LabelPurpose] != config.TestResourcePurposeLabel {
			t.Fatal("RevalidatePreMutation() intents alias authorization input")
		}
	}

	tests := []struct {
		name   string
		mutate func(*isolation.PreMutationInput)
		kind   error
	}{
		{name: "operation attempt proof", mutate: func(value *isolation.PreMutationInput) { value.Operation.Attempt = 0 }, kind: isolation.ErrInvalidGuardInput},
		{name: "operation ID proof", mutate: func(value *isolation.PreMutationInput) { value.Operation.OperationID = "Operation 1" }, kind: isolation.ErrInvalidGuardInput},
		{name: "step ID proof", mutate: func(value *isolation.PreMutationInput) { value.Operation.StepID = "create/test" }, kind: isolation.ErrInvalidGuardInput},
		{name: "selector proof", mutate: func(value *isolation.PreMutationInput) { value.RunID = "different" }, kind: isolation.ErrUnsafeTarget},
		{name: "Compute target underscore", mutate: func(value *isolation.PreMutationInput) {
			value.Targets[0].Identity.Name = "ctrldb-test-run1_vm"
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "Compute target leading digit", mutate: func(value *isolation.PreMutationInput) {
			value.Targets[0].Identity.Name = "1-ctrldb-test-run1-vm"
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "Compute target overlong", mutate: func(value *isolation.PreMutationInput) {
			value.Targets[0].Identity.Name = "ctrldb-test-run1-" + strings.Repeat("a", 47)
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "capacity proof", mutate: func(value *isolation.PreMutationInput) {
			value.Capacity.Instances[0].Machine.VCPUs = 8
			refreshCapacityFingerprint(&value.Capacity)
		}, kind: isolation.ErrCapacityExceeded},
		{name: "network policy proof", mutate: func(value *isolation.PreMutationInput) { value.TestCIDR = "10.80.1.0/24" }, kind: isolation.ErrInvalidGuardInput},
		{name: "lock proof", mutate: func(value *isolation.PreMutationInput) {
			value.Locks[0].Active = true
			value.Locks[0].Holder = value.MutationPrincipal
		}, kind: isolation.ErrNonDisposableLock},
		{name: "permission proof", mutate: func(value *isolation.PreMutationInput) { value.Permissions.Observed = nil }, kind: isolation.ErrPermissionProof},
		{name: "mutation principal proof", mutate: func(value *isolation.PreMutationInput) { value.MutationPrincipal = destructivePrincipal() }, kind: isolation.ErrPermissionProof},
		{name: "firewall proof", mutate: func(value *isolation.PreMutationInput) { value.FirewallRules = value.FirewallRules[:1] }, kind: isolation.ErrUnsafeFirewall},
		{name: "disabled firewall proof", mutate: func(value *isolation.PreMutationInput) { value.FirewallRules[0].Enabled = false }, kind: isolation.ErrUnsafeFirewall},
		{name: "freshness proof", mutate: func(value *isolation.PreMutationInput) { value.Freshness.ValidUntil = value.Freshness.ObservedAt }, kind: isolation.ErrStaleProof},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validPreMutationInput()
			test.mutate(&value)
			if _, err := isolation.AuthorizePreMutation(validPreMutationPolicy(), value, authorizationNow()); !errors.Is(err, test.kind) {
				t.Fatalf("AuthorizePreMutation() error = %v; want %v", err, test.kind)
			}
		})
	}
}

func TestPreMutationAcceptsOnlyCompleteTypedCreateIntents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*isolation.PreMutationInput)
	}{
		{name: "missing intent", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents = value.MutationIntents[:len(value.MutationIntents)-1]
		}},
		{name: "extra intent", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents = append(value.MutationIntents, value.MutationIntents[0])
		}},
		{name: "duplicate target", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents[1] = value.MutationIntents[0]
		}},
		{name: "update action", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents[0].Action = "update"
		}},
		{name: "delete action", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents[0].Action = "delete"
		}},
		{name: "destructive role on create", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents[0].RequiredPrincipalRole = isolation.TestPrincipalRoleDestructive
		}},
		{name: "mismatched target", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents[0].Target = cloneMutationTargetForTest(value.Targets[1])
		}},
		{name: "firewall state missing", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents[0].Create.Firewall = nil
		}},
		{name: "firewall state differs from proof", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents[0].Create.Firewall.Priority = 900
		}},
		{name: "firewall state identity differs from target", mutate: func(value *isolation.PreMutationInput) {
			value.MutationIntents[0].Create.Firewall.Identity = value.FirewallRules[1].Identity
		}},
		{name: "instance create is unrepresentable", mutate: func(value *isolation.PreMutationInput) {
			target := testTargetWithIdentity(value.Capacity.Instances[0].Identity, value.RunID)
			firewall := cloneFirewallRule(value.FirewallRules[0])
			value.Targets = append(value.Targets, target)
			value.MutationIntents = append(value.MutationIntents, isolation.MutationIntent{
				Action: isolation.MutationActionComputeFirewallInsert, Target: target,
				RequiredPrincipalRole: isolation.TestPrincipalRoleOperator,
				Create:                isolation.CreateDesiredState{Firewall: &firewall},
			})
		}},
		{name: "disk create is unrepresentable", mutate: func(value *isolation.PreMutationInput) {
			target := testTargetWithIdentity(value.Capacity.Disks[0].Identity, value.RunID)
			firewall := cloneFirewallRule(value.FirewallRules[0])
			value.Targets = append(value.Targets, target)
			value.MutationIntents = append(value.MutationIntents, isolation.MutationIntent{
				Action: isolation.MutationActionComputeFirewallInsert, Target: target,
				RequiredPrincipalRole: isolation.TestPrincipalRoleOperator,
				Create:                isolation.CreateDesiredState{Firewall: &firewall},
			})
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validPreMutationInput()
			test.mutate(&input)
			if _, err := isolation.AuthorizePreMutation(validPreMutationPolicy(), input, authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) && !errors.Is(err, isolation.ErrPermissionProof) && !errors.Is(err, isolation.ErrUnsafeFirewall) {
				t.Fatalf("AuthorizePreMutation() error = %v; want a fail-closed intent or principal error", err)
			}
		})
	}
}

func TestPreMutationIntentAndDesiredStateAreFingerprintBound(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	decision, err := isolation.AuthorizePreMutation(policy, validPreMutationInput(), authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}

	changedAction := freshPreMutationInput()
	changedAction.MutationIntents[0].Action = "delete"
	if _, err := isolation.RevalidatePreMutation(decision, policy, changedAction, revalidationNow()); err == nil {
		t.Fatal("RevalidatePreMutation() accepted a delete derived from create authorization")
	}

	changedState := freshPreMutationInput()
	changedState.MutationIntents[0].Create.Firewall.Priority = 900
	if _, err := isolation.RevalidatePreMutation(decision, policy, changedState, revalidationNow()); err == nil {
		t.Fatal("RevalidatePreMutation() accepted changed firewall desired state")
	}
}

func TestPreMutationFirewallRetryEmitsOnlyAbsentRulesAndReportsConvergence(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	partial := validPreMutationInput()
	present := cloneFirewallRule(partial.FirewallRules[0])
	partial.FirewallObservations[0] = isolation.FirewallObservation{
		Identity: partial.FirewallRules[0].Identity, State: isolation.FirewallObservationPresent, PresentRule: &present,
	}
	partial.Targets = partial.Targets[1:]
	partial.MutationIntents = validMutationIntents(partial)
	decision, err := isolation.AuthorizePreMutation(policy, partial, authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation(partial retry) unexpected error: %v", err)
	}
	fresh := partial
	fresh.Freshness.ObservedAt = fresh.Freshness.ObservedAt.Add(45 * time.Second)
	boundary, err := isolation.RevalidatePreMutation(decision, policy, fresh, revalidationNow())
	if err != nil {
		t.Fatalf("RevalidatePreMutation(partial retry) unexpected error: %v", err)
	}
	if boundary.Disposition() != isolation.MutationDispositionReady || len(boundary.Intents()) != 1 ||
		boundary.Intents()[0].Target().Identity != partial.FirewallRules[1].Identity {
		t.Fatal("partial retry did not emit exactly the absent firewall insert")
	}

	converged := validPreMutationInput()
	converged.FirewallObservations = presentFirewallObservations(converged.FirewallRules)
	converged.Targets = nil
	converged.MutationIntents = nil
	decision, err = isolation.AuthorizePreMutation(policy, converged, authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation(converged) unexpected error: %v", err)
	}
	freshConverged := converged
	freshConverged.Freshness.ObservedAt = freshConverged.Freshness.ObservedAt.Add(45 * time.Second)
	boundary, err = isolation.RevalidatePreMutation(decision, policy, freshConverged, revalidationNow())
	if err != nil {
		t.Fatalf("RevalidatePreMutation(converged) unexpected error: %v", err)
	}
	if boundary.Disposition() != isolation.MutationDispositionConverged || len(boundary.Intents()) != 0 {
		t.Fatal("fully present retry did not return an explicit no-mutation converged boundary")
	}
}

func TestPreMutationRequiresExactPermissionForEachEmittedFirewallInsert(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*isolation.PreMutationInput)
	}{
		{name: "missing", mutate: func(input *isolation.PreMutationInput) {
			input.Permissions.Expected = withoutFirewallCreatePermission(input.Permissions.Expected)
			input.Permissions.Observed = withoutFirewallCreatePermission(input.Permissions.Observed)
		}},
		{name: "denied", mutate: func(input *isolation.PreMutationInput) {
			mutateFirewallCreatePermission(input, func(value *isolation.PermissionObservation) { value.Granted = false })
		}},
		{name: "wrong principal", mutate: func(input *isolation.PreMutationInput) {
			mutateFirewallCreatePermission(input, func(value *isolation.PermissionObservation) {
				value.Identity = destructivePrincipal()
			})
		}},
		{name: "wrong project", mutate: func(input *isolation.PreMutationInput) {
			resource, _ := isolation.ProjectAuthorizationResource("another-test-project")
			mutateFirewallCreatePermission(input, func(value *isolation.PermissionObservation) { value.Resource = resource })
		}},
		{name: "wrong resource", mutate: func(input *isolation.PreMutationInput) {
			mutateFirewallCreatePermission(input, func(value *isolation.PermissionObservation) {
				value.Resource = permissionResource("ctrldb-test-run1-vm")
			})
		}},
		{name: "get lookalike", mutate: func(input *isolation.PreMutationInput) {
			mutateFirewallCreatePermission(input, func(value *isolation.PermissionObservation) { value.Permission = "compute.firewalls.get" })
		}},
		{name: "update lookalike", mutate: func(input *isolation.PreMutationInput) {
			mutateFirewallCreatePermission(input, func(value *isolation.PermissionObservation) { value.Permission = "compute.firewalls.update" })
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validPreMutationInput()
			test.mutate(&input)
			policy := validPreMutationPolicy()
			refreshPermissionInventory(&policy, input.Permissions.Expected)
			if _, err := isolation.AuthorizePreMutation(policy, input, authorizationNow()); err == nil {
				t.Fatal("AuthorizePreMutation() accepted insufficient firewall-create permission evidence")
			}
		})
	}

	partial := validPreMutationInput()
	present := cloneFirewallRule(partial.FirewallRules[0])
	partial.FirewallObservations[0] = isolation.FirewallObservation{
		Identity: partial.FirewallRules[0].Identity, State: isolation.FirewallObservationPresent, PresentRule: &present,
	}
	partial.Targets = partial.Targets[1:]
	partial.MutationIntents = validMutationIntents(partial)
	partial.Permissions.Expected = withoutFirewallCreatePermission(partial.Permissions.Expected)
	partial.Permissions.Observed = withoutFirewallCreatePermission(partial.Permissions.Observed)
	partialPolicy := validPreMutationPolicy()
	refreshPermissionInventory(&partialPolicy, partial.Permissions.Expected)
	if _, err := isolation.AuthorizePreMutation(partialPolicy, partial, authorizationNow()); !errors.Is(err, isolation.ErrPermissionProof) {
		t.Fatalf("AuthorizePreMutation(partial retry without create grant) error = %v; want ErrPermissionProof", err)
	}

	converged := validPreMutationInput()
	converged.FirewallObservations = presentFirewallObservations(converged.FirewallRules)
	converged.Targets = nil
	converged.MutationIntents = nil
	converged.Permissions.Expected = withoutFirewallCreatePermission(converged.Permissions.Expected)
	converged.Permissions.Observed = withoutFirewallCreatePermission(converged.Permissions.Observed)
	convergedPolicy := validPreMutationPolicy()
	refreshPermissionInventory(&convergedPolicy, converged.Permissions.Expected)
	decision, err := isolation.AuthorizePreMutation(convergedPolicy, converged, authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation(converged without create grant) unexpected error: %v", err)
	}
	fresh := converged
	fresh.Freshness.ObservedAt = fresh.Freshness.ObservedAt.Add(45 * time.Second)
	boundary, err := isolation.RevalidatePreMutation(decision, convergedPolicy, fresh, revalidationNow())
	if err != nil || boundary.Disposition() != isolation.MutationDispositionConverged {
		t.Fatalf("RevalidatePreMutation(converged without create grant) = (%v, %v); want converged success", boundary.Disposition(), err)
	}
}

func TestPreMutationFirewallObservationDriftCannotReuseAuthorization(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	authorized := validPreMutationInput()
	decision, err := isolation.AuthorizePreMutation(policy, authorized, authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}

	fresh := freshPreMutationInput()
	present := cloneFirewallRule(fresh.FirewallRules[0])
	fresh.FirewallObservations[0] = isolation.FirewallObservation{
		Identity: fresh.FirewallRules[0].Identity, State: isolation.FirewallObservationPresent, PresentRule: &present,
	}
	fresh.Targets = fresh.Targets[1:]
	fresh.MutationIntents = validMutationIntents(fresh)
	if _, err := isolation.RevalidatePreMutation(decision, policy, fresh, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(observation drift) error = %v; want ErrProofMismatch", err)
	}

	disappeared := freshPreMutationInput()
	disappeared.FirewallObservations = disappeared.FirewallObservations[:1]
	if _, err := isolation.RevalidatePreMutation(decision, policy, disappeared, revalidationNow()); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("RevalidatePreMutation(disappeared observation) error = %v; want ErrUnsafeFirewall", err)
	}
}

func TestPreMutationCanonicalizesFirewallCollectionsAndDetachesObservations(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	authorized := validPreMutationInput()
	decision, err := isolation.AuthorizePreMutation(policy, authorized, authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	fresh := freshPreMutationInput()
	for index := range fresh.FirewallRules {
		fresh.FirewallRules[index].Denied = []isolation.FirewallTrafficRule{}
		fresh.FirewallRules[index].DestinationCIDRs = []string{}
		fresh.FirewallRules[index].SourceServiceAccounts = []string{}
		fresh.FirewallRules[index].TargetServiceAccounts = []string{}
		fresh.FirewallRules[index].ResourceManagerTags = map[string]string{}
	}
	fresh.MutationIntents = validMutationIntents(fresh)
	boundary, err := isolation.RevalidatePreMutation(decision, policy, fresh, revalidationNow())
	if err != nil {
		t.Fatalf("RevalidatePreMutation(nil/empty equivalent collections) unexpected error: %v", err)
	}
	for _, intent := range boundary.Intents() {
		firewall, _ := intent.FirewallCreateState()
		if firewall.Denied != nil || firewall.DestinationCIDRs != nil || firewall.ResourceManagerTags != nil {
			t.Fatal("MutationBoundary did not return canonical empty firewall collections")
		}
	}
}

func TestMutationBoundarySealsAndDetachesProviderRequests(t *testing.T) {
	t.Parallel()

	input := validPreMutationInput()
	policy := validPreMutationPolicy()
	decision, err := isolation.AuthorizePreMutation(policy, input, authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	fresh := freshPreMutationInput()
	boundary, err := isolation.RevalidatePreMutation(decision, policy, fresh, revalidationNow())
	if err != nil {
		t.Fatalf("RevalidatePreMutation() unexpected error: %v", err)
	}
	if boundary.Operation() != fresh.Operation || boundary.Principal() != operatorPrincipal() {
		t.Fatal("MutationBoundary did not carry the validated operation and configured operator")
	}

	intents := boundary.Intents()
	if len(intents) != len(fresh.Targets) {
		t.Fatalf("MutationBoundary intent count = %d; want %d", len(intents), len(fresh.Targets))
	}
	for _, intent := range intents {
		if intent.Action() != isolation.MutationActionComputeFirewallInsert || intent.RequiredPrincipalRole() != isolation.TestPrincipalRoleOperator {
			t.Fatal("MutationBoundary exposed a non-create or non-operator request")
		}
	}

	firstTarget := intents[0].Target()
	firstTarget.Labels[config.LabelPurpose] = "changed"
	for _, intent := range boundary.Intents() {
		if intent.Target().Labels[config.LabelPurpose] != config.TestResourcePurposeLabel {
			t.Fatal("MutationBoundary target labels alias an earlier accessor result")
		}
	}

	for _, intent := range intents {
		firewall, ok := intent.FirewallCreateState()
		if !ok {
			continue
		}
		firewall.Allowed[0].Ports[0] = 443
		if len(firewall.SourceCIDRs) > 0 {
			firewall.SourceCIDRs[0] = "10.99.0.0/24"
		}
		if len(firewall.SourceTags) > 0 {
			firewall.SourceTags[0] = "changed"
		}
		firewall.TargetTags[0] = "changed"
		firewall.ResourceManagerTags = map[string]string{"tagKeys/123": "tagValues/456"}
	}
	fresh.MutationIntents[0].Target.Labels[config.LabelPurpose] = "changed"
	for _, intent := range fresh.MutationIntents {
		if intent.Create.Firewall != nil {
			intent.Create.Firewall.Allowed[0].Ports[0] = 443
			if len(intent.Create.Firewall.SourceCIDRs) > 0 {
				intent.Create.Firewall.SourceCIDRs[0] = "10.99.0.0/24"
			}
			if len(intent.Create.Firewall.SourceTags) > 0 {
				intent.Create.Firewall.SourceTags[0] = "changed"
			}
			intent.Create.Firewall.TargetTags[0] = "changed"
			intent.Create.Firewall.ResourceManagerTags = map[string]string{"tagKeys/123": "tagValues/456"}
		}
	}
	for _, intent := range boundary.Intents() {
		target := intent.Target()
		if target.Labels[config.LabelPurpose] != config.TestResourcePurposeLabel {
			t.Fatal("MutationBoundary target aliases revalidation input")
		}
		if firewall, ok := intent.FirewallCreateState(); ok {
			if firewall.Allowed[0].Ports[0] == 443 || firewall.TargetTags[0] == "changed" ||
				(len(firewall.SourceCIDRs) > 0 && firewall.SourceCIDRs[0] == "10.99.0.0/24") ||
				(len(firewall.SourceTags) > 0 && firewall.SourceTags[0] == "changed") || len(firewall.ResourceManagerTags) != 0 {
				t.Fatal("MutationBoundary firewall state aliases an input or accessor result")
			}
		}
	}
}

func TestPreMutationPolicyPinsConfiguredTestPrincipals(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	input := validPreMutationInput()
	if _, err := isolation.AuthorizePreMutation(policy, input, authorizationNow()); err != nil {
		t.Fatalf("AuthorizePreMutation(configured operator) unexpected error: %v", err)
	}

	invalidPolicies := []struct {
		name   string
		mutate func(*isolation.PreMutationPolicy)
	}{
		{name: "user operator", mutate: func(value *isolation.PreMutationPolicy) {
			value.TestOperatorPrincipal = isolation.Principal{Kind: isolation.PrincipalKindUser, Subject: "operator@example.test"}
		}},
		{name: "missing destructive principal", mutate: func(value *isolation.PreMutationPolicy) {
			value.TestDestructivePrincipal = isolation.Principal{}
		}},
		{name: "same principals", mutate: func(value *isolation.PreMutationPolicy) {
			value.TestDestructivePrincipal = value.TestOperatorPrincipal
		}},
	}
	for _, test := range invalidPolicies {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			invalid := validPreMutationPolicy()
			test.mutate(&invalid)
			if _, err := isolation.AuthorizePreMutation(invalid, validPreMutationInput(), authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
				t.Fatalf("AuthorizePreMutation() error = %v; want ErrInvalidGuardInput", err)
			}
		})
	}

	for _, alternate := range []isolation.Principal{
		destructivePrincipal(),
		{Kind: isolation.PrincipalKindServiceAccount, Subject: "other-operator@example-test-project.iam.gserviceaccount.com"},
	} {
		alternate := alternate
		t.Run(alternate.Subject, func(t *testing.T) {
			t.Parallel()
			input := validPreMutationInput()
			input.MutationPrincipal = alternate
			for index := range input.Permissions.Expected {
				input.Permissions.Expected[index].Identity = alternate
				input.Permissions.Observed[index].Identity = alternate
			}
			policy := validPreMutationPolicy()
			refreshPermissionInventory(&policy, input.Permissions.Expected)
			if _, err := isolation.AuthorizePreMutation(policy, input, authorizationNow()); !errors.Is(err, isolation.ErrPermissionProof) {
				t.Fatalf("AuthorizePreMutation(self-consistent alternate principal) error = %v; want ErrPermissionProof", err)
			}
		})
	}

	alternate := isolation.Principal{
		Kind: isolation.PrincipalKindServiceAccount, Subject: "other-operator@example-test-project.iam.gserviceaccount.com",
	}
	decision, err := isolation.AuthorizePreMutation(policy, validPreMutationInput(), authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	fresh := freshPreMutationInput()
	fresh.MutationPrincipal = alternate
	for index := range fresh.Permissions.Expected {
		fresh.Permissions.Expected[index].Identity = alternate
		fresh.Permissions.Observed[index].Identity = alternate
	}
	changedPolicy := validPreMutationPolicy()
	changedPolicy.TestOperatorPrincipal = alternate
	fresh.Locks[1].Holder = alternate
	refreshPermissionInventory(&changedPolicy, fresh.Permissions.Expected)
	if _, err := isolation.RevalidatePreMutation(decision, changedPolicy, fresh, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(changed configured principal) error = %v; want ErrProofMismatch", err)
	}
}

func TestPreMutationPolicyPinsOperatorAsRuntimeAndLockPrincipal(t *testing.T) {
	t.Parallel()

	alternate := isolation.Principal{
		Kind: isolation.PrincipalKindServiceAccount, Subject: "alternate-runner@example-test-project.iam.gserviceaccount.com",
	}
	input := validPreMutationInput()
	input.MutationPrincipal = alternate
	input.Locks[1].Holder = alternate
	for index := range input.Permissions.Expected {
		input.Permissions.Expected[index].Identity = alternate
		input.Permissions.Observed[index].Identity = alternate
	}
	policy := validPreMutationPolicy()
	refreshPermissionInventory(&policy, input.Permissions.Expected)
	if _, err := isolation.AuthorizePreMutation(policy, input, authorizationNow()); !errors.Is(err, isolation.ErrPermissionProof) {
		t.Fatalf("AuthorizePreMutation(self-consistent alternate runtime principal) error = %v; want ErrPermissionProof", err)
	}

	policy = validPreMutationPolicy()
	decision, err := isolation.AuthorizePreMutation(policy, validPreMutationInput(), authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	fresh := freshPreMutationInput()
	fresh.MutationPrincipal = alternate
	fresh.Locks[1].Holder = alternate
	for index := range fresh.Permissions.Expected {
		fresh.Permissions.Expected[index].Identity = alternate
		fresh.Permissions.Observed[index].Identity = alternate
	}
	changedPolicy := policy
	changedPolicy.TestOperatorPrincipal = alternate
	refreshPermissionInventory(&changedPolicy, fresh.Permissions.Expected)
	if _, err := isolation.RevalidatePreMutation(decision, changedPolicy, fresh, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(self-consistent alternate runtime principal) error = %v; want ErrProofMismatch", err)
	}
}

func TestPreMutationCapacityProofUsesTheFullPlannedInventory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*isolation.PreMutationInput)
		kind   error
	}{
		{name: "empty instances", mutate: func(input *isolation.PreMutationInput) { input.Capacity.Instances = nil }, kind: isolation.ErrInvalidGuardInput},
		{name: "duplicate instance", mutate: func(input *isolation.PreMutationInput) {
			input.Capacity.Instances = append(input.Capacity.Instances, input.Capacity.Instances[0])
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "zero shape", mutate: func(input *isolation.PreMutationInput) { input.Capacity.Instances[0].Machine.VCPUs = 0 }, kind: isolation.ErrInvalidGuardInput},
		{name: "cross-run instance", mutate: func(input *isolation.PreMutationInput) { input.Capacity.Instances[0].RunID = "run-42" }, kind: isolation.ErrInvalidGuardInput},
		{name: "oversized shape", mutate: func(input *isolation.PreMutationInput) { input.Capacity.Instances[0].Machine.MemoryMB = 32 * 1024 }, kind: isolation.ErrCapacityExceeded},
		{name: "duplicate disk", mutate: func(input *isolation.PreMutationInput) {
			input.Capacity.Disks = append(input.Capacity.Disks, input.Capacity.Disks[0])
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "zero disk size", mutate: func(input *isolation.PreMutationInput) { input.Capacity.Disks[0].SizeGiB = 0 }, kind: isolation.ErrInvalidGuardInput},
		{name: "cross-run disk", mutate: func(input *isolation.PreMutationInput) { input.Capacity.Disks[0].RunID = "run-42" }, kind: isolation.ErrInvalidGuardInput},
		{name: "target absent from plan", mutate: func(input *isolation.PreMutationInput) {
			input.Targets = append(input.Targets, testTarget("ctrldb-test-run1-other", "run1"))
		}, kind: isolation.ErrInvalidGuardInput},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validPreMutationInput()
			test.mutate(&input)
			if test.name != "empty instances" {
				refreshCapacityFingerprint(&input.Capacity)
			}
			if _, err := isolation.AuthorizePreMutation(validPreMutationPolicy(), input, authorizationNow()); !errors.Is(err, test.kind) {
				t.Fatalf("AuthorizePreMutation() error = %v; want %v", err, test.kind)
			}
		})
	}

	input := validPreMutationInput()
	if _, err := isolation.AuthorizePreMutation(validPreMutationPolicy(), input, authorizationNow()); err != nil {
		t.Fatalf("AuthorizePreMutation(firewall-only mutation with planned instance capacity) unexpected error: %v", err)
	}
	regionalDisk := validPreMutationInput()
	regionalDisk.Capacity.Disks[0].Identity = testResourceIdentity(
		"ctrldb-test-run1-disk", isolation.ComputeDiskKind, isolation.ResourceScopeRegion, "europe-west10",
	)
	refreshCapacityFingerprint(&regionalDisk.Capacity)
	if _, err := isolation.AuthorizePreMutation(validPreMutationPolicy(), regionalDisk, authorizationNow()); err != nil {
		t.Fatalf("AuthorizePreMutation(regional disk inventory) unexpected error: %v", err)
	}
}

func TestCapacitySnapshotFingerprintBindsTypedPlanAndCapacityValues(t *testing.T) {
	t.Parallel()

	base := validPreMutationInput().Capacity
	baseline := base.SnapshotFingerprint
	tests := []struct {
		name   string
		mutate func(*isolation.CapacityProofInput)
	}{
		{name: "plan ID", mutate: func(value *isolation.CapacityProofInput) { value.Plan.ID = "plan-fedcba9876543210" }},
		{name: "plan hash", mutate: func(value *isolation.CapacityProofInput) { value.Plan.Hash = strings.Repeat("c", 64) }},
		{name: "machine shape", mutate: func(value *isolation.CapacityProofInput) { value.Instances[0].Machine.VCPUs++ }},
		{name: "disk size", mutate: func(value *isolation.CapacityProofInput) { value.Disks[0].SizeGiB++ }},
		{name: "lifetime", mutate: func(value *isolation.CapacityProofInput) { value.Lifetime++ }},
		{name: "cost", mutate: func(value *isolation.CapacityProofInput) { value.EstimatedCostMicros++ }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validPreMutationInput().Capacity
			test.mutate(&value)
			fingerprint, err := isolation.CapacitySnapshotFingerprint(value)
			if err != nil {
				t.Fatalf("CapacitySnapshotFingerprint() unexpected error: %v", err)
			}
			if fingerprint == baseline {
				t.Fatal("CapacitySnapshotFingerprint() did not change with typed snapshot")
			}
		})
	}

	tampered := validPreMutationInput()
	tampered.Capacity.Instances[0].Machine.MemoryMB++
	if _, err := isolation.AuthorizePreMutation(validPreMutationPolicy(), tampered, authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("AuthorizePreMutation(tampered capacity snapshot) error = %v; want ErrInvalidGuardInput", err)
	}
	invalidPlan := validPreMutationInput()
	invalidPlan.Capacity.Plan.ID = "plan-1"
	if _, err := isolation.AuthorizePreMutation(validPreMutationPolicy(), invalidPlan, authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("AuthorizePreMutation(malformed plan identity) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestPreMutationPolicyPinsRejectIncompleteCallerSets(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	tests := []struct {
		name   string
		mutate func(*isolation.PreMutationInput)
		kind   error
	}{
		{name: "omitted production CIDR", mutate: func(value *isolation.PreMutationInput) { value.ProductionCIDRs = []string{"10.90.0.0/16"} }, kind: isolation.ErrInvalidGuardInput},
		{name: "omitted environment", mutate: func(value *isolation.PreMutationInput) {
			value.ExpectedNonDisposableEnvironments = []isolation.EnvironmentIdentity{{Environment: "staging", Class: domain.EnvironmentStaging}}
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "truncated permissions", mutate: func(value *isolation.PreMutationInput) {
			value.Permissions.Expected = value.Permissions.Expected[:1]
			value.Permissions.Observed = value.Permissions.Observed[:1]
		}, kind: isolation.ErrPermissionProof},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validPreMutationInput()
			test.mutate(&input)
			if _, err := isolation.AuthorizePreMutation(policy, input, authorizationNow()); !errors.Is(err, test.kind) {
				t.Fatalf("AuthorizePreMutation() error = %v; want %v", err, test.kind)
			}
		})
	}

	invalidPolicy := policy
	invalidPolicy.ProductionCIDRInventory.Version = ""
	if _, err := isolation.AuthorizePreMutation(invalidPolicy, validPreMutationInput(), authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("AuthorizePreMutation(malformed policy pin) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestPreMutationPolicyOwnsCapacityCapsAndConfiguredCIDR(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	oversized := validPreMutationInput()
	oversized.Capacity.Instances[0].Machine.VCPUs = policy.RunLimits.MaxMachine.VCPUs + 1
	refreshCapacityFingerprint(&oversized.Capacity)
	if _, err := isolation.AuthorizePreMutation(policy, oversized, authorizationNow()); !errors.Is(err, isolation.ErrCapacityExceeded) {
		t.Fatalf("AuthorizePreMutation(plan above trusted cap) error = %v; want ErrCapacityExceeded", err)
	}

	alternateCIDR := validPreMutationInput()
	alternateCIDR.TestCIDR = "10.30.0.0/24"
	if _, err := isolation.AuthorizePreMutation(policy, alternateCIDR, authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("AuthorizePreMutation(alternate private CIDR) error = %v; want ErrInvalidGuardInput", err)
	}

	invalidPolicy := policy
	invalidPolicy.RunLimits = isolation.RunLimits{}
	if _, err := isolation.AuthorizePreMutation(invalidPolicy, validPreMutationInput(), authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("AuthorizePreMutation(invalid trusted caps) error = %v; want ErrInvalidGuardInput", err)
	}
	invalidPolicy = policy
	invalidPolicy.ProjectID = ""
	if _, err := isolation.AuthorizePreMutation(invalidPolicy, validPreMutationInput(), authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("AuthorizePreMutation(missing trusted project) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestPreMutationPolicyProjectBoundaryCoversEveryResourceFamily(t *testing.T) {
	t.Parallel()

	const otherProject = "another-test-project"
	tests := []struct {
		name   string
		mutate func(*isolation.PreMutationInput, *isolation.PreMutationPolicy)
	}{
		{name: "selected target", mutate: func(input *isolation.PreMutationInput, _ *isolation.PreMutationPolicy) {
			moveResourceProject(&input.Targets[0].Identity, otherProject)
		}},
		{name: "planned instance", mutate: func(input *isolation.PreMutationInput, _ *isolation.PreMutationPolicy) {
			moveResourceProject(&input.Capacity.Instances[0].Identity, otherProject)
			refreshCapacityFingerprint(&input.Capacity)
		}},
		{name: "planned disk", mutate: func(input *isolation.PreMutationInput, _ *isolation.PreMutationPolicy) {
			moveResourceProject(&input.Capacity.Disks[0].Identity, otherProject)
			refreshCapacityFingerprint(&input.Capacity)
		}},
		{name: "firewall identity and network", mutate: func(input *isolation.PreMutationInput, _ *isolation.PreMutationPolicy) {
			moveResourceProject(&input.Targets[0].Identity, otherProject)
			moveResourceProject(&input.FirewallRules[0].Identity, otherProject)
			moveResourceProject(&input.FirewallRules[0].Network, otherProject)
		}},
		{name: "expected and observed permission resources", mutate: func(input *isolation.PreMutationInput, policy *isolation.PreMutationPolicy) {
			moveResourceProject(&input.Permissions.Expected[0].Resource, otherProject)
			moveResourceProject(&input.Permissions.Observed[0].Resource, otherProject)
			refreshPermissionInventory(policy, input.Permissions.Expected)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validPreMutationInput()
			policy := validPreMutationPolicy()
			test.mutate(&input, &policy)
			if _, err := isolation.AuthorizePreMutation(policy, input, authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
				t.Fatalf("AuthorizePreMutation(cross-project resource) error = %v; want ErrInvalidGuardInput", err)
			}
		})
	}
}

func TestPreMutationProjectCannotBeWhollyRecomputedOrSwapped(t *testing.T) {
	t.Parallel()

	const otherProject = "another-test-project"
	policy := validPreMutationPolicy()
	moved := validPreMutationInput()
	moveAllResourceProjects(&moved, otherProject)
	refreshPermissionInventory(&policy, moved.Permissions.Expected)
	if _, err := isolation.AuthorizePreMutation(policy, moved, authorizationNow()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("AuthorizePreMutation(wholesale project move) error = %v; want ErrInvalidGuardInput", err)
	}

	originalPolicy := validPreMutationPolicy()
	decision, err := isolation.AuthorizePreMutation(originalPolicy, validPreMutationInput(), authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	switchedPolicy := originalPolicy
	switchedPolicy.ProjectID = otherProject
	fresh := freshPreMutationInput()
	moveAllResourceProjects(&fresh, otherProject)
	refreshPermissionInventory(&switchedPolicy, fresh.Permissions.Expected)
	if _, err := isolation.RevalidatePreMutation(decision, switchedPolicy, fresh, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(wholesale project swap) error = %v; want ErrProofMismatch", err)
	}
}

func TestPolicyInventoryFingerprintsAreOrderIndependentAndRejectDuplicates(t *testing.T) {
	t.Parallel()

	environments := []isolation.EnvironmentIdentity{
		{Environment: "production", Class: domain.EnvironmentProduction},
		{Environment: "staging", Class: domain.EnvironmentStaging},
	}
	first, err := isolation.NonDisposableEnvironmentInventoryFingerprint(environments)
	if err != nil {
		t.Fatalf("NonDisposableEnvironmentInventoryFingerprint() unexpected error: %v", err)
	}
	second, err := isolation.NonDisposableEnvironmentInventoryFingerprint([]isolation.EnvironmentIdentity{environments[1], environments[0]})
	if err != nil || first != second {
		t.Fatalf("environment fingerprint is not canonical: second=%q error=%v", second, err)
	}
	if _, err := isolation.NonDisposableEnvironmentInventoryFingerprint(append(environments, environments[0])); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("NonDisposableEnvironmentInventoryFingerprint(duplicate) error = %v; want ErrInvalidGuardInput", err)
	}

	cidrs := []string{"10.80.0.0/16", "10.90.0.0/16"}
	first, err = isolation.ProductionCIDRInventoryFingerprint(cidrs)
	if err != nil {
		t.Fatalf("ProductionCIDRInventoryFingerprint() unexpected error: %v", err)
	}
	second, err = isolation.ProductionCIDRInventoryFingerprint([]string{cidrs[1], cidrs[0]})
	if err != nil || first != second {
		t.Fatalf("production CIDR fingerprint is not canonical: second=%q error=%v", second, err)
	}
	if _, err := isolation.ProductionCIDRInventoryFingerprint(append(cidrs, cidrs[0])); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ProductionCIDRInventoryFingerprint(duplicate) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestPreMutationUsesIndependentBoundaryTime(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	future := validPreMutationInput()
	if _, err := isolation.AuthorizePreMutation(policy, future, future.Freshness.ObservedAt.Add(-time.Second)); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("AuthorizePreMutation(future observation) error = %v; want ErrStaleProof", err)
	}
	expired := validPreMutationInput()
	if _, err := isolation.AuthorizePreMutation(policy, expired, expired.Freshness.ValidUntil); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("AuthorizePreMutation(expired observation) error = %v; want ErrStaleProof", err)
	}
	if _, err := isolation.AuthorizePreMutation(policy, validPreMutationInput(), time.Time{}); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("AuthorizePreMutation(zero boundary time) error = %v; want ErrInvalidGuardInput", err)
	}
	decision, err := isolation.AuthorizePreMutation(policy, validPreMutationInput(), authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	newerButBeforeAuthorization := validPreMutationInput()
	newerButBeforeAuthorization.Freshness.ObservedAt = newerButBeforeAuthorization.Freshness.ObservedAt.Add(time.Second)
	if _, err := isolation.RevalidatePreMutation(decision, policy, newerButBeforeAuthorization, revalidationNow()); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(observation before authorization) error = %v; want ErrStaleProof", err)
	}
	equalToAuthorization := validPreMutationInput()
	equalToAuthorization.Freshness.ObservedAt = authorizationNow()
	if _, err := isolation.RevalidatePreMutation(decision, policy, equalToAuthorization, revalidationNow()); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(observation at authorization) error = %v; want ErrStaleProof", err)
	}
	if _, err := isolation.RevalidatePreMutation(decision, policy, freshPreMutationInput(), authorizationNow().Add(-time.Nanosecond)); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(regressed boundary clock) error = %v; want ErrStaleProof", err)
	}
	fresh := freshPreMutationInput()
	if _, err := isolation.RevalidatePreMutation(decision, policy, fresh, fresh.Freshness.ObservedAt.Add(-time.Nanosecond)); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(future rediscovery) error = %v; want ErrStaleProof", err)
	}
}

func TestPreMutationBindsDurableAttemptButRequiresExternalAtomicConsumption(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	decision, err := isolation.AuthorizePreMutation(policy, validPreMutationInput(), authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	changed := freshPreMutationInput()
	changed.Operation.Attempt++
	if _, err := isolation.RevalidatePreMutation(decision, policy, changed, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(changed attempt) error = %v; want ErrProofMismatch", err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		boundary, err := isolation.RevalidatePreMutation(decision, policy, freshPreMutationInput(), revalidationNow())
		if err != nil {
			t.Fatalf("RevalidatePreMutation() unexpected error: %v", err)
		}
		if boundary.Operation() != validPreMutationInput().Operation {
			t.Fatal("RevalidatePreMutation() returned the wrong durable attempt binding")
		}
	}
	// Repeated pure validation intentionally succeeds: the caller must atomically
	// claim the returned binding in its durable journal before provider mutation.
}

func TestPreMutationRequiresCurrentBoundedRunLifetime(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	tests := []struct {
		name   string
		mutate func(*isolation.PreMutationInput)
		kind   error
	}{
		{name: "absent record", mutate: func(value *isolation.PreMutationInput) { value.RunLifetime = isolation.RunLifetimeContract{} }, kind: isolation.ErrInvalidRunID},
		{name: "expired", mutate: func(value *isolation.PreMutationInput) {
			value.RunLifetime.ExpiresAt = authorizationNow()
			refreshRunLifetimeFingerprint(value)
		}, kind: isolation.ErrStaleProof},
		{name: "record created after evidence observation", mutate: func(value *isolation.PreMutationInput) {
			value.RunLifetime.CreatedAt = value.Freshness.ObservedAt.Add(time.Nanosecond)
			refreshRunLifetimeFingerprint(value)
		}, kind: isolation.ErrStaleProof},
		{name: "over planned lifetime", mutate: func(value *isolation.PreMutationInput) {
			value.RunLifetime.ExpiresAt = authorizationNow().Add(value.Capacity.Lifetime + time.Nanosecond)
			refreshRunLifetimeFingerprint(value)
		}, kind: isolation.ErrCapacityExceeded},
		{name: "over trusted maximum", mutate: func(value *isolation.PreMutationInput) {
			value.Capacity.Lifetime = policy.RunLimits.MaxLifetime
			refreshCapacityFingerprint(&value.Capacity)
			value.RunLifetime.ExpiresAt = authorizationNow().Add(policy.RunLimits.MaxLifetime + time.Nanosecond)
			refreshRunLifetimeFingerprint(value)
		}, kind: isolation.ErrCapacityExceeded},
		{name: "wrong run", mutate: func(value *isolation.PreMutationInput) {
			value.RunLifetime.RunID = "run2"
			refreshRunLifetimeFingerprint(value)
		}, kind: isolation.ErrUnsafeFirewall},
		{name: "wrong plan", mutate: func(value *isolation.PreMutationInput) {
			value.RunLifetime.Plan.ID = "plan-fedcba9876543210"
			refreshRunLifetimeFingerprint(value)
		}, kind: isolation.ErrUnsafeFirewall},
		{name: "wrong operation", mutate: func(value *isolation.PreMutationInput) {
			value.RunLifetime.OperationID = "op-fedcba9876543210"
			refreshRunLifetimeFingerprint(value)
		}, kind: isolation.ErrUnsafeFirewall},
		{name: "wrong revocation", mutate: func(value *isolation.PreMutationInput) {
			value.RunLifetime.RevocationWorkflowID = "WF-ACC-03"
		}, kind: isolation.ErrUnsafeFirewall},
		{name: "stale rule after reused run ID", mutate: func(value *isolation.PreMutationInput) {
			value.RunLifetime.RecordGeneration++
			// Deliberately retain the earlier rule fingerprint.
		}, kind: isolation.ErrUnsafeFirewall},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validPreMutationInput()
			test.mutate(&input)
			if _, err := isolation.AuthorizePreMutation(policy, input, authorizationNow()); !errors.Is(err, test.kind) {
				t.Fatalf("AuthorizePreMutation() error = %v; want %v", err, test.kind)
			}
		})
	}
}

func TestRunLifetimeAllowsExactConfiguredBoundaryAndCannotChangeAtRevalidation(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	atBoundary := validPreMutationInput()
	atBoundary.Capacity.Lifetime = policy.RunLimits.MaxLifetime
	refreshCapacityFingerprint(&atBoundary.Capacity)
	atBoundary.RunLifetime.CreatedAt = atBoundary.Freshness.ObservedAt
	atBoundary.RunLifetime.ExpiresAt = atBoundary.Freshness.ObservedAt.Add(policy.RunLimits.MaxLifetime)
	refreshRunLifetimeFingerprint(&atBoundary)
	decision, err := isolation.AuthorizePreMutation(policy, atBoundary, authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation(exact lifetime boundary) unexpected error: %v", err)
	}
	exactWindow := validPreMutationInput()
	exactWindow.RunLifetime.ExpiresAt = authorizationNow().Add(policy.FirewallMutationWindow)
	refreshRunLifetimeFingerprint(&exactWindow)
	if _, err := isolation.AuthorizePreMutation(policy, exactWindow, authorizationNow()); err != nil {
		t.Fatalf("AuthorizePreMutation(exact remaining mutation window) unexpected error: %v", err)
	}
	laterStep := validPreMutationInput()
	laterStep.Operation.StepID = "create-test-vm"
	laterStep.Operation.Attempt = 2
	if _, err := isolation.AuthorizePreMutation(policy, laterStep, authorizationNow()); err != nil {
		t.Fatalf("AuthorizePreMutation(later step in owning operation) unexpected error: %v", err)
	}

	fresh := atBoundary
	fresh.Targets = append([]isolation.MutationTarget(nil), atBoundary.Targets...)
	fresh.FirewallRules = cloneFirewallRulesForTest(atBoundary.FirewallRules)
	fresh.Freshness.ObservedAt = fresh.Freshness.ObservedAt.Add(45 * time.Second)
	if _, err := isolation.RevalidatePreMutation(decision, policy, fresh, revalidationNow()); err != nil {
		t.Fatalf("RevalidatePreMutation(exact lifetime boundary) unexpected error: %v", err)
	}

	changed := fresh
	changed.FirewallRules = cloneFirewallRulesForTest(fresh.FirewallRules)
	changed.RunLifetime.RecordGeneration++
	refreshRunLifetimeFingerprint(&changed)
	if _, err := isolation.RevalidatePreMutation(decision, policy, changed, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(changed lifetime record) error = %v; want ErrProofMismatch", err)
	}
	changedExpiry := fresh
	changedExpiry.FirewallRules = cloneFirewallRulesForTest(fresh.FirewallRules)
	changedExpiry.RunLifetime.ExpiresAt = changedExpiry.RunLifetime.ExpiresAt.Add(-time.Second)
	refreshRunLifetimeFingerprint(&changedExpiry)
	if _, err := isolation.RevalidatePreMutation(decision, policy, changedExpiry, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(changed lifetime expiry) error = %v; want ErrProofMismatch", err)
	}
	createdAfterObservation := fresh
	createdAfterObservation.FirewallRules = cloneFirewallRulesForTest(fresh.FirewallRules)
	createdAfterObservation.RunLifetime.CreatedAt = createdAfterObservation.Freshness.ObservedAt.Add(time.Nanosecond)
	refreshRunLifetimeFingerprint(&createdAfterObservation)
	if _, err := isolation.RevalidatePreMutation(decision, policy, createdAfterObservation, revalidationNow()); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(lifetime created after fresh observation) error = %v; want ErrStaleProof", err)
	}
}

func TestPreMutationRequiresTrustedRemainingFirewallWindow(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*isolation.PreMutationPolicy, *isolation.PreMutationInput)
		kind   error
	}{
		{name: "zero policy window", mutate: func(policy *isolation.PreMutationPolicy, _ *isolation.PreMutationInput) {
			policy.FirewallMutationWindow = 0
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "over planned lifetime", mutate: func(policy *isolation.PreMutationPolicy, input *isolation.PreMutationInput) {
			policy.FirewallMutationWindow = input.Capacity.Lifetime + time.Nanosecond
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "over policy maximum", mutate: func(policy *isolation.PreMutationPolicy, _ *isolation.PreMutationInput) {
			policy.FirewallMutationWindow = policy.RunLimits.MaxLifetime + time.Nanosecond
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "one nanosecond short", mutate: func(policy *isolation.PreMutationPolicy, input *isolation.PreMutationInput) {
			input.RunLifetime.ExpiresAt = authorizationNow().Add(policy.FirewallMutationWindow - time.Nanosecond)
			refreshRunLifetimeFingerprint(input)
		}, kind: isolation.ErrStaleProof},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			policy := validPreMutationPolicy()
			input := validPreMutationInput()
			test.mutate(&policy, &input)
			if _, err := isolation.AuthorizePreMutation(policy, input, authorizationNow()); !errors.Is(err, test.kind) {
				t.Fatalf("AuthorizePreMutation() error = %v; want %v", err, test.kind)
			}
		})
	}

	policy := validPreMutationPolicy()
	input := validPreMutationInput()
	input.RunLifetime.ExpiresAt = authorizationNow().Add(90 * time.Second)
	refreshRunLifetimeFingerprint(&input)
	decision, err := isolation.AuthorizePreMutation(policy, input, authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	fresh := input
	fresh.Freshness.ObservedAt = input.Freshness.ObservedAt.Add(45 * time.Second)
	nearExpiry := input.RunLifetime.ExpiresAt.Add(-policy.FirewallMutationWindow).Add(time.Nanosecond)
	if _, err := isolation.RevalidatePreMutation(decision, policy, fresh, nearExpiry); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(remaining window elapsed) error = %v; want ErrStaleProof", err)
	}
}

func TestPreMutationDecisionRejectsStaleSwappedAndExpiredEvidence(t *testing.T) {
	t.Parallel()

	policy := validPreMutationPolicy()
	decision, err := isolation.AuthorizePreMutation(policy, validPreMutationInput(), authorizationNow())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	if _, err := isolation.RevalidatePreMutation(decision, policy, validPreMutationInput(), revalidationNow()); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(reused observation) error = %v; want ErrStaleProof", err)
	}
	expired := freshPreMutationInput()
	if _, err := isolation.RevalidatePreMutation(decision, policy, expired, expired.Freshness.ValidUntil); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(expired) error = %v; want ErrStaleProof", err)
	}
	extended := freshPreMutationInput()
	extended.Freshness.ValidUntil = extended.Freshness.ValidUntil.Add(time.Second)
	if _, err := isolation.RevalidatePreMutation(decision, policy, extended, revalidationNow()); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(extended expiry) error = %v; want ErrStaleProof", err)
	}
	swapped := freshPreMutationInput()
	swapped.Capacity.Instances[0].Machine.MemoryMB++
	refreshCapacityFingerprint(&swapped.Capacity)
	if _, err := isolation.RevalidatePreMutation(decision, policy, swapped, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(changed capacity plan) error = %v; want ErrProofMismatch", err)
	}
	drifted := freshPreMutationInput()
	drifted.Freshness.Revision = strings.Repeat("c", 64)
	if _, err := isolation.RevalidatePreMutation(decision, policy, drifted, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(drift) error = %v; want ErrProofMismatch", err)
	}
	inventorySwap := policy
	inventorySwap.PermissionInventory.Version = "v2"
	if _, err := isolation.RevalidatePreMutation(decision, inventorySwap, freshPreMutationInput(), revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(inventory swap) error = %v; want ErrProofMismatch", err)
	}
	limitsSwap := policy
	limitsSwap.RunLimits.MaxMachine.VCPUs++
	if _, err := isolation.RevalidatePreMutation(decision, limitsSwap, freshPreMutationInput(), revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(limit swap) error = %v; want ErrProofMismatch", err)
	}
	windowSwap := policy
	windowSwap.FirewallMutationWindow += time.Second
	if _, err := isolation.RevalidatePreMutation(decision, windowSwap, freshPreMutationInput(), revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(mutation-window swap) error = %v; want ErrProofMismatch", err)
	}
	cidrSwap := policy
	cidrSwap.TestCIDR = "10.30.0.0/24"
	freshCIDR := freshPreMutationInput()
	freshCIDR.TestCIDR = cidrSwap.TestCIDR
	if _, err := isolation.RevalidatePreMutation(decision, cidrSwap, freshCIDR, revalidationNow()); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(configured CIDR swap) error = %v; want ErrProofMismatch", err)
	}
}

func TestGuardErrorsDoNotRenderDiscoveredValues(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-resource-name"
	resource := testTarget("ctrldb-"+marker, "run1")
	resource.Labels[config.LabelEnvironment] = "production"
	err := isolation.ValidateCleanupTargets(validCleanupPolicy(), []isolation.MutationTarget{resource})
	if !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("ValidateCleanupTargets() error = %v; want ErrUnsafeTarget", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("isolation error rendered a discovered resource name")
	}
}

func defaultLimits() isolation.RunLimits {
	return isolation.RunLimits{
		MaxMachine:             isolation.MachineShape{VCPUs: 4, MemoryMB: 16 * 1024},
		MaxDiskGiB:             250,
		MaxInstances:           2,
		MaxLifetime:            6 * time.Hour,
		MaxEstimatedCostMicros: 5_000_000,
	}
}

func validPreMutationInput() isolation.PreMutationInput {
	permissions := validPermissionProofInput()
	locks, expectedEnvironments := validLockProof()
	observedAt := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	instance := testResourceIdentity("ctrldb-test-run1-vm", isolation.ComputeInstanceKind, isolation.ResourceScopeZone, "asia-south1-a")
	disk := testResourceIdentity("ctrldb-test-run1-disk", isolation.ComputeDiskKind, isolation.ResourceScopeZone, "asia-south1-a")
	input := isolation.PreMutationInput{
		Operation: isolation.OperationBinding{OperationID: "op-0123456789abcdef", StepID: "create-test-resources", Attempt: 1},
		RunID:     "run1",
		Targets:   firewallTargets("run1"),
		Capacity: isolation.CapacityProofInput{
			Plan:      isolation.PlanIdentity{ID: "plan-0123456789abcdef", Hash: strings.Repeat("a", 64)},
			Instances: []isolation.PlannedInstance{{Identity: instance, RunID: "run1", Machine: isolation.MachineShape{VCPUs: 2, MemoryMB: 8 * 1024}}},
			Disks:     []isolation.PlannedDisk{{Identity: disk, RunID: "run1", SizeGiB: 100}},
			Lifetime:  time.Hour, EstimatedCostMicros: 1_000_000,
		},
		TestCIDR:                          "10.20.0.0/24",
		ProductionCIDRs:                   []string{"10.80.0.0/16"},
		ExpectedNonDisposableEnvironments: expectedEnvironments,
		Locks:                             locks,
		MutationPrincipal:                 operatorPrincipal(),
		Permissions:                       permissions,
		FirewallRules:                     validFirewallRules(),
		RunLifetime:                       validRunLifetimeContract("run1"),
		Freshness: isolation.EvidenceFreshness{
			Revision: strings.Repeat("b", 64), ObservedAt: observedAt,
			ValidUntil: observedAt.Add(4 * time.Minute),
		},
	}
	input.FirewallObservations = absentFirewallObservations(input.FirewallRules)
	refreshCapacityFingerprint(&input.Capacity)
	input.MutationIntents = validMutationIntents(input)
	return input
}

func freshPreMutationInput() isolation.PreMutationInput {
	input := validPreMutationInput()
	input.Freshness.ObservedAt = input.Freshness.ObservedAt.Add(45 * time.Second)
	return input
}

func authorizationNow() time.Time {
	return validPreMutationInput().Freshness.ObservedAt.Add(30 * time.Second)
}

func revalidationNow() time.Time {
	return validPreMutationInput().Freshness.ObservedAt.Add(90 * time.Second)
}

func validPreMutationPolicy() isolation.PreMutationPolicy {
	input := validPreMutationInput()
	permissions, err := isolation.PermissionInventoryFingerprint(input.Permissions.Expected)
	if err != nil {
		panic(err)
	}
	environments, err := isolation.NonDisposableEnvironmentInventoryFingerprint(input.ExpectedNonDisposableEnvironments)
	if err != nil {
		panic(err)
	}
	cidrs, err := isolation.ProductionCIDRInventoryFingerprint(input.ProductionCIDRs)
	if err != nil {
		panic(err)
	}
	return isolation.PreMutationPolicy{
		ProjectID:                "example-test-project",
		RunLimits:                defaultLimits(),
		TestCIDR:                 input.TestCIDR,
		FirewallMutationWindow:   time.Minute,
		TestOperatorPrincipal:    operatorPrincipal(),
		TestDestructivePrincipal: destructivePrincipal(),
		PermissionInventory:      isolation.PolicyInventoryPin{ID: "permission-inventory", Version: "v1", Fingerprint: permissions},
		NonDisposableEnvironmentInventory: isolation.PolicyInventoryPin{
			ID: "environment-inventory", Version: "v1", Fingerprint: environments,
		},
		ProductionCIDRInventory: isolation.PolicyInventoryPin{ID: "production-cidr-inventory", Version: "v1", Fingerprint: cidrs},
	}
}

func validCleanupPolicy() isolation.CleanupPolicy {
	return isolation.CleanupPolicy{ProjectID: "example-test-project"}
}

func refreshCapacityFingerprint(capacity *isolation.CapacityProofInput) {
	fingerprint, err := isolation.CapacitySnapshotFingerprint(*capacity)
	if err != nil {
		panic(err)
	}
	capacity.SnapshotFingerprint = fingerprint
}

func refreshPermissionInventory(policy *isolation.PreMutationPolicy, expected []isolation.PermissionObservation) {
	fingerprint, err := isolation.PermissionInventoryFingerprint(expected)
	if err != nil {
		panic(err)
	}
	policy.PermissionInventory.Fingerprint = fingerprint
}

func withoutFirewallCreatePermission(values []isolation.PermissionObservation) []isolation.PermissionObservation {
	filtered := make([]isolation.PermissionObservation, 0, len(values))
	for _, value := range values {
		if value.Permission != "compute.firewalls.create" {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func mutateFirewallCreatePermission(input *isolation.PreMutationInput, mutate func(*isolation.PermissionObservation)) {
	for index := range input.Permissions.Expected {
		if input.Permissions.Expected[index].Permission == "compute.firewalls.create" {
			mutate(&input.Permissions.Expected[index])
		}
	}
	for index := range input.Permissions.Observed {
		if input.Permissions.Observed[index].Permission == "compute.firewalls.create" {
			mutate(&input.Permissions.Observed[index])
		}
	}
}

func refreshRunLifetimeFingerprint(input *isolation.PreMutationInput) {
	fingerprint, err := isolation.RunLifetimeContractFingerprint(input.RunLifetime)
	if err != nil {
		panic(err)
	}
	for index := range input.FirewallRules {
		input.FirewallRules[index].LifetimeContractFingerprint = fingerprint
		description, descriptionErr := isolation.RunFirewallDescription(fingerprint)
		if descriptionErr != nil {
			panic(descriptionErr)
		}
		input.FirewallRules[index].Description = description
	}
	nodeTag, tagErr := isolation.RunNodeTag(fingerprint)
	if tagErr != nil {
		panic(tagErr)
	}
	for index := range input.FirewallRules {
		input.FirewallRules[index].TargetTags = []string{nodeTag}
		if input.FirewallRules[index].Purpose == isolation.FirewallPurposeInternalMongo {
			input.FirewallRules[index].SourceTags = []string{nodeTag}
		}
	}
	input.FirewallObservations = absentFirewallObservations(input.FirewallRules)
	input.MutationIntents = validMutationIntents(*input)
}

func validMutationIntents(input isolation.PreMutationInput) []isolation.MutationIntent {
	intents := make([]isolation.MutationIntent, 0, len(input.Targets))
	for _, target := range input.Targets {
		intent := isolation.MutationIntent{
			Action:                isolation.MutationActionComputeFirewallInsert,
			Target:                cloneMutationTargetForTest(target),
			RequiredPrincipalRole: isolation.TestPrincipalRoleOperator,
		}
		switch target.Identity.Kind {
		case isolation.ComputeFirewallKind:
			for _, firewall := range input.FirewallRules {
				if firewall.Identity.CanonicalKey == target.Identity.CanonicalKey {
					firewall := cloneFirewallRule(firewall)
					intent.Create.Firewall = &firewall
					break
				}
			}
		}
		intents = append(intents, intent)
	}
	return intents
}

func cloneMutationTargetForTest(target isolation.MutationTarget) isolation.MutationTarget {
	target.Labels = maps.Clone(target.Labels)
	return target
}

func cloneFirewallRulesForTest(rules []isolation.FirewallRule) []isolation.FirewallRule {
	cloned := make([]isolation.FirewallRule, len(rules))
	for index := range rules {
		cloned[index] = cloneFirewallRule(rules[index])
	}
	return cloned
}

func moveResourceProject(identity *isolation.ResourceIdentity, project string) {
	identity.Project = project
	if identity.Service == isolation.CloudResourceManagerServiceName && identity.Kind == isolation.CloudResourceManagerProjectKind {
		identity.Name = project
	}
	identity.CanonicalKey = mustCanonicalTargetKey(*identity)
}

func moveAllResourceProjects(input *isolation.PreMutationInput, project string) {
	for index := range input.Targets {
		moveResourceProject(&input.Targets[index].Identity, project)
	}
	for index := range input.Capacity.Instances {
		moveResourceProject(&input.Capacity.Instances[index].Identity, project)
	}
	for index := range input.Capacity.Disks {
		moveResourceProject(&input.Capacity.Disks[index].Identity, project)
	}
	for index := range input.FirewallRules {
		moveResourceProject(&input.FirewallRules[index].Identity, project)
		moveResourceProject(&input.FirewallRules[index].Network, project)
	}
	for index := range input.FirewallObservations {
		moveResourceProject(&input.FirewallObservations[index].Identity, project)
		if input.FirewallObservations[index].PresentRule != nil {
			moveResourceProject(&input.FirewallObservations[index].PresentRule.Identity, project)
			moveResourceProject(&input.FirewallObservations[index].PresentRule.Network, project)
		}
	}
	for index := range input.Permissions.Expected {
		moveResourceProject(&input.Permissions.Expected[index].Resource, project)
	}
	for index := range input.Permissions.Observed {
		moveResourceProject(&input.Permissions.Observed[index].Resource, project)
	}
	refreshCapacityFingerprint(&input.Capacity)
	input.MutationIntents = validMutationIntents(*input)
}

func testTarget(name, runID string) isolation.MutationTarget {
	return testTargetWithIdentity(testResourceIdentity(name, isolation.ComputeInstanceKind, isolation.ResourceScopeZone, "asia-south1-a"), runID)
}

func testResourceIdentity(name string, kind isolation.ResourceKind, scope isolation.ResourceScope, location string) isolation.ResourceIdentity {
	identity := isolation.ResourceIdentity{
		Project: "example-test-project", Service: isolation.ComputeServiceName,
		Kind: kind, Scope: scope, Location: location, Name: name,
	}
	identity.CanonicalKey = mustCanonicalTargetKey(identity)
	return identity
}

func testTargetWithIdentity(identity isolation.ResourceIdentity, runID string) isolation.MutationTarget {
	return isolation.MutationTarget{
		Identity: identity,
		Labels: map[string]string{
			config.LabelManagedBy: config.LabelManagedByValue, config.LabelEnvironment: config.TestEnvironmentLabel,
			config.LabelPurpose: config.TestResourcePurposeLabel, isolation.LabelRunID: runID,
		},
	}
}

func targetWithName(target isolation.MutationTarget, name string) isolation.MutationTarget {
	target.Identity.Name = name
	target.Identity.CanonicalKey = mustCanonicalTargetKey(target.Identity)
	return target
}

func mustCanonicalTargetKey(identity isolation.ResourceIdentity) string {
	name, err := isolation.CanonicalTargetKey(identity)
	if err != nil {
		panic(err)
	}
	return name
}

func validLockProof() ([]isolation.EnvironmentLock, []isolation.EnvironmentIdentity) {
	expected := []isolation.EnvironmentIdentity{{Environment: "production", Class: domain.EnvironmentProduction}}
	locks := []isolation.EnvironmentLock{
		{Environment: "production", Class: domain.EnvironmentProduction},
		{Environment: config.TestEnvironmentLabel, Class: domain.EnvironmentDisposable, RunID: "run1", Active: true, Holder: operatorPrincipal()},
	}
	return locks, expected
}

func operatorPrincipal() isolation.Principal {
	return isolation.Principal{
		Kind: isolation.PrincipalKindServiceAccount, Subject: "test-operator@example-test-project.iam.gserviceaccount.com",
	}
}

func destructivePrincipal() isolation.Principal {
	return isolation.Principal{
		Kind: isolation.PrincipalKindServiceAccount, Subject: "test-destructive@example-test-project.iam.gserviceaccount.com",
	}
}
