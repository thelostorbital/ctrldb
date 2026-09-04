// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation_test

import (
	"errors"
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
	if err := isolation.ValidateCleanupTargets([]isolation.MutationTarget{valid}); err != nil {
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

			err := isolation.ValidateCleanupTargets([]isolation.MutationTarget{test.resource})
			if !errors.Is(err, isolation.ErrUnsafeTarget) {
				t.Fatalf("ValidateCleanupTargets() error = %v; want ErrUnsafeTarget", err)
			}
		})
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

func TestSelectExpiredTargetsFailsClosedAndReturnsDetachedSortedResults(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	candidates := []isolation.ExpirableTarget{
		{Target: testTarget("ctrldb-test-run1-z", "run1"), CreatedAt: now.Add(-7 * time.Hour)},
		{Target: testTarget("ctrldb-test-run1-young", "run1"), CreatedAt: now.Add(-time.Hour)},
		{Target: testTarget("ctrldb-test-run1-a", "run1"), CreatedAt: now.Add(-6 * time.Hour)},
	}
	selected, err := isolation.SelectExpiredTargets(candidates, now, 6*time.Hour)
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
	if _, err := isolation.SelectExpiredTargets(unsafeYoung, now, 6*time.Hour); !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("SelectExpiredTargets(unsafe young target) error = %v; want ErrUnsafeTarget", err)
	}
}

func TestSelectExpiredTargetsRejectsInvalidTimeBoundaries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	valid := []isolation.ExpirableTarget{{Target: testTarget("ctrldb-test-run1-vm", "run1"), CreatedAt: now.Add(-time.Hour)}}
	if _, err := isolation.SelectExpiredTargets(valid, time.Time{}, time.Hour); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("SelectExpiredTargets(zero now) error = %v; want ErrInvalidGuardInput", err)
	}
	if _, err := isolation.SelectExpiredTargets(valid, now, 0); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("SelectExpiredTargets(zero lifetime) error = %v; want ErrInvalidGuardInput", err)
	}
	future := []isolation.ExpirableTarget{{Target: testTarget("ctrldb-test-run1-vm", "run1"), CreatedAt: now.Add(time.Second)}}
	if _, err := isolation.SelectExpiredTargets(future, now, time.Hour); !errors.Is(err, isolation.ErrInvalidGuardInput) {
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

	for _, cidr := range []string{"10.20.0.0/24", "172.16.0.0/16", "192.168.50.0/24"} {
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
	if err := isolation.ValidateHarnessLocks(locks, expected, "run1", harnessPrincipal()); err != nil {
		t.Fatalf("ValidateHarnessLocks() unexpected error: %v", err)
	}
	if err := isolation.ValidateHarnessLocks(locks, expected, "run1", isolation.Principal{}); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(empty holder) error = %v; want ErrInvalidGuardInput", err)
	}
	activeProduction := append([]isolation.EnvironmentLock(nil), locks...)
	activeProduction[0].Active = true
	activeProduction[0].Holder = operatorPrincipal()
	if err := isolation.ValidateHarnessLocks(activeProduction, expected, "run1", harnessPrincipal()); err != nil {
		t.Fatalf("ValidateHarnessLocks(active production lock held by operator) unexpected error: %v", err)
	}
	inactiveWithHolder := append([]isolation.EnvironmentLock(nil), locks...)
	inactiveWithHolder[0].Holder = operatorPrincipal()
	if err := isolation.ValidateHarnessLocks(inactiveWithHolder, expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(inactive with holder) error = %v; want ErrInvalidGuardInput", err)
	}
	invalidActive := append([]isolation.EnvironmentLock(nil), locks...)
	invalidActive[0].Active = true
	if err := isolation.ValidateHarnessLocks(invalidActive, expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(active without holder) error = %v; want ErrInvalidGuardInput", err)
	}
	aliasHolder := append([]isolation.EnvironmentLock(nil), activeProduction...)
	aliasHolder[0].Holder.Subject = "user:" + aliasHolder[0].Holder.Subject
	if err := isolation.ValidateHarnessLocks(aliasHolder, expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(alias holder) error = %v; want ErrInvalidGuardInput", err)
	}
	duplicate := append(append([]isolation.EnvironmentLock(nil), locks...), locks[0])
	if err := isolation.ValidateHarnessLocks(duplicate, expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(duplicate) error = %v; want ErrInvalidGuardInput", err)
	}
	if err := isolation.ValidateHarnessLocks(locks[:1], expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrRunLockNotHeld) {
		t.Fatalf("ValidateHarnessLocks(missing run lock) error = %v; want ErrRunLockNotHeld", err)
	}
	lost := append([]isolation.EnvironmentLock(nil), locks...)
	lost[1].Holder = isolation.Principal{Kind: isolation.PrincipalKindServiceAccount, Subject: "other-runner@example-test-project.iam.gserviceaccount.com"}
	if err := isolation.ValidateHarnessLocks(lost, expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrRunLockNotHeld) {
		t.Fatalf("ValidateHarnessLocks(lock loss) error = %v; want ErrRunLockNotHeld", err)
	}
	absentRunLock := append([]isolation.EnvironmentLock(nil), locks...)
	absentRunLock[1].Active = false
	absentRunLock[1].Holder = isolation.Principal{}
	if err := isolation.ValidateHarnessLocks(absentRunLock, expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrRunLockNotHeld) {
		t.Fatalf("ValidateHarnessLocks(absent run lock) error = %v; want ErrRunLockNotHeld", err)
	}
	missingProduction := []isolation.EnvironmentLock{locks[1]}
	if err := isolation.ValidateHarnessLocks(missingProduction, expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(missing environment) error = %v; want ErrInvalidGuardInput", err)
	}
	unexpected := append(append([]isolation.EnvironmentLock(nil), locks...), isolation.EnvironmentLock{
		Environment: "staging", Class: domain.EnvironmentStaging,
	})
	if err := isolation.ValidateHarnessLocks(unexpected, expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(unexpected environment) error = %v; want ErrInvalidGuardInput", err)
	}
	heldProduction := append([]isolation.EnvironmentLock(nil), locks...)
	heldProduction[0].Active = true
	heldProduction[0].Holder = harnessPrincipal()
	if err := isolation.ValidateHarnessLocks(heldProduction, expected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrNonDisposableLock) {
		t.Fatalf("ValidateHarnessLocks(non-disposable holder) error = %v; want ErrNonDisposableLock", err)
	}
	ambiguousExpected := append(append([]isolation.EnvironmentIdentity(nil), expected...), isolation.EnvironmentIdentity{
		Environment: "production", Class: domain.EnvironmentStaging,
	})
	if err := isolation.ValidateHarnessLocks(locks, ambiguousExpected, "run1", harnessPrincipal()); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(ambiguous expectation) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestPreMutationGateRequiresEveryLocalProofFamily(t *testing.T) {
	t.Parallel()

	input := validPreMutationInput()
	decision, err := isolation.AuthorizePreMutation(input)
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	targets, err := isolation.RevalidatePreMutation(decision, freshPreMutationInput())
	if err != nil {
		t.Fatalf("RevalidatePreMutation() unexpected error: %v", err)
	}
	targets[0].Labels[config.LabelPurpose] = "changed"
	if input.Targets[0].Labels[config.LabelPurpose] != config.TestResourcePurposeLabel {
		t.Fatal("RevalidatePreMutation() targets alias authorization input")
	}

	tests := []struct {
		name   string
		mutate func(*isolation.PreMutationInput)
		kind   error
	}{
		{name: "selector proof", mutate: func(value *isolation.PreMutationInput) { value.RunID = "different" }, kind: isolation.ErrUnsafeTarget},
		{name: "capacity proof", mutate: func(value *isolation.PreMutationInput) { value.Capacity.Instances[0].Machine.VCPUs = 8 }, kind: isolation.ErrCapacityExceeded},
		{name: "network proof", mutate: func(value *isolation.PreMutationInput) { value.TestCIDR = "10.80.1.0/24" }, kind: isolation.ErrNetworkOverlap},
		{name: "lock proof", mutate: func(value *isolation.PreMutationInput) {
			value.Locks[0].Active = true
			value.Locks[0].Holder = value.HarnessPrincipal
		}, kind: isolation.ErrNonDisposableLock},
		{name: "permission proof", mutate: func(value *isolation.PreMutationInput) { value.Permissions.Observed = nil }, kind: isolation.ErrPermissionProof},
		{name: "firewall proof", mutate: func(value *isolation.PreMutationInput) { value.FirewallRules = value.FirewallRules[:1] }, kind: isolation.ErrUnsafeFirewall},
		{name: "freshness proof", mutate: func(value *isolation.PreMutationInput) { value.Freshness.ValidUntil = value.Freshness.ObservedAt }, kind: isolation.ErrStaleProof},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validPreMutationInput()
			test.mutate(&value)
			if _, err := isolation.AuthorizePreMutation(value); !errors.Is(err, test.kind) {
				t.Fatalf("AuthorizePreMutation() error = %v; want %v", err, test.kind)
			}
		})
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
			input.Targets[0] = testTarget("ctrldb-test-run1-other", "run1")
		}, kind: isolation.ErrInvalidGuardInput},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validPreMutationInput()
			test.mutate(&input)
			if _, err := isolation.AuthorizePreMutation(input); !errors.Is(err, test.kind) {
				t.Fatalf("AuthorizePreMutation() error = %v; want %v", err, test.kind)
			}
		})
	}

	input := validPreMutationInput()
	input.Targets = []isolation.MutationTarget{testTargetWithIdentity(testResourceIdentity(
		"ctrldb-test-run1-firewall", isolation.ResourceKind("firewalls"), isolation.ResourceScopeGlobal, "global",
	), "run1")}
	if _, err := isolation.AuthorizePreMutation(input); err != nil {
		t.Fatalf("AuthorizePreMutation(firewall-only mutation with planned instance capacity) unexpected error: %v", err)
	}
}

func TestPreMutationDecisionRejectsStaleSwappedAndExpiredEvidence(t *testing.T) {
	t.Parallel()

	decision, err := isolation.AuthorizePreMutation(validPreMutationInput())
	if err != nil {
		t.Fatalf("AuthorizePreMutation() unexpected error: %v", err)
	}
	if _, err := isolation.RevalidatePreMutation(decision, validPreMutationInput()); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(reused observation) error = %v; want ErrStaleProof", err)
	}
	expired := freshPreMutationInput()
	expired.Freshness.CheckedAt = validPreMutationInput().Freshness.ValidUntil
	if _, err := isolation.RevalidatePreMutation(decision, expired); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(expired) error = %v; want ErrStaleProof", err)
	}
	extended := freshPreMutationInput()
	extended.Freshness.ValidUntil = extended.Freshness.ValidUntil.Add(time.Second)
	if _, err := isolation.RevalidatePreMutation(decision, extended); !errors.Is(err, isolation.ErrStaleProof) {
		t.Fatalf("RevalidatePreMutation(extended expiry) error = %v; want ErrStaleProof", err)
	}
	swapped := freshPreMutationInput()
	swapped.Targets[0].Identity.Project = "another-test-project"
	swapped.Targets[0].Identity.CanonicalKey = mustCanonicalTargetKey(swapped.Targets[0].Identity)
	swapped.Capacity.Instances[0].Identity = swapped.Targets[0].Identity
	if _, err := isolation.RevalidatePreMutation(decision, swapped); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(swapped target) error = %v; want ErrProofMismatch", err)
	}
	drifted := freshPreMutationInput()
	drifted.Freshness.Revision = strings.Repeat("c", 64)
	if _, err := isolation.RevalidatePreMutation(decision, drifted); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(drift) error = %v; want ErrProofMismatch", err)
	}
	inventorySwap := freshPreMutationInput()
	inventorySwap.Permissions.Inventory.Version = "v2"
	if _, err := isolation.RevalidatePreMutation(decision, inventorySwap); !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("RevalidatePreMutation(inventory swap) error = %v; want ErrProofMismatch", err)
	}
}

func TestGuardErrorsDoNotRenderDiscoveredValues(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-resource-name"
	resource := testTarget("ctrldb-"+marker, "run1")
	resource.Labels[config.LabelEnvironment] = "production"
	err := isolation.ValidateCleanupTargets([]isolation.MutationTarget{resource})
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
	return isolation.PreMutationInput{
		RunID:   "run1",
		Targets: []isolation.MutationTarget{testTargetWithIdentity(instance, "run1")},
		Capacity: isolation.CapacityProofInput{
			PlanFingerprint: strings.Repeat("a", 64),
			Limits:          defaultLimits(),
			Instances:       []isolation.PlannedInstance{{Identity: instance, RunID: "run1", Machine: isolation.MachineShape{VCPUs: 2, MemoryMB: 8 * 1024}}},
			Disks:           []isolation.PlannedDisk{{Identity: disk, RunID: "run1", SizeGiB: 100}},
			Lifetime:        time.Hour, EstimatedCostMicros: 1_000_000,
		},
		TestCIDR:                          "10.20.0.0/24",
		ProductionCIDRs:                   []string{"10.80.0.0/16"},
		ExpectedNonDisposableEnvironments: expectedEnvironments,
		Locks:                             locks,
		HarnessPrincipal:                  harnessPrincipal(),
		Permissions:                       permissions,
		FirewallRules:                     validFirewallRules(),
		Freshness: isolation.EvidenceFreshness{
			Revision: strings.Repeat("b", 64), ObservedAt: observedAt,
			ValidUntil: observedAt.Add(4 * time.Minute), CheckedAt: observedAt,
		},
	}
}

func freshPreMutationInput() isolation.PreMutationInput {
	input := validPreMutationInput()
	input.Freshness.ObservedAt = input.Freshness.ObservedAt.Add(time.Second)
	input.Freshness.CheckedAt = input.Freshness.ObservedAt
	return input
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
		{Environment: config.TestEnvironmentLabel, Class: domain.EnvironmentDisposable, RunID: "run1", Active: true, Holder: harnessPrincipal()},
	}
	return locks, expected
}

func harnessPrincipal() isolation.Principal {
	return isolation.Principal{
		Kind: isolation.PrincipalKindServiceAccount, Subject: "test-runner@example-test-project.iam.gserviceaccount.com",
	}
}

func operatorPrincipal() isolation.Principal {
	return isolation.Principal{Kind: isolation.PrincipalKindUser, Subject: "operator@example.test"}
}
