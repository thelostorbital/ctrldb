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
		Machine:  isolation.MachineShape{VCPUs: 2, MemoryMB: 8 * 1024},
		Lifetime: time.Hour,
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

func TestValidateMutationTargetsRequiresPrefixAndAllLabels(t *testing.T) {
	t.Parallel()

	valid := testResource("ctrldb-test-run1-vm")
	if err := isolation.ValidateMutationTargets([]config.GeneratedResource{valid}); err != nil {
		t.Fatalf("ValidateMutationTargets() unexpected error: %v", err)
	}

	tests := []struct {
		name     string
		resource config.GeneratedResource
	}{
		{name: "production prefix", resource: config.GeneratedResource{Name: "ctrldb-production-vm", Labels: valid.Labels}},
		{name: "missing labels", resource: config.GeneratedResource{Name: valid.Name, Labels: map[string]string{}}},
		{name: "production label", resource: config.GeneratedResource{Name: valid.Name, Labels: map[string]string{
			config.LabelManagedBy: config.LabelManagedByValue, config.LabelEnvironment: "production", config.LabelPurpose: config.TestResourcePurposeLabel,
		}}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := isolation.ValidateMutationTargets([]config.GeneratedResource{test.resource})
			if !errors.Is(err, isolation.ErrUnsafeTarget) {
				t.Fatalf("ValidateMutationTargets() error = %v; want ErrUnsafeTarget", err)
			}
		})
	}
}

func TestSelectExpiredTargetsFailsClosedAndReturnsDetachedSortedResults(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	candidates := []isolation.ExpirableTarget{
		{Resource: testResource("ctrldb-test-run1-z"), CreatedAt: now.Add(-7 * time.Hour)},
		{Resource: testResource("ctrldb-test-run1-young"), CreatedAt: now.Add(-time.Hour)},
		{Resource: testResource("ctrldb-test-run1-a"), CreatedAt: now.Add(-6 * time.Hour)},
	}
	selected, err := isolation.SelectExpiredTargets(candidates, now, 6*time.Hour)
	if err != nil {
		t.Fatalf("SelectExpiredTargets() unexpected error: %v", err)
	}
	wantNames := []string{"ctrldb-test-run1-a", "ctrldb-test-run1-z"}
	gotNames := []string{selected[0].Resource.Name, selected[1].Resource.Name}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("SelectExpiredTargets() names = %v; want %v", gotNames, wantNames)
	}

	selected[0].Resource.Labels[config.LabelPurpose] = "changed"
	if got := candidates[2].Resource.Labels[config.LabelPurpose]; got != config.TestResourcePurposeLabel {
		t.Fatalf("SelectExpiredTargets() result aliases caller labels: got %q", got)
	}

	unsafeYoung := []isolation.ExpirableTarget{{
		Resource:  config.GeneratedResource{Name: "ctrldb-test-run2-young", Labels: map[string]string{}},
		CreatedAt: now.Add(-time.Minute),
	}}
	if _, err := isolation.SelectExpiredTargets(unsafeYoung, now, 6*time.Hour); !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("SelectExpiredTargets(unsafe young target) error = %v; want ErrUnsafeTarget", err)
	}
}

func TestSelectExpiredTargetsRejectsInvalidTimeBoundaries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	valid := []isolation.ExpirableTarget{{Resource: testResource("ctrldb-test-run1-vm"), CreatedAt: now.Add(-time.Hour)}}
	if _, err := isolation.SelectExpiredTargets(valid, time.Time{}, time.Hour); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("SelectExpiredTargets(zero now) error = %v; want ErrInvalidGuardInput", err)
	}
	if _, err := isolation.SelectExpiredTargets(valid, now, 0); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("SelectExpiredTargets(zero lifetime) error = %v; want ErrInvalidGuardInput", err)
	}
	future := []isolation.ExpirableTarget{{Resource: testResource("ctrldb-test-run1-vm"), CreatedAt: now.Add(time.Second)}}
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

func TestValidateHarnessLocksRejectsHarnessHeldNonDisposableLock(t *testing.T) {
	t.Parallel()

	const harness = "test-runner"
	for _, class := range []domain.EnvironmentClass{
		domain.EnvironmentProduction,
		domain.EnvironmentStaging,
		domain.EnvironmentRehearsal,
	} {
		err := isolation.ValidateHarnessLocks([]isolation.EnvironmentLock{{
			Environment: string(class), Class: class, Holder: harness,
		}}, harness)
		if !errors.Is(err, isolation.ErrNonDisposableLock) {
			t.Errorf("ValidateHarnessLocks(%s) error = %v; want ErrNonDisposableLock", class, err)
		}
	}
}

func TestValidateHarnessLocksAllowsDisposableOrOtherHolder(t *testing.T) {
	t.Parallel()

	locks := []isolation.EnvironmentLock{
		{Environment: "production", Class: domain.EnvironmentProduction, Holder: "operator"},
		{Environment: "test", Class: domain.EnvironmentDisposable, Holder: "test-runner"},
	}
	if err := isolation.ValidateHarnessLocks(locks, "test-runner"); err != nil {
		t.Fatalf("ValidateHarnessLocks() unexpected error: %v", err)
	}

	if err := isolation.ValidateHarnessLocks(locks, ""); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(empty holder) error = %v; want ErrInvalidGuardInput", err)
	}
	duplicate := append(locks, isolation.EnvironmentLock{Environment: "production", Class: domain.EnvironmentProduction})
	if err := isolation.ValidateHarnessLocks(duplicate, "test-runner"); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateHarnessLocks(duplicate) error = %v; want ErrInvalidGuardInput", err)
	}
	for _, invalid := range []isolation.EnvironmentLock{
		{Class: domain.EnvironmentProduction},
		{Environment: "unknown", Class: "unknown"},
	} {
		if err := isolation.ValidateHarnessLocks([]isolation.EnvironmentLock{invalid}, "test-runner"); !errors.Is(err, isolation.ErrInvalidGuardInput) {
			t.Fatalf("ValidateHarnessLocks(invalid lock) error = %v; want ErrInvalidGuardInput", err)
		}
	}
}

func TestGuardErrorsDoNotRenderDiscoveredValues(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-resource-name"
	resource := config.GeneratedResource{
		Name: "ctrldb-" + marker,
		Labels: map[string]string{
			config.LabelManagedBy:   config.LabelManagedByValue,
			config.LabelEnvironment: "production",
		},
	}
	err := isolation.ValidateMutationTargets([]config.GeneratedResource{resource})
	if !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("ValidateMutationTargets() error = %v; want ErrUnsafeTarget", err)
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

func testResource(name string) config.GeneratedResource {
	return config.GeneratedResource{
		Name: name,
		Labels: map[string]string{
			config.LabelManagedBy:   config.LabelManagedByValue,
			config.LabelEnvironment: config.TestEnvironmentLabel,
			config.LabelPurpose:     config.TestResourcePurposeLabel,
		},
	}
}
