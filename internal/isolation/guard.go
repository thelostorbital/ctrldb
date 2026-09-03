// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package isolation contains fail-closed, I/O-free guards for disposable test
// infrastructure. Cloud adapters must pass discovered state through these
// guards before issuing a mutation.
package isolation

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
)

var (
	// ErrInvalidGuardInput marks malformed or incomplete discovery input.
	ErrInvalidGuardInput = errors.New("invalid isolation guard input")
	// ErrUnsafeTarget marks a resource that is not unambiguously disposable.
	ErrUnsafeTarget = errors.New("unsafe isolation target")
	// ErrCapacityExceeded marks a run request outside its configured caps.
	ErrCapacityExceeded = errors.New("isolation capacity exceeded")
	// ErrNetworkOverlap marks a test CIDR that is public or intersects another
	// network supplied by discovery.
	ErrNetworkOverlap = errors.New("unsafe isolation network")
	// ErrNonDisposableLock marks the harness as the holder of an active lock for
	// an environment outside the disposable class.
	ErrNonDisposableLock = errors.New("non-disposable lock held by test harness")
)

var testTagPattern = regexp.MustCompile(`^ctrldb-test-[a-z0-9](?:[a-z0-9-]{0,49}[a-z0-9])?$`)

// MachineShape is the live numeric shape resolved for a GCP machine type.
// Comparing dimensions avoids inventing an ordering across machine families.
type MachineShape struct {
	VCPUs    int
	MemoryMB int64
}

// RunLimits is the numeric form of the manifest's test-isolation caps. Cost is
// represented in micro-USD; adapters must round estimates upward before use.
type RunLimits struct {
	MaxMachine             MachineShape
	MaxDiskGiB             int64
	MaxInstances           int
	MaxLifetime            time.Duration
	MaxEstimatedCostMicros int64
}

// RunRequest is the maximum capacity a test plan can consume at any point.
type RunRequest struct {
	Machine             MachineShape
	DiskGiB             int64
	Instances           int
	Lifetime            time.Duration
	EstimatedCostMicros int64
}

// ValidateRunRequest fails closed when resolved capacity or cost exceeds any
// configured test cap.
func ValidateRunRequest(limits RunLimits, request RunRequest) error {
	if err := validateRunLimits(limits); err != nil {
		return err
	}
	if request.Machine.VCPUs <= 0 {
		return guardError(ErrInvalidGuardInput, "request.machine.vcpus", "must be positive")
	}
	if request.Machine.MemoryMB <= 0 {
		return guardError(ErrInvalidGuardInput, "request.machine.memoryMB", "must be positive")
	}
	if request.DiskGiB < 0 {
		return guardError(ErrInvalidGuardInput, "request.diskGiB", "must not be negative")
	}
	if request.Instances < 0 {
		return guardError(ErrInvalidGuardInput, "request.instances", "must not be negative")
	}
	if request.Lifetime <= 0 {
		return guardError(ErrInvalidGuardInput, "request.lifetime", "must be positive")
	}
	if request.EstimatedCostMicros < 0 {
		return guardError(ErrInvalidGuardInput, "request.estimatedCostMicros", "must not be negative")
	}

	checks := []struct {
		exceeded bool
		path     string
	}{
		{exceeded: request.Machine.VCPUs > limits.MaxMachine.VCPUs, path: "request.machine.vcpus"},
		{exceeded: request.Machine.MemoryMB > limits.MaxMachine.MemoryMB, path: "request.machine.memoryMB"},
		{exceeded: request.DiskGiB > limits.MaxDiskGiB, path: "request.diskGiB"},
		{exceeded: request.Instances > limits.MaxInstances, path: "request.instances"},
		{exceeded: request.Lifetime > limits.MaxLifetime, path: "request.lifetime"},
		{exceeded: request.EstimatedCostMicros > limits.MaxEstimatedCostMicros, path: "request.estimatedCostMicros"},
	}
	for _, check := range checks {
		if check.exceeded {
			return guardError(ErrCapacityExceeded, check.path, "exceeds configured cap")
		}
	}

	return nil
}

func validateRunLimits(limits RunLimits) error {
	checks := []struct {
		invalid bool
		path    string
		reason  string
	}{
		{invalid: limits.MaxMachine.VCPUs <= 0, path: "limits.maxMachine.vcpus", reason: "must be positive"},
		{invalid: limits.MaxMachine.MemoryMB <= 0, path: "limits.maxMachine.memoryMB", reason: "must be positive"},
		{invalid: limits.MaxDiskGiB <= 0, path: "limits.maxDiskGiB", reason: "must be positive"},
		{invalid: limits.MaxInstances <= 0, path: "limits.maxInstances", reason: "must be positive"},
		{invalid: limits.MaxLifetime <= 0, path: "limits.maxLifetime", reason: "must be positive"},
		{invalid: limits.MaxEstimatedCostMicros < 0, path: "limits.maxEstimatedCostMicros", reason: "must not be negative"},
	}
	for _, check := range checks {
		if check.invalid {
			return guardError(ErrInvalidGuardInput, check.path, check.reason)
		}
	}
	return nil
}

// ValidateMutationTargets requires both the reserved name prefix and all
// mandatory isolation labels on every resource selected for mutation.
func ValidateMutationTargets(resources []config.GeneratedResource) error {
	for index, resource := range resources {
		if !config.IsTestResource(resource) {
			return guardError(ErrUnsafeTarget, indexedField("targets", index), "does not have exact disposable identity")
		}
	}
	return nil
}

// ExpirableTarget is a disposable resource considered by the nightly wipe.
type ExpirableTarget struct {
	Resource  config.GeneratedResource
	CreatedAt time.Time
}

// SelectExpiredTargets returns a detached, name-sorted set whose age has
// reached maxLifetime. Any ambiguous candidate makes the entire selection
// fail; it is never silently skipped.
func SelectExpiredTargets(candidates []ExpirableTarget, now time.Time, maxLifetime time.Duration) ([]ExpirableTarget, error) {
	if now.IsZero() {
		return nil, guardError(ErrInvalidGuardInput, "now", "must not be zero")
	}
	if maxLifetime <= 0 {
		return nil, guardError(ErrInvalidGuardInput, "maxLifetime", "must be positive")
	}

	resources := make([]config.GeneratedResource, len(candidates))
	for index, candidate := range candidates {
		resources[index] = candidate.Resource
	}
	if err := ValidateMutationTargets(resources); err != nil {
		return nil, err
	}

	selected := make([]ExpirableTarget, 0, len(candidates))
	for index, candidate := range candidates {
		if candidate.CreatedAt.IsZero() || candidate.CreatedAt.After(now) {
			return nil, guardError(ErrInvalidGuardInput, indexedField("targets", index)+".createdAt", "must be a non-future timestamp")
		}
		if now.Sub(candidate.CreatedAt) >= maxLifetime {
			selected = append(selected, cloneExpirableTarget(candidate))
		}
	}
	sort.SliceStable(selected, func(i, j int) bool {
		return selected[i].Resource.Name < selected[j].Resource.Name
	})
	return selected, nil
}

// ValidateFirewallTags prevents a test rule from referencing any application
// or production network tag. Source tags are optional for CIDR-based rules;
// at least one target tag is mandatory.
func ValidateFirewallTags(sourceTags, targetTags []string) error {
	if len(targetTags) == 0 {
		return guardError(ErrInvalidGuardInput, "targetTags", "must not be empty")
	}
	if err := validateTestTags("sourceTags", sourceTags); err != nil {
		return err
	}
	return validateTestTags("targetTags", targetTags)
}

func validateTestTags(path string, tags []string) error {
	seen := make(map[string]struct{}, len(tags))
	for index, tag := range tags {
		itemPath := indexedField(path, index)
		if !testTagPattern.MatchString(tag) {
			return guardError(ErrUnsafeTarget, itemPath, "must use the reserved test namespace")
		}
		if _, exists := seen[tag]; exists {
			return guardError(ErrInvalidGuardInput, itemPath, "duplicates an earlier tag")
		}
		seen[tag] = struct{}{}
	}
	return nil
}

// ValidateNetworkCIDR requires a canonical private IPv4 test CIDR that does
// not overlap any subnet or other forbidden CIDR supplied by discovery.
func ValidateNetworkCIDR(testCIDR string, forbiddenCIDRs []string) error {
	testNetwork, err := parseCanonicalIPv4Prefix(testCIDR)
	if err != nil {
		return guardError(ErrInvalidGuardInput, "testCIDR", "must be a canonical IPv4 prefix")
	}
	if !isPrivateIPv4Prefix(testNetwork) {
		return guardError(ErrNetworkOverlap, "testCIDR", "must be contained in an RFC 1918 range")
	}

	for index, value := range forbiddenCIDRs {
		forbidden, err := parseCanonicalIPv4Prefix(value)
		if err != nil {
			return guardError(ErrInvalidGuardInput, indexedField("forbiddenCIDRs", index), "must be a canonical IPv4 prefix")
		}
		if prefixesOverlap(testNetwork, forbidden) {
			return guardError(ErrNetworkOverlap, indexedField("forbiddenCIDRs", index), "overlaps the test network")
		}
	}
	return nil
}

func parseCanonicalIPv4Prefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
		return netip.Prefix{}, ErrInvalidGuardInput
	}
	return prefix, nil
}

func isPrivateIPv4Prefix(prefix netip.Prefix) bool {
	privateRanges := [...]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	for _, privateRange := range privateRanges {
		if prefix.Bits() >= privateRange.Bits() && privateRange.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func prefixesOverlap(first, second netip.Prefix) bool {
	return first.Contains(second.Addr()) || second.Contains(first.Addr())
}

// EnvironmentLock is active lock state after expiry has been evaluated by the
// control-bucket adapter.
type EnvironmentLock struct {
	Environment string
	Class       domain.EnvironmentClass
	Holder      string
}

// ValidateHarnessLocks refuses a harness identity that holds any active lock
// outside the disposable class.
func ValidateHarnessLocks(locks []EnvironmentLock, harnessHolder string) error {
	if harnessHolder == "" {
		return guardError(ErrInvalidGuardInput, "harnessHolder", "must not be empty")
	}
	seen := make(map[string]struct{}, len(locks))
	for index, lock := range locks {
		path := indexedField("locks", index)
		if lock.Environment == "" || !lock.Class.Valid() {
			return guardError(ErrInvalidGuardInput, path, "must identify a valid environment")
		}
		if _, exists := seen[lock.Environment]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier environment")
		}
		seen[lock.Environment] = struct{}{}
		if lock.Holder == harnessHolder && lock.Class != domain.EnvironmentDisposable {
			return guardError(ErrNonDisposableLock, path, "is held by the test harness")
		}
	}
	return nil
}

func cloneExpirableTarget(target ExpirableTarget) ExpirableTarget {
	labels := make(map[string]string, len(target.Resource.Labels))
	for key, value := range target.Resource.Labels {
		labels[key] = value
	}
	target.Resource.Labels = labels
	return target
}

func indexedField(base string, index int) string {
	return fmt.Sprintf("%s[%d]", base, index)
}

func guardError(kind error, path, reason string) error {
	return fmt.Errorf("%w: %s %s", kind, path, reason)
}
