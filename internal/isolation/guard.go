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
	"strings"
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
	// ErrInvalidRunID marks a run identifier which cannot form an unambiguous
	// resource namespace.
	ErrInvalidRunID = errors.New("invalid isolation run ID")
)

var runIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

const maxRunIDLength = 32

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

// ValidateRunID accepts only a bounded lowercase identifier with single
// hyphen separators. The restriction keeps ctrldb-test-<runId>- an
// unambiguous namespace rather than a user-controlled prefix.
func ValidateRunID(runID string) error {
	if len(runID) == 0 || len(runID) > maxRunIDLength || !runIDPattern.MatchString(runID) {
		return guardError(ErrInvalidRunID, "runID", "must be a bounded lowercase hyphen-separated identifier")
	}
	return nil
}

// RunResourcePrefix returns the namespace which every mutation owned by one
// test run must use. The wider ctrldb-test- prefix is intentionally not
// returned here; it belongs only to cleanup discovery.
func RunResourcePrefix(runID string) (string, error) {
	if err := ValidateRunID(runID); err != nil {
		return "", err
	}
	return config.TestResourcePrefix + runID + "-", nil
}

// SelectRunMutationTargets validates and returns a detached, deterministically
// sorted set of resources owned by exactly one run. Duplicate resource names
// make the complete proof fail closed.
func SelectRunMutationTargets(runID string, resources []config.GeneratedResource) ([]config.GeneratedResource, error) {
	prefix, err := RunResourcePrefix(runID)
	if err != nil {
		return nil, err
	}
	selected := make([]config.GeneratedResource, 0, len(resources))
	seen := make(map[string]struct{}, len(resources))
	for index, resource := range resources {
		path := indexedField("targets", index)
		if !config.IsTestResource(resource) || !strings.HasPrefix(resource.Name, prefix) || len(resource.Name) == len(prefix) {
			return nil, guardError(ErrUnsafeTarget, path, "does not have exact run-scoped disposable identity")
		}
		if _, exists := seen[resource.Name]; exists {
			return nil, guardError(ErrInvalidGuardInput, path, "duplicates an earlier target")
		}
		seen[resource.Name] = struct{}{}
		selected = append(selected, cloneGeneratedResource(resource))
	}
	sort.SliceStable(selected, func(i, j int) bool { return selected[i].Name < selected[j].Name })
	return selected, nil
}

// ValidateCleanupTargets validates the global-prefix selector reserved for
// teardown and nightly cleanup. Run mutations must use
// SelectRunMutationTargets instead.
func ValidateCleanupTargets(resources []config.GeneratedResource) error {
	seen := make(map[string]struct{}, len(resources))
	for index, resource := range resources {
		path := indexedField("targets", index)
		if !config.IsTestResource(resource) {
			return guardError(ErrUnsafeTarget, path, "does not have exact disposable identity")
		}
		if _, exists := seen[resource.Name]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier target")
		}
		seen[resource.Name] = struct{}{}
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
	if err := ValidateCleanupTargets(resources); err != nil {
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

// PreMutationInput contains every local proof family required before a test
// harness operation can reach a provider mutation boundary.
type PreMutationInput struct {
	RunID               string
	Targets             []config.GeneratedResource
	Limits              RunLimits
	Request             RunRequest
	TestCIDR            string
	ProductionCIDRs     []string
	Locks               []EnvironmentLock
	HarnessHolder       string
	ExpectedPermissions []PermissionObservation
	ObservedPermissions []PermissionObservation
	FirewallRules       []FirewallRule
}

// PreMutationDecision is a detached authorization result. Callers may retain
// it without aliasing discovery-owned label maps.
type PreMutationDecision struct {
	Targets []config.GeneratedResource
}

// AuthorizePreMutation evaluates every local isolation proof before returning
// a usable decision. It performs no I/O and has no mutation capability.
func AuthorizePreMutation(input PreMutationInput) (PreMutationDecision, error) {
	if len(input.Targets) == 0 {
		return PreMutationDecision{}, guardError(ErrInvalidGuardInput, "targets", "must not be empty")
	}
	if len(input.ProductionCIDRs) == 0 {
		return PreMutationDecision{}, guardError(ErrInvalidGuardInput, "productionCIDRs", "must not be empty")
	}
	if len(input.Locks) == 0 {
		return PreMutationDecision{}, guardError(ErrInvalidGuardInput, "locks", "must not be empty")
	}
	targets, err := SelectRunMutationTargets(input.RunID, input.Targets)
	if err != nil {
		return PreMutationDecision{}, err
	}
	if err := ValidateRunRequest(input.Limits, input.Request); err != nil {
		return PreMutationDecision{}, err
	}
	if err := ValidateNetworkCIDR(input.TestCIDR, input.ProductionCIDRs); err != nil {
		return PreMutationDecision{}, err
	}
	if err := ValidateHarnessLocks(input.Locks, input.HarnessHolder); err != nil {
		return PreMutationDecision{}, err
	}
	if err := ValidatePermissionProof(input.ExpectedPermissions, input.ObservedPermissions); err != nil {
		return PreMutationDecision{}, err
	}
	if err := ValidateFirewallRules(input.FirewallRules, input.ProductionCIDRs); err != nil {
		return PreMutationDecision{}, err
	}
	return PreMutationDecision{Targets: targets}, nil
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
	target.Resource = cloneGeneratedResource(target.Resource)
	return target
}

func cloneGeneratedResource(resource config.GeneratedResource) config.GeneratedResource {
	labels := make(map[string]string, len(resource.Labels))
	for key, value := range resource.Labels {
		labels[key] = value
	}
	resource.Labels = labels
	return resource
}

func indexedField(base string, index int) string {
	return fmt.Sprintf("%s[%d]", base, index)
}

func guardError(kind error, path, reason string) error {
	return fmt.Errorf("%w: %s %s", kind, path, reason)
}
