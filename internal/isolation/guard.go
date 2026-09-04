// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package isolation contains fail-closed, I/O-free guards for disposable test
// infrastructure. Cloud adapters must pass discovered state through these
// guards before issuing a mutation.
package isolation

import (
	"crypto/sha256"
	"encoding/json"
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
	// ErrRunLockNotHeld marks missing or lost ownership of the run lock.
	ErrRunLockNotHeld = errors.New("test harness run lock not held")
	// ErrStaleProof marks expired or insufficiently fresh evidence.
	ErrStaleProof = errors.New("stale isolation proof")
	// ErrProofMismatch marks drift between authorization and mutation-boundary
	// revalidation.
	ErrProofMismatch = errors.New("isolation proof mismatch")
)

var runIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

var (
	projectIDPattern             = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	servicePattern               = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$`)
	resourceKindPattern          = regexp.MustCompile(`^[a-z][A-Za-z0-9]{0,62}$`)
	regionPattern                = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+[0-9]$`)
	zonePattern                  = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+[0-9]-[a-z]$`)
	resourceNamePattern          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?$`)
	environmentNamePattern       = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	userSubjectPattern           = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	serviceAccountSubjectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
)

const (
	maxRunIDLength              = 32
	LabelRunID                  = "run-id"
	MaxPreMutationProofLifetime = 5 * time.Minute
)

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
	if request.Instances <= 0 {
		return guardError(ErrInvalidGuardInput, "request.instances", "must be positive")
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

// ResourceScope makes provider location explicit so no mutation can inherit an
// ambient project, region, or zone.
type ResourceScope string

// ProviderService identifies an explicit provider API namespace.
type ProviderService string

// ResourceKind identifies the provider collection used by a mutation.
type ResourceKind string

const (
	ResourceScopeGlobal ResourceScope   = "global"
	ResourceScopeRegion ResourceScope   = "region"
	ResourceScopeZone   ResourceScope   = "zone"
	ComputeServiceName  ProviderService = "compute.googleapis.com"
	ComputeInstanceKind ResourceKind    = "instances"
	ComputeDiskKind     ResourceKind    = "disks"
)

// ResourceIdentity is the complete explicit identity a future provider adapter
// must consume without consulting ambient defaults. CanonicalKey is an
// internal comparison key, not a provider resource-name grammar.
type ResourceIdentity struct {
	Project      string
	Service      ProviderService
	Kind         ResourceKind
	Scope        ResourceScope
	Location     string
	Name         string
	CanonicalKey string
}

// MutationTarget binds full provider identity to the labels observed for that
// exact resource.
type MutationTarget struct {
	Identity ResourceIdentity
	Labels   map[string]string
}

// CanonicalTargetKey derives a synthetic internal comparison key from every
// explicit identity field. Adapters must consume the fields themselves and
// must not send this key to a provider API.
func CanonicalTargetKey(identity ResourceIdentity) (string, error) {
	if !projectIDPattern.MatchString(identity.Project) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.project", "must be a canonical explicit project ID")
	}
	if !servicePattern.MatchString(string(identity.Service)) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.service", "must be a canonical service name")
	}
	if !resourceKindPattern.MatchString(string(identity.Kind)) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.kind", "must be a canonical resource kind")
	}
	var scopePath string
	switch identity.Scope {
	case ResourceScopeGlobal:
		if identity.Location != "global" {
			return "", guardError(ErrInvalidGuardInput, "target.identity.location", "must equal global for global scope")
		}
		scopePath = "global"
	case ResourceScopeRegion:
		if !regionPattern.MatchString(identity.Location) {
			return "", guardError(ErrInvalidGuardInput, "target.identity.location", "must identify a canonical region")
		}
		scopePath = "regions/" + identity.Location
	case ResourceScopeZone:
		if !zonePattern.MatchString(identity.Location) {
			return "", guardError(ErrInvalidGuardInput, "target.identity.location", "must identify a canonical zone")
		}
		scopePath = "zones/" + identity.Location
	default:
		return "", guardError(ErrInvalidGuardInput, "target.identity.scope", "must be global, region, or zone")
	}
	if !resourceNamePattern.MatchString(identity.Name) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.name", "must be a canonical resource name")
	}
	return "ctrldb-target-key:v1|" + identity.Project + "|" + string(identity.Service) + "|" + scopePath + "|" + string(identity.Kind) + "|" + identity.Name, nil
}

// SelectRunMutationTargets validates and returns a detached, deterministically
// sorted set of exact resources owned by one run. The required run-id label
// closes variable-length prefix ambiguity; duplicate full identities fail.
func SelectRunMutationTargets(runID string, resources []MutationTarget) ([]MutationTarget, error) {
	prefix, err := RunResourcePrefix(runID)
	if err != nil {
		return nil, err
	}
	selected := make([]MutationTarget, 0, len(resources))
	seen := make(map[string]struct{}, len(resources))
	for index, resource := range resources {
		path := indexedField("targets", index)
		if err := validateMutationTarget(resource); err != nil {
			return nil, guardError(err, path, "has invalid full identity")
		}
		if !strings.HasPrefix(resource.Identity.Name, prefix) || len(resource.Identity.Name) == len(prefix) || resource.Labels[LabelRunID] != runID {
			return nil, guardError(ErrUnsafeTarget, path, "does not have exact run-scoped disposable identity")
		}
		if _, exists := seen[resource.Identity.CanonicalKey]; exists {
			return nil, guardError(ErrInvalidGuardInput, path, "duplicates an earlier target")
		}
		seen[resource.Identity.CanonicalKey] = struct{}{}
		selected = append(selected, cloneMutationTarget(resource))
	}
	sort.SliceStable(selected, func(i, j int) bool { return selected[i].Identity.CanonicalKey < selected[j].Identity.CanonicalKey })
	return selected, nil
}

// ValidateCleanupTargets validates the global-prefix selector reserved for
// teardown and nightly cleanup. Run mutations must use
// SelectRunMutationTargets instead.
func ValidateCleanupTargets(resources []MutationTarget) error {
	seen := make(map[string]struct{}, len(resources))
	for index, resource := range resources {
		path := indexedField("targets", index)
		if err := validateMutationTarget(resource); err != nil {
			return guardError(err, path, "has invalid full identity")
		}
		if !config.IsTestResource(config.GeneratedResource{Name: resource.Identity.Name, Labels: resource.Labels}) {
			return guardError(ErrUnsafeTarget, path, "does not have exact disposable identity")
		}
		if _, exists := seen[resource.Identity.CanonicalKey]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier target")
		}
		seen[resource.Identity.CanonicalKey] = struct{}{}
	}
	return nil
}

// ExpirableTarget is a disposable resource considered by the nightly wipe.
type ExpirableTarget struct {
	Target    MutationTarget
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

	resources := make([]MutationTarget, len(candidates))
	for index, candidate := range candidates {
		resources[index] = candidate.Target
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
		return selected[i].Target.Identity.CanonicalKey < selected[j].Target.Identity.CanonicalKey
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

// PrincipalKind is a closed namespace for lock and permission principals.
type PrincipalKind string

const (
	PrincipalKindUser           PrincipalKind = "user"
	PrincipalKindServiceAccount PrincipalKind = "service-account"
)

// Principal is a structural canonical identity. Subject never includes a
// user:/serviceAccount: prefix, preventing alias forms from comparing equal.
type Principal struct {
	Kind    PrincipalKind
	Subject string
}

// EnvironmentIdentity is one caller-declared non-disposable environment whose
// present or absent lock state must be represented exactly in the observation
// set.
type EnvironmentIdentity struct {
	Environment string
	Class       domain.EnvironmentClass
}

// EnvironmentLock is an explicit present/absent observation after expiry
// evaluation. RunID is mandatory only for the disposable run lock. Inactive
// observations carry the zero Principal.
type EnvironmentLock struct {
	Environment string
	Class       domain.EnvironmentClass
	RunID       string
	Active      bool
	Holder      Principal
}

// PlannedInstance is one complete plan-wide instance capacity observation.
// RunID closes prefix ambiguity independently of the resource name.
type PlannedInstance struct {
	Identity ResourceIdentity
	RunID    string
	Machine  MachineShape
}

// PlannedDisk is one complete plan-wide disk capacity observation. RunID
// closes prefix ambiguity independently of the resource name.
type PlannedDisk struct {
	Identity ResourceIdentity
	RunID    string
	SizeGiB  int64
}

// CapacityProofInput is the full run-capacity inventory supplied from an
// inspectable plan and provider-resolved machine data. EstimatedCostMicros is
// a plan-derived upward-rounded claim per D-146. This package derives counts
// and maxima, validates and fingerprints them, but performs no provider reads.
type CapacityProofInput struct {
	PlanFingerprint     string
	Limits              RunLimits
	Instances           []PlannedInstance
	Disks               []PlannedDisk
	Lifetime            time.Duration
	EstimatedCostMicros int64
}

// EvidenceFreshness binds a content revision to a short observation window.
// Revision must be the SHA-256 fingerprint of provider observations, not a
// clock or sequence number, so unchanged rediscovery retains the same value.
type EvidenceFreshness struct {
	Revision   string
	ObservedAt time.Time
	ValidUntil time.Time
	CheckedAt  time.Time
}

// PreMutationInput contains every local proof family required before a test
// harness operation can reach a provider mutation boundary.
type PreMutationInput struct {
	RunID                             string
	Targets                           []MutationTarget
	Capacity                          CapacityProofInput
	TestCIDR                          string
	ProductionCIDRs                   []string
	ExpectedNonDisposableEnvironments []EnvironmentIdentity
	Locks                             []EnvironmentLock
	HarnessPrincipal                  Principal
	Permissions                       PermissionProofInput
	FirewallRules                     []FirewallRule
	Freshness                         EvidenceFreshness
}

// PreMutationDecision is deliberately opaque. It is not an authorization to
// mutate and exposes no targets; RevalidatePreMutation must match it against a
// newer fresh observation at the mutation boundary.
type PreMutationDecision struct {
	fingerprint [sha256.Size]byte
	observedAt  time.Time
	validUntil  time.Time
}

// AuthorizePreMutation evaluates every local isolation proof and returns an
// opaque, bounded comparison token. It performs no I/O and grants no mutation
// capability by itself.
func AuthorizePreMutation(input PreMutationInput) (PreMutationDecision, error) {
	_, fingerprint, err := evaluatePreMutation(input)
	if err != nil {
		return PreMutationDecision{}, err
	}
	return PreMutationDecision{
		fingerprint: fingerprint,
		observedAt:  input.Freshness.ObservedAt,
		validUntil:  input.Freshness.ValidUntil,
	}, nil
}

// RevalidatePreMutation reevaluates fresh input at the mutation boundary and
// returns detached exact targets only when no semantic evidence changed. The
// returned targets are for immediate provider-boundary consumption only. The
// fresh observation must be newer and retain the original fixed expiry.
func RevalidatePreMutation(decision PreMutationDecision, fresh PreMutationInput) ([]MutationTarget, error) {
	if decision.validUntil.IsZero() || !fresh.Freshness.ObservedAt.After(decision.observedAt) ||
		!fresh.Freshness.ValidUntil.Equal(decision.validUntil) || !fresh.Freshness.CheckedAt.Before(decision.validUntil) {
		return nil, guardError(ErrStaleProof, "freshness", "does not satisfy immediate revalidation")
	}
	targets, fingerprint, err := evaluatePreMutation(fresh)
	if err != nil {
		return nil, err
	}
	if fingerprint != decision.fingerprint {
		return nil, guardError(ErrProofMismatch, "evidence", "changed since authorization")
	}
	return targets, nil
}

func evaluatePreMutation(input PreMutationInput) ([]MutationTarget, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if len(input.Targets) == 0 {
		return nil, zero, guardError(ErrInvalidGuardInput, "targets", "must not be empty")
	}
	if len(input.ProductionCIDRs) == 0 {
		return nil, zero, guardError(ErrInvalidGuardInput, "productionCIDRs", "must not be empty")
	}
	if err := validateEvidenceFreshness(input.Freshness); err != nil {
		return nil, zero, err
	}
	targets, err := SelectRunMutationTargets(input.RunID, input.Targets)
	if err != nil {
		return nil, zero, err
	}
	if err := validateCapacityProof(input.Capacity, input.RunID, targets); err != nil {
		return nil, zero, err
	}
	if err := ValidateNetworkCIDR(input.TestCIDR, input.ProductionCIDRs); err != nil {
		return nil, zero, err
	}
	if err := ValidateHarnessLocks(input.Locks, input.ExpectedNonDisposableEnvironments, input.RunID, input.HarnessPrincipal); err != nil {
		return nil, zero, err
	}
	if err := ValidatePermissionProof(input.Permissions); err != nil {
		return nil, zero, err
	}
	if err := ValidateFirewallRules(input.FirewallRules, input.ProductionCIDRs); err != nil {
		return nil, zero, err
	}
	fingerprint, err := preMutationFingerprint(input, targets)
	if err != nil {
		return nil, zero, err
	}
	return targets, fingerprint, nil
}

func validateCapacityProof(capacity CapacityProofInput, runID string, targets []MutationTarget) error {
	if !isSHA256Fingerprint(capacity.PlanFingerprint) {
		return guardError(ErrInvalidGuardInput, "capacity.planFingerprint", "must be a SHA-256 fingerprint")
	}
	if len(capacity.Instances) == 0 {
		return guardError(ErrInvalidGuardInput, "capacity.instances", "must contain the full planned instance inventory")
	}
	prefix, err := RunResourcePrefix(runID)
	if err != nil {
		return err
	}
	instanceKeys := make(map[string]struct{}, len(capacity.Instances))
	maximumMachine := MachineShape{}
	for index, instance := range capacity.Instances {
		path := indexedField("capacity.instances", index)
		if err := validateResourceIdentity(instance.Identity); err != nil {
			return guardError(err, path, "has invalid identity")
		}
		if instance.Identity.Service != ComputeServiceName || instance.Identity.Kind != ComputeInstanceKind ||
			!strings.HasPrefix(instance.Identity.Name, prefix) || len(instance.Identity.Name) == len(prefix) || instance.RunID != runID {
			return guardError(ErrInvalidGuardInput, path, "must identify a run-scoped Compute instance")
		}
		if instance.Machine.VCPUs <= 0 || instance.Machine.MemoryMB <= 0 {
			return guardError(ErrInvalidGuardInput, path, "must have a positive resolved machine shape")
		}
		if _, exists := instanceKeys[instance.Identity.CanonicalKey]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier planned instance")
		}
		instanceKeys[instance.Identity.CanonicalKey] = struct{}{}
		maximumMachine.VCPUs = max(maximumMachine.VCPUs, instance.Machine.VCPUs)
		maximumMachine.MemoryMB = max(maximumMachine.MemoryMB, instance.Machine.MemoryMB)
	}

	diskKeys := make(map[string]struct{}, len(capacity.Disks))
	var maximumDiskGiB int64
	for index, disk := range capacity.Disks {
		path := indexedField("capacity.disks", index)
		if err := validateResourceIdentity(disk.Identity); err != nil {
			return guardError(err, path, "has invalid identity")
		}
		if disk.Identity.Service != ComputeServiceName || disk.Identity.Kind != ComputeDiskKind ||
			!strings.HasPrefix(disk.Identity.Name, prefix) || len(disk.Identity.Name) == len(prefix) || disk.RunID != runID || disk.SizeGiB <= 0 {
			return guardError(ErrInvalidGuardInput, path, "must identify a positive run-scoped Compute disk")
		}
		if _, exists := diskKeys[disk.Identity.CanonicalKey]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier planned disk")
		}
		diskKeys[disk.Identity.CanonicalKey] = struct{}{}
		maximumDiskGiB = max(maximumDiskGiB, disk.SizeGiB)
	}

	for index, target := range targets {
		path := indexedField("targets", index)
		switch {
		case target.Identity.Service == ComputeServiceName && target.Identity.Kind == ComputeInstanceKind:
			if _, exists := instanceKeys[target.Identity.CanonicalKey]; !exists {
				return guardError(ErrInvalidGuardInput, path, "is absent from the planned instance inventory")
			}
		case target.Identity.Service == ComputeServiceName && target.Identity.Kind == ComputeDiskKind:
			if _, exists := diskKeys[target.Identity.CanonicalKey]; !exists {
				return guardError(ErrInvalidGuardInput, path, "is absent from the planned disk inventory")
			}
		}
	}

	request := RunRequest{
		Machine:             maximumMachine,
		DiskGiB:             maximumDiskGiB,
		Instances:           len(capacity.Instances),
		Lifetime:            capacity.Lifetime,
		EstimatedCostMicros: capacity.EstimatedCostMicros,
	}
	return ValidateRunRequest(capacity.Limits, request)
}

// ValidateHarnessLocks proves an exact lock observation set: one active,
// run-specific disposable lock held by the harness plus one present-or-absent
// observation for every caller-declared non-disposable environment, with no
// missing or unexpected observations.
func ValidateHarnessLocks(locks []EnvironmentLock, expected []EnvironmentIdentity, runID string, harnessPrincipal Principal) error {
	if err := ValidateRunID(runID); err != nil {
		return err
	}
	if !validPrincipal(harnessPrincipal) {
		return guardError(ErrInvalidGuardInput, "harnessPrincipal", "must be a canonical principal")
	}
	if len(expected) == 0 {
		return guardError(ErrInvalidGuardInput, "expectedEnvironments", "must not be empty")
	}
	expectedSet := make(map[EnvironmentIdentity]struct{}, len(expected))
	expectedNames := make(map[string]struct{}, len(expected))
	for index, environment := range expected {
		path := indexedField("expectedEnvironments", index)
		if !environmentNamePattern.MatchString(environment.Environment) || environment.Environment == config.TestEnvironmentLabel ||
			!environment.Class.Valid() || environment.Class == domain.EnvironmentDisposable {
			return guardError(ErrInvalidGuardInput, path, "must identify a non-disposable environment")
		}
		if _, exists := expectedNames[environment.Environment]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier environment")
		}
		expectedSet[environment] = struct{}{}
		expectedNames[environment.Environment] = struct{}{}
	}

	seenLocks := make(map[environmentLockKey]struct{}, len(locks))
	seenEnvironments := make(map[string]struct{}, len(locks))
	seenExpected := make(map[EnvironmentIdentity]struct{}, len(expected))
	runLockSeen := false
	for index, lock := range locks {
		path := indexedField("locks", index)
		if !environmentNamePattern.MatchString(lock.Environment) || !lock.Class.Valid() {
			return guardError(ErrInvalidGuardInput, path, "must have canonical environment and class")
		}
		if lock.Active {
			if !validPrincipal(lock.Holder) {
				return guardError(ErrInvalidGuardInput, path, "active observations require one canonical holder")
			}
		} else if lock.Holder != (Principal{}) {
			return guardError(ErrInvalidGuardInput, path, "inactive observations must not carry a holder")
		}
		key := environmentLockKey{environment: lock.Environment, class: lock.Class, runID: lock.RunID}
		if _, exists := seenLocks[key]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier lock observation")
		}
		if _, exists := seenEnvironments[lock.Environment]; exists {
			return guardError(ErrInvalidGuardInput, path, "ambiguously repeats an environment")
		}
		seenLocks[key] = struct{}{}
		seenEnvironments[lock.Environment] = struct{}{}
		if lock.Class == domain.EnvironmentDisposable {
			if lock.Environment != config.TestEnvironmentLabel || lock.RunID != runID {
				return guardError(ErrInvalidGuardInput, path, "is an unexpected disposable lock")
			}
			if !lock.Active || lock.Holder != harnessPrincipal {
				return guardError(ErrRunLockNotHeld, path, "is not held by the harness")
			}
			runLockSeen = true
			continue
		}
		if lock.RunID != "" {
			return guardError(ErrInvalidGuardInput, path, "non-disposable locks must not carry a run ID")
		}
		if lock.Active && lock.Holder == harnessPrincipal {
			return guardError(ErrNonDisposableLock, path, "is held by the test harness")
		}
		identity := EnvironmentIdentity{Environment: lock.Environment, Class: lock.Class}
		if _, exists := expectedSet[identity]; !exists {
			return guardError(ErrInvalidGuardInput, path, "is an unexpected non-disposable lock")
		}
		seenExpected[identity] = struct{}{}
	}
	if !runLockSeen {
		return guardError(ErrRunLockNotHeld, "locks", "is missing the run-specific disposable lock")
	}
	if len(seenExpected) != len(expectedSet) {
		return guardError(ErrInvalidGuardInput, "locks", "is missing a declared non-disposable environment")
	}
	if len(seenLocks) != len(expectedSet)+1 {
		return guardError(ErrInvalidGuardInput, "locks", "does not exactly match the declared lock set")
	}
	return nil
}

type environmentLockKey struct {
	environment string
	class       domain.EnvironmentClass
	runID       string
}

func validateEvidenceFreshness(freshness EvidenceFreshness) error {
	if !isSHA256Fingerprint(freshness.Revision) {
		return guardError(ErrInvalidGuardInput, "freshness.revision", "must be a SHA-256 fingerprint")
	}
	if freshness.ObservedAt.IsZero() || freshness.ValidUntil.IsZero() || freshness.CheckedAt.IsZero() {
		return guardError(ErrInvalidGuardInput, "freshness", "must contain complete timestamps")
	}
	for _, value := range []time.Time{freshness.ObservedAt, freshness.ValidUntil, freshness.CheckedAt} {
		_, offset := value.Zone()
		if offset != 0 {
			return guardError(ErrInvalidGuardInput, "freshness", "timestamps must use UTC")
		}
	}
	window := freshness.ValidUntil.Sub(freshness.ObservedAt)
	if window <= 0 || window > MaxPreMutationProofLifetime {
		return guardError(ErrStaleProof, "freshness", "must use a positive bounded validity window")
	}
	if freshness.CheckedAt.Before(freshness.ObservedAt) || !freshness.CheckedAt.Before(freshness.ValidUntil) {
		return guardError(ErrStaleProof, "freshness", "is outside its validity window")
	}
	return nil
}

type preMutationPayload struct {
	RunID                             string
	Targets                           []MutationTarget
	Capacity                          CapacityProofInput
	TestCIDR                          string
	ProductionCIDRs                   []string
	ExpectedNonDisposableEnvironments []EnvironmentIdentity
	Locks                             []EnvironmentLock
	HarnessPrincipal                  Principal
	Permissions                       PermissionProofInput
	FirewallRules                     []FirewallRule
	EvidenceRevision                  string
}

func preMutationFingerprint(input PreMutationInput, targets []MutationTarget) ([sha256.Size]byte, error) {
	payload := preMutationPayload{
		RunID:                             input.RunID,
		Targets:                           append([]MutationTarget(nil), targets...),
		Capacity:                          cloneCapacityProof(input.Capacity),
		TestCIDR:                          input.TestCIDR,
		ProductionCIDRs:                   append([]string(nil), input.ProductionCIDRs...),
		ExpectedNonDisposableEnvironments: append([]EnvironmentIdentity(nil), input.ExpectedNonDisposableEnvironments...),
		Locks:                             append([]EnvironmentLock(nil), input.Locks...),
		HarnessPrincipal:                  input.HarnessPrincipal,
		Permissions: PermissionProofInput{
			Inventory: input.Permissions.Inventory,
			Expected:  append([]PermissionObservation(nil), input.Permissions.Expected...),
			Observed:  append([]PermissionObservation(nil), input.Permissions.Observed...),
		},
		FirewallRules:    cloneFirewallRules(input.FirewallRules),
		EvidenceRevision: input.Freshness.Revision,
	}
	sort.Strings(payload.ProductionCIDRs)
	sort.Slice(payload.Capacity.Instances, func(i, j int) bool {
		return payload.Capacity.Instances[i].Identity.CanonicalKey < payload.Capacity.Instances[j].Identity.CanonicalKey
	})
	sort.Slice(payload.Capacity.Disks, func(i, j int) bool {
		return payload.Capacity.Disks[i].Identity.CanonicalKey < payload.Capacity.Disks[j].Identity.CanonicalKey
	})
	sort.Slice(payload.ExpectedNonDisposableEnvironments, func(i, j int) bool {
		if payload.ExpectedNonDisposableEnvironments[i].Environment != payload.ExpectedNonDisposableEnvironments[j].Environment {
			return payload.ExpectedNonDisposableEnvironments[i].Environment < payload.ExpectedNonDisposableEnvironments[j].Environment
		}
		return payload.ExpectedNonDisposableEnvironments[i].Class < payload.ExpectedNonDisposableEnvironments[j].Class
	})
	sort.Slice(payload.Locks, func(i, j int) bool {
		first, second := payload.Locks[i], payload.Locks[j]
		if first.Environment != second.Environment {
			return first.Environment < second.Environment
		}
		if first.Class != second.Class {
			return first.Class < second.Class
		}
		return first.RunID < second.RunID
	})
	sortPermissionObservations(payload.Permissions.Expected)
	sortPermissionObservations(payload.Permissions.Observed)
	sort.Slice(payload.FirewallRules, func(i, j int) bool {
		return payload.FirewallRules[i].Purpose < payload.FirewallRules[j].Purpose
	})
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [sha256.Size]byte{}, guardError(ErrInvalidGuardInput, "evidence", "could not be fingerprinted")
	}
	return sha256.Sum256(encoded), nil
}

func sortPermissionObservations(values []PermissionObservation) {
	sort.Slice(values, func(i, j int) bool {
		first, second := newPermissionObservationKey(values[i]), newPermissionObservationKey(values[j])
		if first.identityKind != second.identityKind {
			return first.identityKind < second.identityKind
		}
		if first.identitySubject != second.identitySubject {
			return first.identitySubject < second.identitySubject
		}
		if first.resource != second.resource {
			return first.resource < second.resource
		}
		if first.permission != second.permission {
			return first.permission < second.permission
		}
		return !values[i].Granted && values[j].Granted
	})
}

func cloneFirewallRules(rules []FirewallRule) []FirewallRule {
	cloned := make([]FirewallRule, len(rules))
	for index, rule := range rules {
		rule.Ports = append([]uint16(nil), rule.Ports...)
		rule.SourceCIDRs = append([]string(nil), rule.SourceCIDRs...)
		rule.SourceTags = append([]string(nil), rule.SourceTags...)
		rule.TargetTags = append([]string(nil), rule.TargetTags...)
		cloned[index] = rule
	}
	return cloned
}

func cloneCapacityProof(capacity CapacityProofInput) CapacityProofInput {
	capacity.Instances = append([]PlannedInstance(nil), capacity.Instances...)
	capacity.Disks = append([]PlannedDisk(nil), capacity.Disks...)
	return capacity
}

func validPrincipal(principal Principal) bool {
	if principal.Subject != strings.ToLower(principal.Subject) || principal.Subject != strings.TrimSpace(principal.Subject) {
		return false
	}
	switch principal.Kind {
	case PrincipalKindUser:
		return userSubjectPattern.MatchString(principal.Subject)
	case PrincipalKindServiceAccount:
		return serviceAccountSubjectPattern.MatchString(principal.Subject)
	default:
		return false
	}
}

func cloneExpirableTarget(target ExpirableTarget) ExpirableTarget {
	target.Target = cloneMutationTarget(target.Target)
	return target
}

func validateMutationTarget(target MutationTarget) error {
	if err := validateResourceIdentity(target.Identity); err != nil {
		return err
	}
	resource := config.GeneratedResource{Name: target.Identity.Name, Labels: target.Labels}
	if !config.IsTestResource(resource) {
		return guardError(ErrUnsafeTarget, "target.labels", "do not have exact disposable identity")
	}
	return nil
}

func validateResourceIdentity(identity ResourceIdentity) error {
	wantKey, err := CanonicalTargetKey(identity)
	if err != nil {
		return err
	}
	if identity.CanonicalKey != wantKey {
		return guardError(ErrInvalidGuardInput, "target.identity.canonicalKey", "does not match the explicit identity fields")
	}
	return nil
}

func cloneMutationTarget(target MutationTarget) MutationTarget {
	labels := make(map[string]string, len(target.Labels))
	for key, value := range target.Labels {
		labels[key] = value
	}
	target.Labels = labels
	return target
}

func indexedField(base string, index int) string {
	return fmt.Sprintf("%s[%d]", base, index)
}

func guardError(kind error, path, reason string) error {
	return fmt.Errorf("%w: %s %s", kind, path, reason)
}
