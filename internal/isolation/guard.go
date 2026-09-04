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
	projectIDPattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	servicePattern          = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$`)
	resourceKindPattern     = regexp.MustCompile(`^[a-z][A-Za-z0-9]{0,62}$`)
	resourceLocationPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	resourceNamePattern     = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	environmentNamePattern  = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
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
)

// MutationTargetIdentity is the complete local identity a future provider
// adapter must consume without consulting ambient defaults. FullName is the
// canonical //service/projects/project/scope/kind/name representation.
type MutationTargetIdentity struct {
	Project  string
	Service  ProviderService
	Kind     ResourceKind
	Scope    ResourceScope
	Location string
	Name     string
	FullName string
}

// MutationTarget binds full provider identity to the labels observed for that
// exact resource.
type MutationTarget struct {
	Identity MutationTargetIdentity
	Labels   map[string]string
}

// CanonicalMutationTargetName derives the complete, explicit identity string.
func CanonicalMutationTargetName(identity MutationTargetIdentity) (string, error) {
	if !projectIDPattern.MatchString(identity.Project) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.project", "must be a canonical explicit project ID")
	}
	if !servicePattern.MatchString(string(identity.Service)) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.service", "must be a canonical service name")
	}
	if !resourceKindPattern.MatchString(string(identity.Kind)) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.kind", "must be a canonical resource kind")
	}
	if !resourceLocationPattern.MatchString(identity.Location) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.location", "must be a canonical explicit location")
	}
	var scopePath string
	switch identity.Scope {
	case ResourceScopeGlobal:
		if identity.Location != "global" {
			return "", guardError(ErrInvalidGuardInput, "target.identity.location", "must equal global for global scope")
		}
		scopePath = "global"
	case ResourceScopeRegion:
		if identity.Location == "global" {
			return "", guardError(ErrInvalidGuardInput, "target.identity.location", "must identify a region")
		}
		scopePath = "regions/" + identity.Location
	case ResourceScopeZone:
		if identity.Location == "global" {
			return "", guardError(ErrInvalidGuardInput, "target.identity.location", "must identify a zone")
		}
		scopePath = "zones/" + identity.Location
	default:
		return "", guardError(ErrInvalidGuardInput, "target.identity.scope", "must be global, region, or zone")
	}
	if !resourceNamePattern.MatchString(identity.Name) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.name", "must be a canonical resource name")
	}
	return "//" + string(identity.Service) + "/projects/" + identity.Project + "/" + scopePath + "/" + string(identity.Kind) + "/" + identity.Name, nil
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
		if _, exists := seen[resource.Identity.FullName]; exists {
			return nil, guardError(ErrInvalidGuardInput, path, "duplicates an earlier target")
		}
		seen[resource.Identity.FullName] = struct{}{}
		selected = append(selected, cloneMutationTarget(resource))
	}
	sort.SliceStable(selected, func(i, j int) bool { return selected[i].Identity.FullName < selected[j].Identity.FullName })
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
		if _, exists := seen[resource.Identity.FullName]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier target")
		}
		seen[resource.Identity.FullName] = struct{}{}
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
		return selected[i].Target.Identity.FullName < selected[j].Target.Identity.FullName
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

// EnvironmentIdentity is one caller-declared non-disposable environment whose
// active lock must be represented exactly in the observation set.
type EnvironmentIdentity struct {
	Environment string
	Class       domain.EnvironmentClass
}

// EnvironmentLock is active lock state after expiry has been evaluated by the
// control-bucket adapter. RunID is mandatory only for the disposable run lock.
type EnvironmentLock struct {
	Environment string
	Class       domain.EnvironmentClass
	RunID       string
	Holder      string
}

// CapacityProofInput is a local proof supplied from an inspectable plan and
// provider-resolved machine data. This package validates and fingerprints the
// claim; it does not independently discover machine, disk, or pricing truth.
type CapacityProofInput struct {
	PlanFingerprint string
	Limits          RunLimits
	Request         RunRequest
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
	HarnessHolder                     string
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
// fresh observation must be newer and cannot extend the original expiry.
func RevalidatePreMutation(decision PreMutationDecision, fresh PreMutationInput) ([]MutationTarget, error) {
	if decision.validUntil.IsZero() || !fresh.Freshness.ObservedAt.After(decision.observedAt) ||
		!fresh.Freshness.CheckedAt.Before(decision.validUntil) {
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
	if !isSHA256Fingerprint(input.Capacity.PlanFingerprint) {
		return nil, zero, guardError(ErrInvalidGuardInput, "capacity.planFingerprint", "must be a SHA-256 fingerprint")
	}
	if err := ValidateRunRequest(input.Capacity.Limits, input.Capacity.Request); err != nil {
		return nil, zero, err
	}
	instanceTargets := 0
	for _, target := range targets {
		if target.Identity.Service == ComputeServiceName && target.Identity.Kind == ComputeInstanceKind {
			instanceTargets++
		}
	}
	if input.Capacity.Request.Instances != instanceTargets {
		return nil, zero, guardError(ErrInvalidGuardInput, "capacity.request.instances", "does not match the exact instance target set")
	}
	if err := ValidateNetworkCIDR(input.TestCIDR, input.ProductionCIDRs); err != nil {
		return nil, zero, err
	}
	if err := ValidateHarnessLocks(input.Locks, input.ExpectedNonDisposableEnvironments, input.RunID, input.HarnessHolder); err != nil {
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

// ValidateHarnessLocks proves an exact lock observation set: one run-specific
// disposable lock held by the harness plus one lock for every caller-declared
// non-disposable environment, with no missing or unexpected observations.
func ValidateHarnessLocks(locks []EnvironmentLock, expected []EnvironmentIdentity, runID, harnessHolder string) error {
	if err := ValidateRunID(runID); err != nil {
		return err
	}
	if !isCanonicalOpaqueID(harnessHolder) {
		return guardError(ErrInvalidGuardInput, "harnessHolder", "must be a canonical nonempty holder")
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
		if !environmentNamePattern.MatchString(lock.Environment) || !lock.Class.Valid() || !isCanonicalOpaqueID(lock.Holder) {
			return guardError(ErrInvalidGuardInput, path, "must have canonical environment, class, and holder")
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
			if lock.Holder != harnessHolder {
				return guardError(ErrRunLockNotHeld, path, "is not held by the harness")
			}
			runLockSeen = true
			continue
		}
		if lock.RunID != "" {
			return guardError(ErrInvalidGuardInput, path, "non-disposable locks must not carry a run ID")
		}
		if lock.Holder == harnessHolder {
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
	HarnessHolder                     string
	Permissions                       PermissionProofInput
	FirewallRules                     []FirewallRule
	EvidenceRevision                  string
}

func preMutationFingerprint(input PreMutationInput, targets []MutationTarget) ([sha256.Size]byte, error) {
	payload := preMutationPayload{
		RunID:                             input.RunID,
		Targets:                           append([]MutationTarget(nil), targets...),
		Capacity:                          input.Capacity,
		TestCIDR:                          input.TestCIDR,
		ProductionCIDRs:                   append([]string(nil), input.ProductionCIDRs...),
		ExpectedNonDisposableEnvironments: append([]EnvironmentIdentity(nil), input.ExpectedNonDisposableEnvironments...),
		Locks:                             append([]EnvironmentLock(nil), input.Locks...),
		HarnessHolder:                     input.HarnessHolder,
		Permissions: PermissionProofInput{
			Inventory: input.Permissions.Inventory,
			Expected:  append([]PermissionObservation(nil), input.Permissions.Expected...),
			Observed:  append([]PermissionObservation(nil), input.Permissions.Observed...),
		},
		FirewallRules:    cloneFirewallRules(input.FirewallRules),
		EvidenceRevision: input.Freshness.Revision,
	}
	sort.Strings(payload.ProductionCIDRs)
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
		if first.identity != second.identity {
			return first.identity < second.identity
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

func isCanonicalOpaqueID(value string) bool {
	if len(value) == 0 || len(value) > 256 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func cloneExpirableTarget(target ExpirableTarget) ExpirableTarget {
	target.Target = cloneMutationTarget(target.Target)
	return target
}

func validateMutationTarget(target MutationTarget) error {
	wantFullName, err := CanonicalMutationTargetName(target.Identity)
	if err != nil {
		return err
	}
	if target.Identity.FullName != wantFullName {
		return guardError(ErrInvalidGuardInput, "target.identity.fullName", "does not match the explicit identity fields")
	}
	resource := config.GeneratedResource{Name: target.Identity.Name, Labels: target.Labels}
	if !config.IsTestResource(resource) {
		return guardError(ErrUnsafeTarget, "target.labels", "do not have exact disposable identity")
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
