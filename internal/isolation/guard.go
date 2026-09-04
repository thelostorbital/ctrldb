// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package isolation contains fail-closed, I/O-free guards for disposable test
// infrastructure. Cloud adapters must pass discovered state through these
// guards before issuing a mutation.
package isolation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
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
	regionPattern                = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+[0-9]+$`)
	zonePattern                  = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+[0-9]+-[a-z]$`)
	resourceNamePattern          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?$`)
	computeResourceNamePattern   = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	environmentNamePattern       = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	userSubjectPattern           = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	serviceAccountSubjectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	canonicalIDPattern           = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	operationIDPattern           = regexp.MustCompile(`^op-[0-9a-f]{16}$`)
	planIDPattern                = regexp.MustCompile(`^plan-[0-9a-f]{16}$`)
	inventoryVersionPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
)

const (
	maxRunIDLength              = 32
	LabelRunID                  = "run-id"
	MaxPreMutationProofLifetime = 5 * time.Minute
	maxGCPSubnetPrefixBits      = 29
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
	ComputeFirewallKind ResourceKind    = "firewalls"
	ComputeNetworkKind  ResourceKind    = "networks"
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
	if err := validateKnownResourceScope(identity); err != nil {
		return "", err
	}
	if !resourceNamePattern.MatchString(identity.Name) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.name", "must be a canonical resource name")
	}
	if identity.Service == ComputeServiceName && !computeResourceNamePattern.MatchString(identity.Name) {
		return "", guardError(ErrInvalidGuardInput, "target.identity.name", "must be a 1-63 character RFC 1035 Compute resource name")
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
	if testNetwork.Bits() > maxGCPSubnetPrefixBits {
		return guardError(ErrInvalidGuardInput, "testCIDR", "must be a provider-valid subnet prefix")
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

// PlanIdentity binds the capacity snapshot to an immutable plan artifact
// produced by the future trusted plan compiler.
type PlanIdentity struct {
	ID   string
	Hash string
}

// CapacityProofInput is the full run-capacity inventory supplied from an
// inspectable plan and provider-resolved machine data. EstimatedCostMicros is
// a plan-derived upward-rounded claim per D-146. SnapshotFingerprint must be
// produced by CapacitySnapshotFingerprint over this exact typed snapshot.
// This package checks local integrity and caps but cannot establish that the
// future trusted plan compiler/provider adapter supplied truthful inputs.
type CapacityProofInput struct {
	Plan                PlanIdentity
	SnapshotFingerprint string
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
}

// OperationBinding identifies exactly one durable mutation attempt. The I/O-
// free guard fingerprints this binding; a durable journal must atomically
// claim it before provider mutation because this package cannot consume it.
type OperationBinding struct {
	OperationID string
	StepID      string
	Attempt     uint32
}

// MutationAction is a closed provider verb admitted by the test-isolation
// boundary. M-0 proves only an exact Compute firewalls.insert request; every
// other create, update, and delete requires its own complete request type and
// proof family.
type MutationAction string

const MutationActionComputeFirewallInsert MutationAction = "compute.firewalls.insert"

// TestPrincipalRole selects one exact trusted test identity. Firewall creation
// is operator-only; the destructive role is reserved for a future exhaustively
// validated cleanup intent.
type TestPrincipalRole string

const (
	TestPrincipalRoleOperator    TestPrincipalRole = "operator"
	TestPrincipalRoleDestructive TestPrincipalRole = "destructive"
)

// CreateDesiredState is the closed M-0 creation union. Only Firewall is
// currently representable; VM, disk, VPC, subnet, NAT, and other provider
// creates remain unrepresentable until complete request types exist.
type CreateDesiredState struct {
	Firewall *FirewallRule
}

// MutationIntent is the proposed, untrusted request that binds one exact
// create verb, selected target, typed desired state, and required identity.
type MutationIntent struct {
	Action                MutationAction
	Target                MutationTarget
	RequiredPrincipalRole TestPrincipalRole
	Create                CreateDesiredState
}

// AuthorizedMutationIntent is the sealed, detached provider request returned
// only after immediate revalidation. Accessors return values or deep copies so
// callers cannot turn a validated create into another action or desired state.
type AuthorizedMutationIntent struct {
	action                MutationAction
	target                MutationTarget
	requiredPrincipalRole TestPrincipalRole
	create                CreateDesiredState
}

// Action returns the exact validated provider verb.
func (intent AuthorizedMutationIntent) Action() MutationAction { return intent.action }

// Target returns a detached copy of the exact validated resource target.
func (intent AuthorizedMutationIntent) Target() MutationTarget {
	return cloneMutationTarget(intent.target)
}

// RequiredPrincipalRole returns the trusted identity class required by Action.
func (intent AuthorizedMutationIntent) RequiredPrincipalRole() TestPrincipalRole {
	return intent.requiredPrincipalRole
}

// FirewallCreateState returns a detached copy of the validated firewall state
// when this is a firewall-create intent.
func (intent AuthorizedMutationIntent) FirewallCreateState() (FirewallRule, bool) {
	if intent.create.Firewall == nil {
		return FirewallRule{}, false
	}
	return cloneFirewallRules([]FirewallRule{*intent.create.Firewall})[0], true
}

// PolicyInventoryPin is a policy-owned name, version, and expected content
// fingerprint. It is passed separately from discovered proof values so the
// mutation boundary can source it from a trusted configuration boundary.
type PolicyInventoryPin struct {
	ID          string
	Version     string
	Fingerprint string
}

// PreMutationPolicy contains the trusted project boundary, resolved caps, the
// exact configured test CIDR and principals, and three independent complete-
// inventory pins. The decision fingerprint binds the complete policy alongside
// the immutable plan identity and every resource observation. This pure type
// does not itself prove the caller sourced those policy values authoritatively.
type PreMutationPolicy struct {
	ProjectID                         string
	RunLimits                         RunLimits
	TestCIDR                          string
	TestHarnessPrincipal              Principal
	TestOperatorPrincipal             Principal
	TestDestructivePrincipal          Principal
	PermissionInventory               PolicyInventoryPin
	NonDisposableEnvironmentInventory PolicyInventoryPin
	ProductionCIDRInventory           PolicyInventoryPin
}

// PreMutationInput contains every local proof family required before a test
// harness operation can reach a provider mutation boundary.
type PreMutationInput struct {
	Operation                         OperationBinding
	RunID                             string
	Targets                           []MutationTarget
	Capacity                          CapacityProofInput
	TestCIDR                          string
	ProductionCIDRs                   []string
	ExpectedNonDisposableEnvironments []EnvironmentIdentity
	Locks                             []EnvironmentLock
	HarnessPrincipal                  Principal
	MutationPrincipal                 Principal
	MutationIntents                   []MutationIntent
	Permissions                       PermissionProofInput
	FirewallRules                     []FirewallRule
	// RunLifetime is the currently discovered immutable lifetime-record
	// generation. The enclosing Freshness revision must cover this observation.
	RunLifetime RunLifetimeContract
	Freshness   EvidenceFreshness
}

// PreMutationDecision is deliberately opaque. It is not an authorization to
// mutate and exposes no targets; RevalidatePreMutation must match it against a
// newer fresh observation at the mutation boundary.
type PreMutationDecision struct {
	fingerprint  [sha256.Size]byte
	operation    OperationBinding
	authorizedAt time.Time
	validUntil   time.Time
}

// MutationBoundary is the detached result for immediate provider-boundary use.
// The caller must atomically claim Operation in its durable journal, then a
// future provider adapter must execute each typed Intent verbatim as Principal.
// It must not infer provider defaults or synthesize unrepresented resources.
// Repeated pure validation is not atomic consumption.
type MutationBoundary struct {
	operation OperationBinding
	principal Principal
	intents   []AuthorizedMutationIntent
}

// Operation returns the exact durable operation attempt bound to this result.
func (boundary MutationBoundary) Operation() OperationBinding { return boundary.operation }

// Principal returns the exact configured service account authorized to execute
// the boundary's intents.
func (boundary MutationBoundary) Principal() Principal { return boundary.principal }

// Intents returns detached provider requests. A future adapter must consume
// their actions, targets, and desired states verbatim.
func (boundary MutationBoundary) Intents() []AuthorizedMutationIntent {
	return cloneAuthorizedMutationIntents(boundary.intents)
}

// AuthorizePreMutation evaluates every local isolation proof and returns an
// opaque, bounded comparison token. It performs no I/O and grants no mutation
// capability by itself. The caller must source now from its boundary clock,
// independently of the evidence timestamps.
func AuthorizePreMutation(policy PreMutationPolicy, input PreMutationInput, now time.Time) (PreMutationDecision, error) {
	_, fingerprint, err := evaluatePreMutation(policy, input, now)
	if err != nil {
		return PreMutationDecision{}, err
	}
	return PreMutationDecision{
		fingerprint:  fingerprint,
		operation:    input.Operation,
		authorizedAt: now,
		validUntil:   input.Freshness.ValidUntil,
	}, nil
}

// RevalidatePreMutation reevaluates fresh input at the mutation boundary and
// returns detached typed intents only when no semantic evidence changed. The
// returned intents are for immediate provider-boundary consumption only. The
// fresh observation must be strictly newer than the authorization boundary
// and retain the original fixed expiry. The caller must independently sample
// now at this boundary; that clock cannot move backward from authorization.
func RevalidatePreMutation(decision PreMutationDecision, policy PreMutationPolicy, fresh PreMutationInput, now time.Time) (MutationBoundary, error) {
	if now.IsZero() {
		return MutationBoundary{}, guardError(ErrInvalidGuardInput, "now", "must not be zero")
	}
	if decision.authorizedAt.IsZero() || decision.validUntil.IsZero() || now.Before(decision.authorizedAt) ||
		!fresh.Freshness.ObservedAt.After(decision.authorizedAt) || !fresh.Freshness.ValidUntil.Equal(decision.validUntil) {
		return MutationBoundary{}, guardError(ErrStaleProof, "freshness", "does not satisfy immediate revalidation")
	}
	intents, fingerprint, err := evaluatePreMutation(policy, fresh, now)
	if err != nil {
		return MutationBoundary{}, err
	}
	if fingerprint != decision.fingerprint || fresh.Operation != decision.operation {
		return MutationBoundary{}, guardError(ErrProofMismatch, "evidence", "changed since authorization")
	}
	return MutationBoundary{
		operation: fresh.Operation,
		principal: fresh.MutationPrincipal,
		intents:   authorizeMutationIntents(intents),
	}, nil
}

func evaluatePreMutation(policy PreMutationPolicy, input PreMutationInput, now time.Time) ([]MutationIntent, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if len(input.Targets) == 0 {
		return nil, zero, guardError(ErrInvalidGuardInput, "targets", "must not be empty")
	}
	if err := validateOperationBinding(input.Operation); err != nil {
		return nil, zero, err
	}
	if err := validateEvidenceFreshness(input.Freshness, now); err != nil {
		return nil, zero, err
	}
	if err := validatePreMutationPolicy(policy, input); err != nil {
		return nil, zero, err
	}
	targets, err := SelectRunMutationTargets(input.RunID, input.Targets)
	if err != nil {
		return nil, zero, err
	}
	if err := validatePreMutationProject(policy.ProjectID, input, targets); err != nil {
		return nil, zero, err
	}
	if err := validateCapacityProof(input.Capacity, policy.RunLimits, input.RunID, targets); err != nil {
		return nil, zero, err
	}
	if err := ValidateNetworkCIDR(input.TestCIDR, input.ProductionCIDRs); err != nil {
		return nil, zero, err
	}
	if err := ValidateHarnessLocks(input.Locks, input.ExpectedNonDisposableEnvironments, input.RunID, input.HarnessPrincipal); err != nil {
		return nil, zero, err
	}
	if err := ValidatePermissionProof(policy.PermissionInventory, input.Permissions, input.MutationPrincipal); err != nil {
		return nil, zero, err
	}
	if err := ValidateFirewallRules(input.FirewallRules, input.ProductionCIDRs, targets, FirewallValidationContext{
		RunID: input.RunID, Plan: input.Capacity.Plan, Operation: input.Operation,
		PlannedLifetime: input.Capacity.Lifetime, RunLimits: policy.RunLimits,
		RunLifetime: input.RunLifetime, Now: now,
	}); err != nil {
		return nil, zero, err
	}
	intents, err := validateMutationIntents(policy, input, targets)
	if err != nil {
		return nil, zero, err
	}
	fingerprint, err := preMutationFingerprint(policy, input, targets, intents)
	if err != nil {
		return nil, zero, err
	}
	return intents, fingerprint, nil
}

func validateCapacityProof(capacity CapacityProofInput, limits RunLimits, runID string, targets []MutationTarget) error {
	if !planIDPattern.MatchString(capacity.Plan.ID) || !isSHA256Fingerprint(capacity.Plan.Hash) {
		return guardError(ErrInvalidGuardInput, "capacity.plan", "must identify a canonical immutable plan")
	}
	fingerprint, err := CapacitySnapshotFingerprint(capacity)
	if err != nil {
		return err
	}
	if capacity.SnapshotFingerprint != fingerprint {
		return guardError(ErrInvalidGuardInput, "capacity.snapshotFingerprint", "does not match the typed capacity snapshot")
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
			instance.Identity.Scope != ResourceScopeZone || !strings.HasPrefix(instance.Identity.Name, prefix) ||
			len(instance.Identity.Name) == len(prefix) || instance.RunID != runID {
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
			(disk.Identity.Scope != ResourceScopeZone && disk.Identity.Scope != ResourceScopeRegion) ||
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
	return ValidateRunRequest(limits, request)
}

func validateMutationIntents(policy PreMutationPolicy, input PreMutationInput, targets []MutationTarget) ([]MutationIntent, error) {
	if len(input.MutationIntents) != len(targets) {
		return nil, guardError(ErrInvalidGuardInput, "mutationIntents", "must contain exactly one intent per selected target")
	}
	if input.MutationPrincipal != policy.TestOperatorPrincipal {
		return nil, guardError(ErrPermissionProof, "mutationPrincipal", "does not match the configured test operator")
	}

	targetsByKey := make(map[string]MutationTarget, len(targets))
	for _, target := range targets {
		targetsByKey[target.Identity.CanonicalKey] = target
	}
	firewallsByKey := make(map[string]FirewallRule, len(input.FirewallRules))
	for _, firewall := range input.FirewallRules {
		firewallsByKey[firewall.Identity.CanonicalKey] = firewall
	}

	seen := make(map[string]struct{}, len(input.MutationIntents))
	validated := make([]MutationIntent, 0, len(input.MutationIntents))
	for index, intent := range input.MutationIntents {
		path := indexedField("mutationIntents", index)
		if intent.Action != MutationActionComputeFirewallInsert {
			return nil, guardError(ErrInvalidGuardInput, path+".action", "is not an admitted provider action")
		}
		if intent.RequiredPrincipalRole != TestPrincipalRoleOperator {
			return nil, guardError(ErrPermissionProof, path+".requiredPrincipalRole", "does not select the configured test operator")
		}
		if err := validateMutationTarget(intent.Target); err != nil {
			return nil, guardError(err, path+".target", "is not a valid disposable target")
		}
		wantTarget, exists := targetsByKey[intent.Target.Identity.CanonicalKey]
		if !exists || !equalMutationTarget(intent.Target, wantTarget) {
			return nil, guardError(ErrInvalidGuardInput, path+".target", "does not match one selected target")
		}
		if _, exists := seen[intent.Target.Identity.CanonicalKey]; exists {
			return nil, guardError(ErrInvalidGuardInput, path+".target", "duplicates an earlier intent")
		}

		switch {
		case intent.Target.Identity.Service == ComputeServiceName && intent.Target.Identity.Kind == ComputeFirewallKind:
			if intent.Create.Firewall == nil {
				return nil, guardError(ErrInvalidGuardInput, path+".create", "must contain typed firewall state")
			}
			want, exists := firewallsByKey[intent.Target.Identity.CanonicalKey]
			if !exists || !equalFirewallRule(*intent.Create.Firewall, want) {
				return nil, guardError(ErrInvalidGuardInput, path+".create.firewall", "does not match the validated firewall proof")
			}
		default:
			return nil, guardError(ErrInvalidGuardInput, path+".target", "has no admitted typed create state")
		}

		seen[intent.Target.Identity.CanonicalKey] = struct{}{}
		validated = append(validated, cloneMutationIntent(intent))
	}
	if len(seen) != len(targetsByKey) {
		return nil, guardError(ErrInvalidGuardInput, "mutationIntents", "is missing a selected target")
	}
	sort.Slice(validated, func(i, j int) bool {
		return validated[i].Target.Identity.CanonicalKey < validated[j].Target.Identity.CanonicalKey
	})
	return validated, nil
}

func equalMutationTarget(first, second MutationTarget) bool {
	return first.Identity == second.Identity && maps.Equal(first.Labels, second.Labels)
}

func equalFirewallRule(first, second FirewallRule) bool {
	return first.Identity == second.Identity && first.Description == second.Description && first.Network == second.Network &&
		first.RunID == second.RunID && first.Purpose == second.Purpose && first.Enabled == second.Enabled &&
		first.Priority == second.Priority && first.Direction == second.Direction &&
		equalFirewallTrafficRules(first.Allowed, second.Allowed) && equalFirewallTrafficRules(first.Denied, second.Denied) &&
		slices.Equal(first.DestinationCIDRs, second.DestinationCIDRs) && slices.Equal(first.SourceCIDRs, second.SourceCIDRs) &&
		slices.Equal(first.SourceTags, second.SourceTags) && slices.Equal(first.SourceServiceAccounts, second.SourceServiceAccounts) &&
		slices.Equal(first.TargetTags, second.TargetTags) && slices.Equal(first.TargetServiceAccounts, second.TargetServiceAccounts) &&
		first.LogConfig == second.LogConfig && maps.Equal(first.ResourceManagerTags, second.ResourceManagerTags) &&
		first.LifetimeContractFingerprint == second.LifetimeContractFingerprint
}

func equalFirewallTrafficRules(first, second []FirewallTrafficRule) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index].IPProtocol != second[index].IPProtocol || !slices.Equal(first[index].Ports, second[index].Ports) {
			return false
		}
	}
	return true
}

// CapacitySnapshotFingerprint returns the deterministic identity of the
// immutable plan reference and exact capacity/cost snapshot. Run limits are a
// separate trusted-policy input. The future trusted plan compiler and provider
// adapter remain responsible for supplying truthful typed values.
func CapacitySnapshotFingerprint(capacity CapacityProofInput) (string, error) {
	if !planIDPattern.MatchString(capacity.Plan.ID) || !isSHA256Fingerprint(capacity.Plan.Hash) {
		return "", guardError(ErrInvalidGuardInput, "capacity.plan", "must identify a canonical immutable plan")
	}
	if len(capacity.Instances) == 0 || capacity.Lifetime <= 0 || capacity.EstimatedCostMicros < 0 {
		return "", guardError(ErrInvalidGuardInput, "capacity", "must contain a complete positive snapshot")
	}
	payload := struct {
		Plan                PlanIdentity
		Instances           []PlannedInstance
		Disks               []PlannedDisk
		Lifetime            time.Duration
		EstimatedCostMicros int64
	}{
		Plan: capacity.Plan, Instances: append([]PlannedInstance(nil), capacity.Instances...),
		Disks: append([]PlannedDisk(nil), capacity.Disks...), Lifetime: capacity.Lifetime,
		EstimatedCostMicros: capacity.EstimatedCostMicros,
	}
	sort.Slice(payload.Instances, func(i, j int) bool {
		return payload.Instances[i].Identity.CanonicalKey < payload.Instances[j].Identity.CanonicalKey
	})
	sort.Slice(payload.Disks, func(i, j int) bool {
		return payload.Disks[i].Identity.CanonicalKey < payload.Disks[j].Identity.CanonicalKey
	})
	return canonicalJSONFingerprint(payload)
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

func validateEvidenceFreshness(freshness EvidenceFreshness, now time.Time) error {
	if !isSHA256Fingerprint(freshness.Revision) {
		return guardError(ErrInvalidGuardInput, "freshness.revision", "must be a SHA-256 fingerprint")
	}
	if freshness.ObservedAt.IsZero() || freshness.ValidUntil.IsZero() || now.IsZero() {
		return guardError(ErrInvalidGuardInput, "freshness", "must contain complete timestamps")
	}
	for _, value := range []time.Time{freshness.ObservedAt, freshness.ValidUntil, now} {
		_, offset := value.Zone()
		if offset != 0 {
			return guardError(ErrInvalidGuardInput, "freshness", "timestamps must use UTC")
		}
	}
	window := freshness.ValidUntil.Sub(freshness.ObservedAt)
	if window <= 0 || window > MaxPreMutationProofLifetime {
		return guardError(ErrStaleProof, "freshness", "must use a positive bounded validity window")
	}
	if now.Before(freshness.ObservedAt) || !now.Before(freshness.ValidUntil) {
		return guardError(ErrStaleProof, "now", "is outside the evidence validity window")
	}
	return nil
}

func validateOperationBinding(binding OperationBinding) error {
	if !operationIDPattern.MatchString(binding.OperationID) || !canonicalIDPattern.MatchString(binding.StepID) || binding.Attempt == 0 {
		return guardError(ErrInvalidGuardInput, "operation", "must identify one canonical durable step attempt")
	}
	return nil
}

func validatePreMutationPolicy(policy PreMutationPolicy, input PreMutationInput) error {
	if !projectIDPattern.MatchString(policy.ProjectID) {
		return guardError(ErrInvalidGuardInput, "policy.projectID", "must be a canonical explicit project ID")
	}
	if err := validateRunLimits(policy.RunLimits); err != nil {
		return err
	}
	if !validPrincipal(policy.TestHarnessPrincipal) {
		return guardError(ErrInvalidGuardInput, "policy.testHarnessPrincipal", "must identify one canonical configured principal")
	}
	if input.HarnessPrincipal != policy.TestHarnessPrincipal {
		return guardError(ErrInvalidGuardInput, "harnessPrincipal", "does not match the configured test harness principal")
	}
	for _, principal := range []struct {
		path  string
		value Principal
	}{
		{path: "policy.testOperatorPrincipal", value: policy.TestOperatorPrincipal},
		{path: "policy.testDestructivePrincipal", value: policy.TestDestructivePrincipal},
	} {
		if principal.value.Kind != PrincipalKindServiceAccount || !validPrincipal(principal.value) {
			return guardError(ErrInvalidGuardInput, principal.path, "must identify one configured service account")
		}
	}
	if policy.TestOperatorPrincipal == policy.TestDestructivePrincipal {
		return guardError(ErrInvalidGuardInput, "policy.testPrincipals", "must identify distinct operator and destructive service accounts")
	}
	if policy.TestCIDR != input.TestCIDR {
		return guardError(ErrInvalidGuardInput, "testCIDR", "does not match the configured test-isolation network")
	}
	if err := validateInventoryPin("policy.permissionInventory", policy.PermissionInventory); err != nil {
		return err
	}
	if err := validateInventoryPin("policy.nonDisposableEnvironmentInventory", policy.NonDisposableEnvironmentInventory); err != nil {
		return err
	}
	if err := validateInventoryPin("policy.productionCIDRInventory", policy.ProductionCIDRInventory); err != nil {
		return err
	}
	environments, err := NonDisposableEnvironmentInventoryFingerprint(input.ExpectedNonDisposableEnvironments)
	if err != nil {
		return err
	}
	if environments != policy.NonDisposableEnvironmentInventory.Fingerprint {
		return guardError(ErrInvalidGuardInput, "policy.nonDisposableEnvironmentInventory", "does not match the supplied complete environment set")
	}
	cidrs, err := ProductionCIDRInventoryFingerprint(input.ProductionCIDRs)
	if err != nil {
		return err
	}
	if cidrs != policy.ProductionCIDRInventory.Fingerprint {
		return guardError(ErrInvalidGuardInput, "policy.productionCIDRInventory", "does not match the supplied complete CIDR set")
	}
	return nil
}

func validatePreMutationProject(projectID string, input PreMutationInput, targets []MutationTarget) error {
	requireProject := func(path string, identity ResourceIdentity) error {
		if identity.Project != projectID {
			return guardError(ErrInvalidGuardInput, path, "does not match the configured project")
		}
		return nil
	}
	for index, target := range targets {
		if err := requireProject(indexedField("targets", index)+".identity.project", target.Identity); err != nil {
			return err
		}
	}
	for index, instance := range input.Capacity.Instances {
		if err := requireProject(indexedField("capacity.instances", index)+".identity.project", instance.Identity); err != nil {
			return err
		}
	}
	for index, disk := range input.Capacity.Disks {
		if err := requireProject(indexedField("capacity.disks", index)+".identity.project", disk.Identity); err != nil {
			return err
		}
	}
	for index, rule := range input.FirewallRules {
		path := indexedField("firewallRules", index)
		if err := requireProject(path+".identity.project", rule.Identity); err != nil {
			return err
		}
		if err := requireProject(path+".network.project", rule.Network); err != nil {
			return err
		}
	}
	for index, observation := range input.Permissions.Expected {
		if err := requireProject(indexedField("permissions.expected", index)+".resource.project", observation.Resource); err != nil {
			return err
		}
	}
	for index, observation := range input.Permissions.Observed {
		if err := requireProject(indexedField("permissions.observed", index)+".resource.project", observation.Resource); err != nil {
			return err
		}
	}
	return nil
}

func validateInventoryPin(path string, pin PolicyInventoryPin) error {
	if !canonicalIDPattern.MatchString(pin.ID) || !inventoryVersionPattern.MatchString(pin.Version) || !isSHA256Fingerprint(pin.Fingerprint) {
		return guardError(ErrInvalidGuardInput, path, "must contain a canonical name, version, and SHA-256 fingerprint")
	}
	return nil
}

// NonDisposableEnvironmentInventoryFingerprint hashes a validated complete
// policy inventory. Completeness is guaranteed only when a trusted policy
// boundary pins the returned digest.
func NonDisposableEnvironmentInventoryFingerprint(values []EnvironmentIdentity) (string, error) {
	if len(values) == 0 {
		return "", guardError(ErrInvalidGuardInput, "expectedEnvironments", "must not be empty")
	}
	canonical := append([]EnvironmentIdentity(nil), values...)
	seen := make(map[string]struct{}, len(canonical))
	for index, value := range canonical {
		if !environmentNamePattern.MatchString(value.Environment) || value.Environment == config.TestEnvironmentLabel ||
			!value.Class.Valid() || value.Class == domain.EnvironmentDisposable {
			return "", guardError(ErrInvalidGuardInput, indexedField("expectedEnvironments", index), "must identify a non-disposable environment")
		}
		if _, exists := seen[value.Environment]; exists {
			return "", guardError(ErrInvalidGuardInput, indexedField("expectedEnvironments", index), "duplicates an earlier environment")
		}
		seen[value.Environment] = struct{}{}
	}
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Environment != canonical[j].Environment {
			return canonical[i].Environment < canonical[j].Environment
		}
		return canonical[i].Class < canonical[j].Class
	})
	return canonicalJSONFingerprint(canonical)
}

// ProductionCIDRInventoryFingerprint hashes canonical discovered production
// CIDRs. Only a separately trusted policy pin makes the set authoritative.
func ProductionCIDRInventoryFingerprint(values []string) (string, error) {
	if len(values) == 0 {
		return "", guardError(ErrInvalidGuardInput, "productionCIDRs", "must not be empty")
	}
	if err := validateProductionCIDRs(values); err != nil {
		return "", err
	}
	canonical := append([]string(nil), values...)
	sort.Strings(canonical)
	return canonicalJSONFingerprint(canonical)
}

func canonicalJSONFingerprint(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", guardError(ErrInvalidGuardInput, "inventory", "could not be fingerprinted")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func isSHA256Fingerprint(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

type preMutationPayload struct {
	Policy                            PreMutationPolicy
	Operation                         OperationBinding
	RunID                             string
	Targets                           []MutationTarget
	Capacity                          CapacityProofInput
	TestCIDR                          string
	ProductionCIDRs                   []string
	ExpectedNonDisposableEnvironments []EnvironmentIdentity
	Locks                             []EnvironmentLock
	HarnessPrincipal                  Principal
	MutationPrincipal                 Principal
	MutationIntents                   []MutationIntent
	Permissions                       PermissionProofInput
	FirewallRules                     []FirewallRule
	RunLifetime                       RunLifetimeContract
	EvidenceRevision                  string
}

func preMutationFingerprint(
	policy PreMutationPolicy,
	input PreMutationInput,
	targets []MutationTarget,
	intents []MutationIntent,
) ([sha256.Size]byte, error) {
	payload := preMutationPayload{
		Policy:                            policy,
		Operation:                         input.Operation,
		RunID:                             input.RunID,
		Targets:                           append([]MutationTarget(nil), targets...),
		Capacity:                          cloneCapacityProof(input.Capacity),
		TestCIDR:                          input.TestCIDR,
		ProductionCIDRs:                   append([]string(nil), input.ProductionCIDRs...),
		ExpectedNonDisposableEnvironments: append([]EnvironmentIdentity(nil), input.ExpectedNonDisposableEnvironments...),
		Locks:                             append([]EnvironmentLock(nil), input.Locks...),
		HarnessPrincipal:                  input.HarnessPrincipal,
		MutationPrincipal:                 input.MutationPrincipal,
		MutationIntents:                   cloneMutationIntents(intents),
		Permissions: PermissionProofInput{
			Expected: append([]PermissionObservation(nil), input.Permissions.Expected...),
			Observed: append([]PermissionObservation(nil), input.Permissions.Observed...),
		},
		FirewallRules:    cloneFirewallRules(input.FirewallRules),
		RunLifetime:      input.RunLifetime,
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
	sort.Slice(payload.MutationIntents, func(i, j int) bool {
		return payload.MutationIntents[i].Target.Identity.CanonicalKey < payload.MutationIntents[j].Target.Identity.CanonicalKey
	})
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
		rule.Allowed = cloneFirewallTrafficRules(rule.Allowed)
		rule.Denied = cloneFirewallTrafficRules(rule.Denied)
		rule.DestinationCIDRs = append([]string(nil), rule.DestinationCIDRs...)
		rule.SourceCIDRs = append([]string(nil), rule.SourceCIDRs...)
		rule.SourceTags = append([]string(nil), rule.SourceTags...)
		rule.SourceServiceAccounts = append([]string(nil), rule.SourceServiceAccounts...)
		rule.TargetTags = append([]string(nil), rule.TargetTags...)
		rule.TargetServiceAccounts = append([]string(nil), rule.TargetServiceAccounts...)
		rule.ResourceManagerTags = maps.Clone(rule.ResourceManagerTags)
		cloned[index] = rule
	}
	return cloned
}

func cloneFirewallTrafficRules(rules []FirewallTrafficRule) []FirewallTrafficRule {
	cloned := make([]FirewallTrafficRule, len(rules))
	for index, rule := range rules {
		rule.Ports = append([]uint16(nil), rule.Ports...)
		cloned[index] = rule
	}
	return cloned
}

func cloneMutationIntents(intents []MutationIntent) []MutationIntent {
	cloned := make([]MutationIntent, len(intents))
	for index, intent := range intents {
		cloned[index] = cloneMutationIntent(intent)
	}
	return cloned
}

func cloneMutationIntent(intent MutationIntent) MutationIntent {
	intent.Target = cloneMutationTarget(intent.Target)
	if intent.Create.Firewall != nil {
		firewall := cloneFirewallRules([]FirewallRule{*intent.Create.Firewall})[0]
		intent.Create.Firewall = &firewall
	}
	return intent
}

func authorizeMutationIntents(intents []MutationIntent) []AuthorizedMutationIntent {
	authorized := make([]AuthorizedMutationIntent, len(intents))
	for index, intent := range intents {
		cloned := cloneMutationIntent(intent)
		authorized[index] = AuthorizedMutationIntent{
			action:                cloned.Action,
			target:                cloned.Target,
			requiredPrincipalRole: cloned.RequiredPrincipalRole,
			create:                cloned.Create,
		}
	}
	return authorized
}

func cloneAuthorizedMutationIntents(intents []AuthorizedMutationIntent) []AuthorizedMutationIntent {
	cloned := make([]AuthorizedMutationIntent, len(intents))
	for index, intent := range intents {
		proposed := MutationIntent{
			Action:                intent.action,
			Target:                intent.target,
			RequiredPrincipalRole: intent.requiredPrincipalRole,
			Create:                intent.create,
		}
		detached := authorizeMutationIntents([]MutationIntent{proposed})[0]
		cloned[index] = detached
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

func validateKnownResourceScope(identity ResourceIdentity) error {
	if identity.Service == ComputeServiceName {
		switch identity.Kind {
		case ComputeInstanceKind:
			if identity.Scope != ResourceScopeZone {
				return guardError(ErrInvalidGuardInput, "target.identity.scope", "Compute instances must be zonal")
			}
		case ComputeDiskKind:
			if identity.Scope != ResourceScopeZone && identity.Scope != ResourceScopeRegion {
				return guardError(ErrInvalidGuardInput, "target.identity.scope", "Compute disks must be zonal or regional")
			}
		case ComputeFirewallKind, ComputeNetworkKind:
			if identity.Scope != ResourceScopeGlobal {
				return guardError(ErrInvalidGuardInput, "target.identity.scope", "Compute networks and firewalls must be global")
			}
		}
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
