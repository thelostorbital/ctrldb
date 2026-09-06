// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const OwnershipRecordSchemaV1 = "ctrldb.ctrlboard.dev/ownership/v1"

var ErrInvalidOwnershipProof = errors.New("invalid isolation ownership proof")

// CleanupCapability is a resource kind for which create, ownership, ordering,
// and delete behavior have all been implemented. It is intentionally closed.
type CleanupCapability string

const (
	CleanupComputeInstances CleanupCapability = "compute.instances"
	CleanupComputeDisks     CleanupCapability = "compute.disks"
	CleanupComputeFirewalls CleanupCapability = "compute.firewalls"
)

var initialCleanupCapabilities = [...]CleanupCapability{
	CleanupComputeDisks,
	CleanupComputeFirewalls,
	CleanupComputeInstances,
}

// InitialCleanupCapabilities returns a detached, canonical copy of D-159's
// initial mutation-and-cleanup capability set.
func InitialCleanupCapabilities() []CleanupCapability {
	return append([]CleanupCapability(nil), initialCleanupCapabilities[:]...)
}

// ValidateCleanupCapabilities requires exactly the closed initial set. A
// missing, duplicate, reordered, or unknown entry changes the state binding.
func ValidateCleanupCapabilities(values []CleanupCapability) error {
	if len(values) != len(initialCleanupCapabilities) {
		return guardError(ErrInvalidOwnershipProof, "cleanupCapabilities", "does not contain the complete supported set")
	}
	for index, expected := range initialCleanupCapabilities {
		if values[index] != expected {
			return guardError(ErrInvalidOwnershipProof, indexedField("cleanupCapabilities", index), "does not match the canonical supported set")
		}
	}
	return nil
}

func cleanupCapabilityFor(identity ResourceIdentity) (CleanupCapability, bool) {
	if identity.Service != ComputeServiceName {
		return "", false
	}
	switch identity.Kind {
	case ComputeInstanceKind:
		return CleanupComputeInstances, true
	case ComputeDiskKind:
		return CleanupComputeDisks, true
	case ComputeFirewallKind:
		return CleanupComputeFirewalls, true
	default:
		return "", false
	}
}

func labelCapableCleanupIdentity(identity ResourceIdentity) bool {
	capability, ok := cleanupCapabilityFor(identity)
	return ok && capability != CleanupComputeFirewalls
}

// SelectRunFirewallMutationTargets proves only the provider identity portion
// of classic firewall insert targets. Description, lifetime, durable-record,
// expiry, and complete desired-state proof are enforced by FirewallRule and
// FirewallValidationContext; ordinary labels are forbidden because the
// classic Compute Firewall resource has no such field.
func SelectRunFirewallMutationTargets(runID string, resources []MutationTarget) ([]MutationTarget, error) {
	if _, err := RunResourcePrefix(runID); err != nil {
		return nil, err
	}
	selected := make([]MutationTarget, 0, len(resources))
	seen := make(map[string]struct{}, len(resources))
	for index, resource := range resources {
		path := indexedField("targets", index)
		if err := validateResourceIdentity(resource.Identity); err != nil {
			return nil, guardError(err, path, "has invalid full identity")
		}
		if resource.Identity.Service != ComputeServiceName || resource.Identity.Kind != ComputeFirewallKind ||
			resource.Identity.Scope != ResourceScopeGlobal || resource.Identity.Location != "global" {
			return nil, guardError(ErrUnsafeFirewall, path, "is not a classic global Compute firewall")
		}
		if len(resource.Labels) != 0 {
			return nil, guardError(ErrUnsafeFirewall, path, "must not invent ordinary labels for a classic firewall")
		}
		if !isExactRunFirewallName(resource.Identity.Name, runID) {
			return nil, guardError(ErrUnsafeFirewall, path, "is not one of the two exact run firewall identities")
		}
		if _, duplicate := seen[resource.Identity.CanonicalKey]; duplicate {
			return nil, guardError(ErrInvalidGuardInput, path, "duplicates an earlier target")
		}
		seen[resource.Identity.CanonicalKey] = struct{}{}
		selected = append(selected, cloneMutationTarget(resource))
	}
	sort.SliceStable(selected, func(i, j int) bool {
		return selected[i].Identity.CanonicalKey < selected[j].Identity.CanonicalKey
	})
	return selected, nil
}

// PermanentOwnershipRecordV1 is the durable control-store claim for one
// non-age-wiped harness singleton. All fingerprints are over complete,
// canonical desired values; raw provider descriptions are not retained here.
type PermanentOwnershipRecordV1 struct {
	SchemaVersion           string
	RecordID                string
	RecordGeneration        uint64
	Identity                ResourceIdentity
	ProviderID              string
	DesiredStateFingerprint string
	DescriptionFingerprint  string
}

// PermanentSingletonExpectation is the independently trusted identity and
// complete desired state derived from HarnessConfiguration and the sealed
// plan. It contains no provider-sourced identity.
type PermanentSingletonExpectation struct {
	Identity                ResourceIdentity
	DesiredStateFingerprint string
	DescriptionFingerprint  string
}

// PermanentSingletonObservation is a complete, bounded provider observation
// supplied by the future typed discovery adapter.
type PermanentSingletonObservation struct {
	Identity                ResourceIdentity
	ProviderID              string
	DesiredStateFingerprint string
	DescriptionFingerprint  string
	Revision                string
	ObservedAt              time.Time
	ValidUntil              time.Time
}

// PermanentSingletonProof binds desired identity, a fresh complete provider
// observation, and the matching durable ownership record. Observation expiry
// proves mutation-boundary freshness only; permanent singletons are never
// age-wipe candidates.
type PermanentSingletonProof struct {
	ProjectID string
	Expected  PermanentSingletonExpectation
	Observed  PermanentSingletonObservation
	Record    PermanentOwnershipRecordV1
}

// ValidatePermanentSingletonOwnership rejects adoption by name alone and any
// cross-project, partial, unknown-kind, state, description, or record drift.
func ValidatePermanentSingletonOwnership(proof PermanentSingletonProof, now time.Time) error {
	if !projectIDPattern.MatchString(proof.ProjectID) {
		return guardError(ErrInvalidOwnershipProof, "projectID", "must be an explicit canonical project")
	}
	if now.IsZero() {
		return guardError(ErrInvalidOwnershipProof, "now", "must be an explicit mutation-boundary time")
	}
	if _, offset := now.Zone(); offset != 0 {
		return guardError(ErrInvalidOwnershipProof, "now", "must use UTC")
	}
	if err := validatePermanentSingletonExpectation(proof.ProjectID, proof.Expected); err != nil {
		return err
	}
	if err := validatePermanentSingletonObservation(proof.ProjectID, proof.Observed, now); err != nil {
		return err
	}
	if proof.Observed.Identity != proof.Expected.Identity ||
		proof.Observed.DesiredStateFingerprint != proof.Expected.DesiredStateFingerprint ||
		proof.Observed.DescriptionFingerprint != proof.Expected.DescriptionFingerprint {
		return guardError(ErrInvalidOwnershipProof, "observed", "does not equal the complete desired singleton state")
	}
	record := proof.Record
	if record.SchemaVersion != OwnershipRecordSchemaV1 || !canonicalIDPattern.MatchString(record.RecordID) || record.RecordGeneration == 0 {
		return guardError(ErrInvalidOwnershipProof, "record", "does not identify a supported durable record generation")
	}
	if record.Identity != proof.Expected.Identity || record.ProviderID != proof.Observed.ProviderID ||
		record.DesiredStateFingerprint != proof.Expected.DesiredStateFingerprint ||
		record.DescriptionFingerprint != proof.Expected.DescriptionFingerprint {
		return guardError(ErrInvalidOwnershipProof, "record", "does not match the desired singleton")
	}
	return nil
}

func validatePermanentSingletonExpectation(projectID string, value PermanentSingletonExpectation) error {
	if err := validateResourceIdentity(value.Identity); err != nil || value.Identity.Project != projectID ||
		!supportedPermanentSingletonIdentity(value.Identity) {
		return guardError(ErrInvalidOwnershipProof, "expected.identity", "is not an independently trusted harness singleton identity")
	}
	return validatePermanentSingletonFingerprints("expected", value.Identity, value.DesiredStateFingerprint, value.DescriptionFingerprint)
}

func validatePermanentSingletonObservation(projectID string, value PermanentSingletonObservation, now time.Time) error {
	if err := validateResourceIdentity(value.Identity); err != nil || value.Identity.Project != projectID ||
		!supportedPermanentSingletonIdentity(value.Identity) {
		return guardError(ErrInvalidOwnershipProof, "observed.identity", "is not the expected project singleton identity")
	}
	if value.ProviderID == "" || strings.TrimSpace(value.ProviderID) != value.ProviderID || !isSHA256Fingerprint(value.Revision) {
		return guardError(ErrInvalidOwnershipProof, "observed", "requires provider ID and an exhaustive observation revision")
	}
	if err := validateUTCWindow(value.ObservedAt, value.ValidUntil, MaxPreMutationProofLifetime); err != nil ||
		now.Before(value.ObservedAt) || !now.Before(value.ValidUntil) {
		return guardError(ErrInvalidOwnershipProof, "observed", "is not a fresh bounded provider observation")
	}
	return validatePermanentSingletonFingerprints("observed", value.Identity, value.DesiredStateFingerprint, value.DescriptionFingerprint)
}

func validatePermanentSingletonFingerprints(path string, identity ResourceIdentity, state, description string) error {
	if !isSHA256Fingerprint(state) {
		return guardError(ErrInvalidOwnershipProof, path+".desiredStateFingerprint", "must bind complete desired state")
	}
	if permanentSingletonSupportsDescription(identity) && !isSHA256Fingerprint(description) {
		return guardError(ErrInvalidOwnershipProof, path+".descriptionFingerprint", "is required for this provider kind")
	}
	if !permanentSingletonSupportsDescription(identity) && description != "" {
		return guardError(ErrInvalidOwnershipProof, path+".descriptionFingerprint", "must be absent for this provider kind")
	}
	return nil
}

func permanentSingletonSupportsDescription(identity ResourceIdentity) bool {
	switch {
	case identity.Service == ComputeServiceName && identity.Kind == ComputeRouterNATKind:
		return false
	case identity.Service == RunServiceName && identity.Kind == RunJobKind:
		return false
	default:
		return true
	}
}

func supportedPermanentSingletonIdentity(identity ResourceIdentity) bool {
	switch identity.Service {
	case ComputeServiceName:
		switch identity.Kind {
		case ComputeNetworkKind:
			return identity.Scope == ResourceScopeGlobal
		case ComputeFirewallKind:
			return identity.Scope == ResourceScopeGlobal &&
				(identity.Name == TestIAPSSHFirewallName || identity.Name == TestInternalFirewallName)
		case ComputeSubnetworkKind, ComputeRouterKind, ComputeRouterNATKind:
			return identity.Scope == ResourceScopeRegion
		}
	case IAMServiceName:
		return identity.Scope == ResourceScopeGlobal &&
			(identity.Kind == IAMServiceAccountKind || identity.Kind == IAMRoleKind)
	case RunServiceName:
		return identity.Scope == ResourceScopeRegion && identity.Kind == RunJobKind
	case SchedulerServiceName:
		return identity.Scope == ResourceScopeRegion && identity.Kind == SchedulerJobKind
	}
	return false
}

// RunFirewallCleanupTarget contains the non-label ownership evidence required
// before a classic firewall may be selected by teardown or the nightly wipe.
type RunFirewallCleanupTarget struct {
	Identity    ResourceIdentity
	Description string
	RunLifetime RunLifetimeContract
	ObservedAt  time.Time
}

// RunFirewallCleanupMode distinguishes an approved operation's immediate
// teardown from the nightly wipe's expiry-based selection. The future mutation
// gateway is responsible for deriving this closed value from the admitted
// workflow; arbitrary provider callers never receive this API directly.
type RunFirewallCleanupMode string

const (
	RunFirewallCleanupRecordedTeardown RunFirewallCleanupMode = "recorded-teardown"
	RunFirewallCleanupExpiredWipe      RunFirewallCleanupMode = "expired-wipe"
)

// ValidateRunFirewallCleanupTarget verifies project, scope, exact run prefix,
// immutable description, durable record, and expiry. It never accepts labels
// as a substitute for the lifetime record.
func ValidateRunFirewallCleanupTarget(policy CleanupPolicy, target RunFirewallCleanupTarget, mode RunFirewallCleanupMode, now time.Time, maxLifetime time.Duration) error {
	if !projectIDPattern.MatchString(policy.ProjectID) || now.IsZero() || maxLifetime <= 0 {
		return guardError(ErrInvalidOwnershipProof, "cleanup", "requires explicit project and time")
	}
	if mode != RunFirewallCleanupRecordedTeardown && mode != RunFirewallCleanupExpiredWipe {
		return guardError(ErrInvalidOwnershipProof, "cleanupMode", "is not a supported cleanup authority")
	}
	if _, offset := now.Zone(); offset != 0 {
		return guardError(ErrInvalidOwnershipProof, "now", "must use UTC")
	}
	if err := validateResourceIdentity(target.Identity); err != nil || target.Identity.Project != policy.ProjectID ||
		target.Identity.Service != ComputeServiceName || target.Identity.Kind != ComputeFirewallKind ||
		target.Identity.Scope != ResourceScopeGlobal {
		return guardError(ErrInvalidOwnershipProof, "identity", "is not the exact configured-project classic firewall")
	}
	if !isExactRunFirewallName(target.Identity.Name, target.RunLifetime.RunID) {
		return guardError(ErrInvalidOwnershipProof, "identity.name", "is not one of the two exact durable-record firewall identities")
	}
	fingerprint, err := RunLifetimeContractFingerprint(target.RunLifetime)
	if err != nil {
		return fmt.Errorf("%w: invalid durable lifetime record", ErrInvalidOwnershipProof)
	}
	description, _ := RunFirewallDescription(fingerprint)
	if target.RunLifetime.ProjectID != policy.ProjectID {
		return guardError(ErrInvalidOwnershipProof, "runLifetime.projectID", "does not match the cleanup project")
	}
	if target.Description != description {
		return guardError(ErrInvalidOwnershipProof, "description", "does not match the durable lifetime record")
	}
	if target.ObservedAt.IsZero() || target.ObservedAt.After(now) || target.ObservedAt.Before(target.RunLifetime.CreatedAt) ||
		now.Sub(target.ObservedAt) > MaxPreMutationProofLifetime {
		return guardError(ErrInvalidOwnershipProof, "observedAt", "does not bind a current complete observation")
	}
	if _, offset := target.ObservedAt.Zone(); offset != 0 {
		return guardError(ErrInvalidOwnershipProof, "observedAt", "must use UTC")
	}
	if target.RunLifetime.ExpiresAt.Sub(target.RunLifetime.CreatedAt) <= 0 ||
		target.RunLifetime.ExpiresAt.Sub(target.RunLifetime.CreatedAt) > maxLifetime {
		return guardError(ErrInvalidOwnershipProof, "expiresAt", "exceeds the configured maximum lifetime")
	}
	if mode == RunFirewallCleanupExpiredWipe && now.Before(target.RunLifetime.ExpiresAt) {
		return guardError(ErrInvalidOwnershipProof, "expiresAt", "has not reached its recorded expiry")
	}
	return nil
}

func isExactRunFirewallName(name, runID string) bool {
	for _, purpose := range []FirewallPurpose{FirewallPurposeIAPSSH, FirewallPurposeInternalMongo} {
		expected, err := RunFirewallRuleName(runID, purpose)
		if err == nil && name == expected {
			return true
		}
	}
	return false
}
