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
	prefix, err := RunResourcePrefix(runID)
	if err != nil {
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
		if !strings.HasPrefix(resource.Identity.Name, prefix) || len(resource.Identity.Name) == len(prefix) {
			return nil, guardError(ErrUnsafeFirewall, path, "does not have the exact run prefix")
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

// PermanentSingletonObservation is a complete provider observation supplied
// by the future typed discovery adapter.
type PermanentSingletonObservation struct {
	Identity                ResourceIdentity
	ProviderID              string
	DesiredStateFingerprint string
	DescriptionFingerprint  string
}

// PermanentSingletonProof binds desired identity, complete observed state,
// and the matching durable ownership record. It deliberately has no age or
// expiry field: permanent singletons are never wipe candidates.
type PermanentSingletonProof struct {
	ProjectID string
	Desired   PermanentSingletonObservation
	Observed  PermanentSingletonObservation
	Record    PermanentOwnershipRecordV1
}

// ValidatePermanentSingletonOwnership rejects adoption by name alone and any
// cross-project, partial, unknown-kind, state, description, or record drift.
func ValidatePermanentSingletonOwnership(proof PermanentSingletonProof) error {
	if !projectIDPattern.MatchString(proof.ProjectID) {
		return guardError(ErrInvalidOwnershipProof, "projectID", "must be an explicit canonical project")
	}
	for _, entry := range []struct {
		path  string
		value PermanentSingletonObservation
	}{{path: "desired", value: proof.Desired}, {path: "observed", value: proof.Observed}} {
		path, value := entry.path, entry.value
		if err := validatePermanentSingletonObservation(path, value); err != nil {
			return err
		}
		if value.Identity.Project != proof.ProjectID {
			return guardError(ErrInvalidOwnershipProof, path+".identity.project", "does not match the configured project")
		}
	}
	if proof.Desired != proof.Observed {
		return guardError(ErrInvalidOwnershipProof, "observed", "does not equal the complete desired singleton state")
	}
	record := proof.Record
	if record.SchemaVersion != OwnershipRecordSchemaV1 || !canonicalIDPattern.MatchString(record.RecordID) || record.RecordGeneration == 0 {
		return guardError(ErrInvalidOwnershipProof, "record", "does not identify a supported durable record generation")
	}
	if record.Identity != proof.Desired.Identity || record.ProviderID != proof.Desired.ProviderID ||
		record.DesiredStateFingerprint != proof.Desired.DesiredStateFingerprint ||
		record.DescriptionFingerprint != proof.Desired.DescriptionFingerprint {
		return guardError(ErrInvalidOwnershipProof, "record", "does not match the desired singleton")
	}
	return nil
}

func validatePermanentSingletonObservation(path string, value PermanentSingletonObservation) error {
	if err := validateResourceIdentity(value.Identity); err != nil {
		return guardError(ErrInvalidOwnershipProof, path+".identity", "is incomplete")
	}
	if !supportedPermanentSingletonIdentity(value.Identity) {
		return guardError(ErrInvalidOwnershipProof, path+".identity", "uses an unsupported permanent singleton kind")
	}
	if value.ProviderID == "" || strings.TrimSpace(value.ProviderID) != value.ProviderID ||
		!isSHA256Fingerprint(value.DesiredStateFingerprint) {
		return guardError(ErrInvalidOwnershipProof, path, "requires provider ID and a complete state fingerprint")
	}
	if permanentSingletonSupportsDescription(value.Identity) {
		if !isSHA256Fingerprint(value.DescriptionFingerprint) {
			return guardError(ErrInvalidOwnershipProof, path+".descriptionFingerprint", "is required for this provider kind")
		}
	} else if value.DescriptionFingerprint != "" {
		return guardError(ErrInvalidOwnershipProof, path+".descriptionFingerprint", "must be absent for this provider kind")
	}
	return nil
}

func permanentSingletonSupportsDescription(identity ResourceIdentity) bool {
	return !(identity.Service == ComputeServiceName && identity.Kind == ComputeRouterNATKind) &&
		!(identity.Service == RunServiceName && identity.Kind == RunJobKind)
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

// ValidateRunFirewallCleanupTarget verifies project, scope, exact run prefix,
// immutable description, durable record, and expiry. It never accepts labels
// as a substitute for the lifetime record.
func ValidateRunFirewallCleanupTarget(policy CleanupPolicy, target RunFirewallCleanupTarget, now time.Time, maxLifetime time.Duration) error {
	if !projectIDPattern.MatchString(policy.ProjectID) || now.IsZero() || maxLifetime <= 0 {
		return guardError(ErrInvalidOwnershipProof, "cleanup", "requires explicit project and time")
	}
	if _, offset := now.Zone(); offset != 0 {
		return guardError(ErrInvalidOwnershipProof, "now", "must use UTC")
	}
	if err := validateResourceIdentity(target.Identity); err != nil || target.Identity.Project != policy.ProjectID ||
		target.Identity.Service != ComputeServiceName || target.Identity.Kind != ComputeFirewallKind ||
		target.Identity.Scope != ResourceScopeGlobal {
		return guardError(ErrInvalidOwnershipProof, "identity", "is not the exact configured-project classic firewall")
	}
	prefix, err := RunResourcePrefix(target.RunLifetime.RunID)
	if err != nil || !strings.HasPrefix(target.Identity.Name, prefix) || len(target.Identity.Name) == len(prefix) {
		return guardError(ErrInvalidOwnershipProof, "identity.name", "does not match the durable record run prefix")
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
	if now.Before(target.RunLifetime.ExpiresAt) {
		return guardError(ErrInvalidOwnershipProof, "expiresAt", "has not reached its recorded expiry")
	}
	return nil
}
