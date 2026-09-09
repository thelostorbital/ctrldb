// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package cleanup selects and orders WF-TEST-01 nightly-wipe deletions from an
// exhaustive typed inventory. It performs no process execution, provider I/O,
// or durable I/O: a provider adapter supplies the inventory, a control-store
// adapter supplies durable records, and the package returns sealed deletions
// which only that same adapter family may execute.
package cleanup

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

const (
	// ModeTestWipe is the only cleanup mode implemented by M1-08.
	ModeTestWipe = "test-wipe"
	// MaxInventoryLifetime bounds how old an inventory may be at the mutation
	// boundary. It equals the isolation package's pre-mutation proof lifetime
	// because every firewall proof is re-validated against the same clock.
	MaxInventoryLifetime = isolation.MaxPreMutationProofLifetime
	// MaxWipeLifetime bounds the configured age threshold so a corrupted policy
	// cannot postpone cleanup indefinitely or make every resource expired.
	MaxWipeLifetime = 24 * time.Hour
	// MinWipeLifetime rejects a threshold so small that a resource created by
	// an in-flight approved operation would be selected immediately.
	MinWipeLifetime = 15 * time.Minute
)

var (
	ErrInvalidWipeInput = errors.New("invalid test wipe input")
	ErrInventoryRefused = errors.New("test wipe inventory refused")
)

var (
	projectIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	sha256Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// WipePolicy is the trusted boundary supplied from fixed job configuration.
// It carries no provider defaults; a missing value fails closed.
type WipePolicy struct {
	ProjectID   string
	MaxLifetime time.Duration
}

// InstanceObservation is one complete Compute instance observation.
type InstanceObservation struct {
	Identity      isolation.ResourceIdentity
	Labels        map[string]string
	CreatedAt     time.Time
	AttachedDisks []string
}

// DiskObservation is one complete Compute disk observation. AttachedInstances
// lists the exact instance names currently using the disk.
type DiskObservation struct {
	Identity          isolation.ResourceIdentity
	Labels            map[string]string
	CreatedAt         time.Time
	AttachedInstances []string
}

// FirewallObservation is one complete classic Compute firewall observation.
// Classic firewalls have no ordinary labels; ownership comes from the exact
// description and the durable lifetime record.
type FirewallObservation struct {
	Identity    isolation.ResourceIdentity
	Description string
	CreatedAt   time.Time
}

// UnsupportedObservation is any test-namespace resource of a kind outside the
// closed cleanup capability set. Its presence refuses the whole inventory.
type UnsupportedObservation struct {
	Identity isolation.ResourceIdentity
}

// Inventory is the exhaustive observation of the configured project at one
// instant. A non-exhaustive or stale inventory selects nothing.
type Inventory struct {
	ProjectID   string
	Revision    string
	ObservedAt  time.Time
	ValidUntil  time.Time
	Exhaustive  bool
	Instances   []InstanceObservation
	Disks       []DiskObservation
	Firewalls   []FirewallObservation
	Unsupported []UnsupportedObservation
}

// LifetimeRecord pairs one durable run lifetime record with the fresh
// generation observation of the object which holds it.
type LifetimeRecord struct {
	Contract isolation.RunLifetimeContract
	Expected isolation.OwnershipRecordExpectation
}

func validatePolicy(policy WipePolicy) error {
	if !projectIDPattern.MatchString(policy.ProjectID) {
		return inputError("policy.projectID", "must be an explicit canonical project ID")
	}
	if policy.MaxLifetime < MinWipeLifetime || policy.MaxLifetime > MaxWipeLifetime {
		return inputError("policy.maxLifetime", "must be between 15 minutes and 24 hours")
	}
	return nil
}

func validateNow(now time.Time) error {
	if now.IsZero() {
		return inputError("now", "must be an explicit mutation-boundary time")
	}
	if _, offset := now.Zone(); offset != 0 {
		return inputError("now", "must use UTC")
	}
	return nil
}

func validateInventoryWindow(policy WipePolicy, inventory Inventory, now time.Time) error {
	if inventory.ProjectID != policy.ProjectID {
		return refusal("inventory.projectID", "does not name the configured project")
	}
	if !inventory.Exhaustive {
		return refusal("inventory", "is not exhaustive")
	}
	if !sha256Pattern.MatchString(inventory.Revision) {
		return refusal("inventory.revision", "must be a SHA-256 content revision")
	}
	if err := validateUTCTimestamp(inventory.ObservedAt); err != nil || validateUTCTimestamp(inventory.ValidUntil) != nil {
		return refusal("inventory.window", "must be a complete UTC window")
	}
	if !inventory.ValidUntil.After(inventory.ObservedAt) || inventory.ValidUntil.Sub(inventory.ObservedAt) > MaxInventoryLifetime {
		return refusal("inventory.window", "must be a bounded observation window")
	}
	if now.Before(inventory.ObservedAt) || !now.Before(inventory.ValidUntil) {
		return refusal("inventory.window", "is not fresh at the mutation boundary")
	}
	if len(inventory.Unsupported) != 0 {
		return refusal("inventory.unsupported", "contains a test-namespace resource of an unsupported kind")
	}
	return nil
}

func validateUTCTimestamp(value time.Time) error {
	if value.IsZero() {
		return ErrInvalidWipeInput
	}
	if _, offset := value.Zone(); offset != 0 {
		return ErrInvalidWipeInput
	}
	return nil
}

// validateObservedIdentity requires an explicit, canonical, configured-project
// identity of the expected provider kind. Every entry in the inventory must
// pass, including foreign resources which are later ignored.
func validateObservedIdentity(policy WipePolicy, path string, identity isolation.ResourceIdentity, kind isolation.ResourceKind) error {
	wantKey, err := isolation.CanonicalTargetKey(identity)
	if err != nil || identity.CanonicalKey != wantKey {
		return refusal(path, "does not carry a complete canonical identity")
	}
	if identity.Project != policy.ProjectID {
		return refusal(path, "names another project")
	}
	if identity.Service != isolation.ComputeServiceName || identity.Kind != kind {
		return refusal(path, "is not the expected Compute resource kind")
	}
	return nil
}

func validateObservedTimestamp(path string, createdAt, now time.Time) error {
	if validateUTCTimestamp(createdAt) != nil || createdAt.After(now) {
		return refusal(path+".createdAt", "must be a non-future UTC creation time")
	}
	return nil
}

func sortedNames(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func indexedField(base string, index int) string {
	return fmt.Sprintf("%s[%d]", base, index)
}

func inputError(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidWipeInput, path, reason)
}

func refusal(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInventoryRefused, path, reason)
}
