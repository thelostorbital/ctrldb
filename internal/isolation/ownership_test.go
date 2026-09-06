// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

func TestInitialCleanupCapabilitiesAreExactDetachedAndCanonical(t *testing.T) {
	t.Parallel()

	want := []isolation.CleanupCapability{
		isolation.CleanupComputeDisks,
		isolation.CleanupComputeFirewalls,
		isolation.CleanupComputeInstances,
	}
	got := isolation.InitialCleanupCapabilities()
	if len(got) != len(want) {
		t.Fatalf("InitialCleanupCapabilities() length = %d; want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("capability[%d] = %q; want %q", index, got[index], want[index])
		}
	}
	got[0] = "changed"
	if isolation.InitialCleanupCapabilities()[0] != isolation.CleanupComputeDisks {
		t.Fatal("InitialCleanupCapabilities() exposed mutable package state")
	}

	tests := [][]isolation.CleanupCapability{
		nil,
		{isolation.CleanupComputeInstances, isolation.CleanupComputeDisks, isolation.CleanupComputeFirewalls},
		{isolation.CleanupComputeDisks, isolation.CleanupComputeFirewalls, "compute.snapshots"},
		{isolation.CleanupComputeDisks, isolation.CleanupComputeDisks, isolation.CleanupComputeInstances},
	}
	for _, values := range tests {
		if err := isolation.ValidateCleanupCapabilities(values); !errors.Is(err, isolation.ErrInvalidOwnershipProof) {
			t.Fatalf("ValidateCleanupCapabilities(%v) error = %v; want ErrInvalidOwnershipProof", values, err)
		}
	}
	if err := isolation.ValidateCleanupCapabilities(want); err != nil {
		t.Fatalf("ValidateCleanupCapabilities(valid) unexpected error: %v", err)
	}
}

func TestLabelCapableOwnershipRequiresPrefixAndAllLabels(t *testing.T) {
	t.Parallel()

	valid := testTarget("ctrldb-test-run1-instance", "run1")
	if _, err := isolation.SelectRunMutationTargets("run1", []isolation.MutationTarget{valid}); err != nil {
		t.Fatalf("SelectRunMutationTargets() unexpected error: %v", err)
	}

	prefixOnly := valid
	prefixOnly.Labels = nil
	if _, err := isolation.SelectRunMutationTargets("run1", []isolation.MutationTarget{prefixOnly}); !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("prefix-only error = %v; want ErrUnsafeTarget", err)
	}
	labelsOnly := targetWithName(valid, "ctrldb-test-other-instance")
	if _, err := isolation.SelectRunMutationTargets("run1", []isolation.MutationTarget{labelsOnly}); !errors.Is(err, isolation.ErrUnsafeTarget) {
		t.Fatalf("labels-only error = %v; want ErrUnsafeTarget", err)
	}
	firewallWithInventedLabels := testTargetWithIdentity(
		testResourceIdentity("ctrldb-test-run1-iap-ssh", isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global"), "run1",
	)
	if _, err := isolation.SelectRunFirewallMutationTargets("run1", []isolation.MutationTarget{firewallWithInventedLabels}); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("classic firewall with labels error = %v; want ErrUnsafeFirewall", err)
	}
	validFirewall := isolation.MutationTarget{Identity: testResourceIdentity(
		"ctrldb-test-run1-iap-ssh", isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global",
	)}
	if _, err := isolation.SelectRunFirewallMutationTargets("run1", []isolation.MutationTarget{validFirewall}); err != nil {
		t.Fatalf("exact run firewall unexpected error: %v", err)
	}
	wrongSuffix := validFirewall
	wrongSuffix.Identity = testResourceIdentity(
		"ctrldb-test-run1-unplanned", isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global",
	)
	if _, err := isolation.SelectRunFirewallMutationTargets("run1", []isolation.MutationTarget{wrongSuffix}); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("unplanned run firewall error = %v; want ErrUnsafeFirewall", err)
	}
}

func TestPermanentSingletonOwnershipRequiresExactStateAndDurableRecord(t *testing.T) {
	t.Parallel()

	proof := validPermanentSingletonProof()
	if err := isolation.ValidatePermanentSingletonOwnership(proof); err != nil {
		t.Fatalf("ValidatePermanentSingletonOwnership() unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*isolation.PermanentSingletonProof)
	}{
		{name: "cross project", mutate: func(value *isolation.PermanentSingletonProof) {
			value.Observed.Identity = resourceIdentityForProject(value.Observed.Identity.Name, isolation.ComputeNetworkKind, isolation.ResourceScopeGlobal, "global", "different-project")
		}},
		{name: "provider ID drift", mutate: func(value *isolation.PermanentSingletonProof) { value.Observed.ProviderID = "provider-id-2" }},
		{name: "state drift", mutate: func(value *isolation.PermanentSingletonProof) {
			value.Observed.DesiredStateFingerprint = strings.Repeat("d", 64)
		}},
		{name: "description drift", mutate: func(value *isolation.PermanentSingletonProof) {
			value.Observed.DescriptionFingerprint = strings.Repeat("e", 64)
		}},
		{name: "malformed record ID", mutate: func(value *isolation.PermanentSingletonProof) { value.Record.RecordID = " not-canonical " }},
		{name: "missing durable generation", mutate: func(value *isolation.PermanentSingletonProof) { value.Record.RecordGeneration = 0 }},
		{name: "record identity drift", mutate: func(value *isolation.PermanentSingletonProof) { value.Record.ProviderID = "other" }},
		{name: "unknown kind", mutate: func(value *isolation.PermanentSingletonProof) {
			identity := resourceIdentityForProject("ctrldb-test-widget", isolation.ResourceKind("widgets"), isolation.ResourceScopeGlobal, "global", "example-test-project")
			value.ExpectedIdentity = identity
			value.Desired.Identity, value.Observed.Identity, value.Record.Identity = identity, identity, identity
		}},
		{name: "trusted identity mismatch", mutate: func(value *isolation.PermanentSingletonProof) {
			value.ExpectedIdentity = testResourceIdentity("ctrldb-test-other-vpc", isolation.ComputeNetworkKind, isolation.ResourceScopeGlobal, "global")
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validPermanentSingletonProof()
			test.mutate(&value)
			if err := isolation.ValidatePermanentSingletonOwnership(value); !errors.Is(err, isolation.ErrInvalidOwnershipProof) {
				t.Fatalf("error = %v; want ErrInvalidOwnershipProof", err)
			}
		})
	}
}

func TestPermanentSingletonWithoutProviderDescriptionRequiresNoInventedFingerprint(t *testing.T) {
	t.Parallel()

	identity := testResourceIdentity("ctrldb-test-nat", isolation.ComputeRouterNATKind, isolation.ResourceScopeRegion, "us-central1")
	observation := isolation.PermanentSingletonObservation{
		Identity: identity, ProviderID: "provider-id-nat", DesiredStateFingerprint: strings.Repeat("a", 64),
	}
	proof := isolation.PermanentSingletonProof{
		ProjectID: "example-test-project", ExpectedIdentity: identity, Desired: observation, Observed: observation,
		Record: isolation.PermanentOwnershipRecordV1{
			SchemaVersion: isolation.OwnershipRecordSchemaV1, RecordID: "ownership-test-nat", RecordGeneration: 1,
			Identity: identity, ProviderID: observation.ProviderID, DesiredStateFingerprint: observation.DesiredStateFingerprint,
		},
	}
	if err := isolation.ValidatePermanentSingletonOwnership(proof); err != nil {
		t.Fatalf("ValidatePermanentSingletonOwnership(NAT) unexpected error: %v", err)
	}
	proof.Observed.DescriptionFingerprint = strings.Repeat("b", 64)
	if err := isolation.ValidatePermanentSingletonOwnership(proof); !errors.Is(err, isolation.ErrInvalidOwnershipProof) {
		t.Fatalf("invented NAT description error = %v; want ErrInvalidOwnershipProof", err)
	}
}

func TestRunScopedFirewallCannotBecomePermanentSingleton(t *testing.T) {
	t.Parallel()

	proof := validPermanentSingletonProof()
	identity := testResourceIdentity(
		"ctrldb-test-run1-iap-ssh",
		isolation.ComputeFirewallKind,
		isolation.ResourceScopeGlobal,
		"global",
	)
	proof.Desired.Identity = identity
	proof.Observed.Identity = identity
	proof.Record.Identity = identity
	proof.ExpectedIdentity = identity
	if err := isolation.ValidatePermanentSingletonOwnership(proof); !errors.Is(err, isolation.ErrInvalidOwnershipProof) {
		t.Fatalf("ValidatePermanentSingletonOwnership(run firewall) error = %v; want ErrInvalidOwnershipProof", err)
	}
}

func TestOnlyReservedHarnessFirewallsCanBePermanentSingletons(t *testing.T) {
	t.Parallel()

	for _, name := range []string{isolation.TestIAPSSHFirewallName, isolation.TestInternalFirewallName} {
		proof := validPermanentSingletonProof()
		identity := testResourceIdentity(name, isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global")
		proof.Desired.Identity = identity
		proof.Observed.Identity = identity
		proof.Record.Identity = identity
		proof.ExpectedIdentity = identity
		if err := isolation.ValidatePermanentSingletonOwnership(proof); err != nil {
			t.Fatalf("ValidatePermanentSingletonOwnership(%q) unexpected error: %v", name, err)
		}
	}

	proof := validPermanentSingletonProof()
	identity := testResourceIdentity("ctrldb-test-other-firewall", isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global")
	proof.Desired.Identity = identity
	proof.Observed.Identity = identity
	proof.Record.Identity = identity
	proof.ExpectedIdentity = identity
	if err := isolation.ValidatePermanentSingletonOwnership(proof); !errors.Is(err, isolation.ErrInvalidOwnershipProof) {
		t.Fatalf("ValidatePermanentSingletonOwnership(unreserved firewall) error = %v; want ErrInvalidOwnershipProof", err)
	}
}

func TestRunFirewallCleanupRequiresLifetimeDescriptionRecordAndExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	lifetime := validRunLifetimeContract("run1")
	lifetime.CreatedAt = now.Add(-2 * time.Hour)
	lifetime.ExpiresAt = now.Add(-time.Minute)
	fingerprint, err := isolation.RunLifetimeContractFingerprint(lifetime)
	if err != nil {
		t.Fatalf("RunLifetimeContractFingerprint() unexpected error: %v", err)
	}
	description, err := isolation.RunFirewallDescription(fingerprint)
	if err != nil {
		t.Fatalf("RunFirewallDescription() unexpected error: %v", err)
	}
	target := isolation.RunFirewallCleanupTarget{
		Identity:    testResourceIdentity("ctrldb-test-run1-iap-ssh", isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global"),
		Description: description, RunLifetime: lifetime, ObservedAt: now,
	}
	if err := isolation.ValidateRunFirewallCleanupTarget(validCleanupPolicy(), target, isolation.RunFirewallCleanupExpiredWipe, now, 3*time.Hour); err != nil {
		t.Fatalf("ValidateRunFirewallCleanupTarget() unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*isolation.RunFirewallCleanupTarget, *time.Time, *time.Duration)
	}{
		{name: "cross project", mutate: func(value *isolation.RunFirewallCleanupTarget, _ *time.Time, _ *time.Duration) {
			value.Identity = resourceIdentityForProject(value.Identity.Name, isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global", "different-project")
		}},
		{name: "wrong prefix", mutate: func(value *isolation.RunFirewallCleanupTarget, _ *time.Time, _ *time.Duration) {
			value.Identity = testResourceIdentity("ctrldb-test-other-iap-ssh", isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global")
		}},
		{name: "unplanned suffix", mutate: func(value *isolation.RunFirewallCleanupTarget, _ *time.Time, _ *time.Duration) {
			value.Identity = testResourceIdentity("ctrldb-test-run1-unplanned", isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global")
		}},
		{name: "description mismatch", mutate: func(value *isolation.RunFirewallCleanupTarget, _ *time.Time, _ *time.Duration) {
			value.Description = "changed"
		}},
		{name: "not expired", mutate: func(_ *isolation.RunFirewallCleanupTarget, now *time.Time, _ *time.Duration) {
			*now = (*now).Add(-2 * time.Hour)
		}},
		{name: "over lifetime cap", mutate: func(_ *isolation.RunFirewallCleanupTarget, _ *time.Time, maximum *time.Duration) {
			*maximum = time.Hour
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value, boundary, maximum := target, now, 3*time.Hour
			test.mutate(&value, &boundary, &maximum)
			if err := isolation.ValidateRunFirewallCleanupTarget(validCleanupPolicy(), value, isolation.RunFirewallCleanupExpiredWipe, boundary, maximum); !errors.Is(err, isolation.ErrInvalidOwnershipProof) {
				t.Fatalf("error = %v; want ErrInvalidOwnershipProof", err)
			}
		})
	}

	early := target
	early.RunLifetime.ExpiresAt = now.Add(time.Hour)
	earlyFingerprint, err := isolation.RunLifetimeContractFingerprint(early.RunLifetime)
	if err != nil {
		t.Fatalf("RunLifetimeContractFingerprint(early teardown) unexpected error: %v", err)
	}
	early.Description, err = isolation.RunFirewallDescription(earlyFingerprint)
	if err != nil {
		t.Fatalf("RunFirewallDescription(early teardown) unexpected error: %v", err)
	}
	if err := isolation.ValidateRunFirewallCleanupTarget(validCleanupPolicy(), early, isolation.RunFirewallCleanupRecordedTeardown, now, 3*time.Hour); err != nil {
		t.Fatalf("recorded teardown before expiry unexpected error: %v", err)
	}
	if err := isolation.ValidateRunFirewallCleanupTarget(validCleanupPolicy(), early, isolation.RunFirewallCleanupExpiredWipe, now, 3*time.Hour); !errors.Is(err, isolation.ErrInvalidOwnershipProof) {
		t.Fatalf("nightly wipe before expiry error = %v; want ErrInvalidOwnershipProof", err)
	}
	if err := isolation.ValidateRunFirewallCleanupTarget(validCleanupPolicy(), target, "unknown", now, 3*time.Hour); !errors.Is(err, isolation.ErrInvalidOwnershipProof) {
		t.Fatalf("unknown cleanup mode error = %v; want ErrInvalidOwnershipProof", err)
	}
}

func validPermanentSingletonProof() isolation.PermanentSingletonProof {
	identity := testResourceIdentity(isolation.TestVPCName, isolation.ComputeNetworkKind, isolation.ResourceScopeGlobal, "global")
	observation := isolation.PermanentSingletonObservation{
		Identity: identity, ProviderID: "provider-id-1",
		DesiredStateFingerprint: strings.Repeat("a", 64),
		DescriptionFingerprint:  strings.Repeat("b", 64),
	}
	return isolation.PermanentSingletonProof{
		ProjectID: "example-test-project", ExpectedIdentity: identity, Desired: observation, Observed: observation,
		Record: isolation.PermanentOwnershipRecordV1{
			SchemaVersion: isolation.OwnershipRecordSchemaV1,
			RecordID:      "ownership-test-vpc", RecordGeneration: 1,
			Identity: identity, ProviderID: observation.ProviderID,
			DesiredStateFingerprint: observation.DesiredStateFingerprint,
			DescriptionFingerprint:  observation.DescriptionFingerprint,
		},
	}
}

func resourceIdentityForProject(name string, kind isolation.ResourceKind, scope isolation.ResourceScope, location, project string) isolation.ResourceIdentity {
	identity := isolation.ResourceIdentity{
		Project: project, Service: isolation.ComputeServiceName, Kind: kind,
		Scope: scope, Location: location, Name: name,
	}
	identity.CanonicalKey, _ = isolation.CanonicalTargetKey(identity)
	return identity
}
