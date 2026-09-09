// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package cleanup_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/cleanup"
)

func TestSelectOrdersOwnedExpiredResourcesAndSealsThem(t *testing.T) {
	t.Parallel()
	inventory, records := fullInventory(t)
	selection, err := cleanup.Select(testPolicy(), isolation.InitialCleanupCapabilities(), inventory, records, testNow)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	want := []string{
		"compute.instances:ctrldb-test-run-0a1b-node",
		"compute.disks:ctrldb-test-run-0a1b-data",
		"compute.disks:ctrldb-test-run-0a1b-node",
		"compute.firewalls:ctrldb-test-run-0a1b-iap-ssh",
		"compute.firewalls:ctrldb-test-run-0a1b-internal",
	}
	if got := deletionNames(selection.Deletions); !slices.Equal(got, want) {
		t.Fatalf("deletions = %v, want %v", got, want)
	}
	for index, deletion := range selection.Deletions {
		if deletion.Sequence != index+1 || !deletion.Sealed() || deletion.RunID != testRunID {
			t.Fatalf("deletion %d = %+v", index, deletion)
		}
		if deletion.Capability == isolation.CleanupComputeInstances && !deletion.KeepDisks {
			t.Fatalf("instance deletion must retain disks: %+v", deletion)
		}
		if deletion.Capability != isolation.CleanupComputeInstances && deletion.KeepDisks {
			t.Fatalf("only instances carry retained-disk semantics: %+v", deletion)
		}
	}
	if selection.Ignored != 2 || len(selection.Protected) != 2 || len(selection.Retained) != 3 || len(selection.Deferred) != 0 {
		t.Fatalf("selection accounting = ignored %d protected %d retained %d deferred %d", selection.Ignored, len(selection.Protected), len(selection.Retained), len(selection.Deferred))
	}
	tampered := selection.Deletions[0]
	tampered.Identity.Name = "ctrldb-test-run-0a1b-other"
	if tampered.Sealed() {
		t.Fatal("a modified deletion must not remain sealed")
	}
	if (cleanup.Deletion{Sequence: 1}).Sealed() {
		t.Fatal("a caller-constructed deletion must not be sealed")
	}
}

func TestSelectHonorsExactMaxLifetimeBoundary(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		age      time.Duration
		selected bool
	}{
		{name: "exactly max lifetime", age: testLifetime, selected: true},
		{name: "one second younger", age: testLifetime - time.Second, selected: false},
		{name: "one second older", age: testLifetime + time.Second, selected: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			inventory := cleanup.Inventory{
				ProjectID: testProject, Revision: testRevision, ObservedAt: testNow.Add(-time.Minute), ValidUntil: testNow.Add(time.Minute), Exhaustive: true,
				Instances: []cleanup.InstanceObservation{{Identity: instanceIdentity(t, "ctrldb-test-run-0a1b-node"), Labels: runLabels(testRunID), CreatedAt: testNow.Add(-test.age)}},
			}
			selection, err := cleanup.Select(testPolicy(), isolation.InitialCleanupCapabilities(), inventory, nil, testNow)
			if err != nil {
				t.Fatalf("Select() error = %v", err)
			}
			if (len(selection.Deletions) == 1) != test.selected || (len(selection.Retained) == 1) == test.selected {
				t.Fatalf("deletions = %d retained = %d, want selected = %t", len(selection.Deletions), len(selection.Retained), test.selected)
			}
		})
	}
}

func TestSelectDefersExpiredDiskAttachedToUnselectedInstance(t *testing.T) {
	t.Parallel()
	inventory := cleanup.Inventory{
		ProjectID: testProject, Revision: testRevision, ObservedAt: testNow.Add(-time.Minute), ValidUntil: testNow.Add(time.Minute), Exhaustive: true,
		Instances: []cleanup.InstanceObservation{{Identity: instanceIdentity(t, "ctrldb-test-run-9z8y-node"), Labels: runLabels(otherRunID), CreatedAt: freshAt()}},
		Disks: []cleanup.DiskObservation{{
			Identity: diskIdentity(t, "ctrldb-test-run-0a1b-data"), Labels: runLabels(testRunID), CreatedAt: expiredAt(),
			AttachedInstances: []string{"ctrldb-test-run-9z8y-node"},
		}},
	}
	selection, err := cleanup.Select(testPolicy(), isolation.InitialCleanupCapabilities(), inventory, nil, testNow)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if len(selection.Deletions) != 0 || len(selection.Deferred) != 1 || !slices.Equal(selection.Deferred[0].BlockedBy, []string{"ctrldb-test-run-9z8y-node"}) {
		t.Fatalf("deletions = %v deferred = %+v", selection.Deletions, selection.Deferred)
	}
}

func TestSelectRefusesEveryAmbiguousOrUnsafeInventory(t *testing.T) {
	t.Parallel()
	fresh := func(t *testing.T) cleanup.Inventory {
		t.Helper()
		inventory, _ := fullInventory(t)
		return inventory
	}
	foreignProject := func(t *testing.T) isolation.ResourceIdentity {
		t.Helper()
		value := instanceIdentity(t, "ctrldb-test-run-0a1b-node")
		value.Project = "foreign-project-42"
		key, err := isolation.CanonicalTargetKey(value)
		if err != nil {
			t.Fatalf("CanonicalTargetKey() error = %v", err)
		}
		value.CanonicalKey = key
		return value
	}
	tests := []struct {
		name    string
		mutate  func(t *testing.T, inventory *cleanup.Inventory, records *[]cleanup.LifetimeRecord, policy *cleanup.WipePolicy)
		wantErr error
	}{
		{name: "prefix without labels", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Instances[0].Labels = map[string]string{config.LabelManagedBy: config.LabelManagedByValue}
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "labels without prefix", mutate: func(t *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Instances[2] = cleanup.InstanceObservation{Identity: instanceIdentity(t, "ctrldb-prod-node"), Labels: runLabels(testRunID), CreatedAt: expiredAt()}
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "missing run-id label", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			delete(inventory.Instances[0].Labels, isolation.LabelRunID)
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "run-id label not binding name", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Instances[0].Labels[isolation.LabelRunID] = otherRunID
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "production environment label on prefixed disk", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Disks[0].Labels[config.LabelEnvironment] = "production"
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "cross-project candidate", mutate: func(t *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Instances[0].Identity = foreignProject(t)
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "cross-project inventory", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.ProjectID = "foreign-project-42"
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "non-exhaustive inventory", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Exhaustive = false
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "stale inventory", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.ObservedAt, inventory.ValidUntil = testNow.Add(-3*time.Minute), testNow.Add(-time.Minute)
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "overlong inventory window", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.ValidUntil = inventory.ObservedAt.Add(cleanup.MaxInventoryLifetime + time.Second)
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "unsupported kind present", mutate: func(t *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Unsupported = []cleanup.UnsupportedObservation{{Identity: identity(t, "snapshots", isolation.ResourceScopeGlobal, "global", "ctrldb-test-run-0a1b-snap")}}
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "duplicate identity", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Instances = append(inventory.Instances, inventory.Instances[0])
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "disk listed as instance", mutate: func(t *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Instances[0].Identity = diskIdentity(t, "ctrldb-test-run-0a1b-node-x")
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "canonical key mismatch", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Instances[0].Identity.CanonicalKey = strings.Repeat("x", 12)
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "future creation time", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Disks[0].CreatedAt = testNow.Add(time.Minute)
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "run firewall without lifetime record", mutate: func(_ *testing.T, _ *cleanup.Inventory, records *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			*records = (*records)[1:]
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "run firewall description drift", mutate: func(_ *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Firewalls[2].Description = "ctrldb:test-isolation:lifetime-sha256=" + strings.Repeat("0", 64) + ";revoke=WF-TEST-01"
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "unrecorded test-namespace firewall", mutate: func(t *testing.T, inventory *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			inventory.Firewalls = append(inventory.Firewalls, cleanup.FirewallObservation{Identity: firewallIdentity(t, "ctrldb-test-manual-rule"), CreatedAt: expiredAt()})
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "lifetime record beyond max lifetime", mutate: func(t *testing.T, inventory *cleanup.Inventory, records *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			(*records)[0] = lifetimeRecord(t, testRunID, expiredAt(), expiredAt().Add(testLifetime+time.Second))
			inventory.Firewalls[2].Description = firewallDescription(t, (*records)[0])
			inventory.Firewalls[3].Description = firewallDescription(t, (*records)[0])
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "stale lifetime record observation", mutate: func(_ *testing.T, _ *cleanup.Inventory, records *[]cleanup.LifetimeRecord, _ *cleanup.WipePolicy) {
			(*records)[0].Expected.ObservedAt = testNow.Add(-10 * time.Minute)
			(*records)[0].Expected.ValidUntil = testNow.Add(-6 * time.Minute)
		}, wantErr: cleanup.ErrInventoryRefused},
		{name: "wrong project policy", mutate: func(_ *testing.T, _ *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, policy *cleanup.WipePolicy) {
			policy.ProjectID = "Example Project"
		}, wantErr: cleanup.ErrInvalidWipeInput},
		{name: "max lifetime too small", mutate: func(_ *testing.T, _ *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, policy *cleanup.WipePolicy) {
			policy.MaxLifetime = cleanup.MinWipeLifetime - time.Second
		}, wantErr: cleanup.ErrInvalidWipeInput},
		{name: "max lifetime too large", mutate: func(_ *testing.T, _ *cleanup.Inventory, _ *[]cleanup.LifetimeRecord, policy *cleanup.WipePolicy) {
			policy.MaxLifetime = cleanup.MaxWipeLifetime + time.Second
		}, wantErr: cleanup.ErrInvalidWipeInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			inventory, records := fullInventory(t)
			policy := testPolicy()
			test.mutate(t, &inventory, &records, &policy)
			selection, err := cleanup.Select(policy, isolation.InitialCleanupCapabilities(), inventory, records, testNow)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Select() error = %v, want %v", err, test.wantErr)
			}
			if len(selection.Deletions) != 0 {
				t.Fatalf("a refused inventory must select nothing: %v", selection.Deletions)
			}
		})
	}
	if _, err := cleanup.Select(testPolicy(), []isolation.CleanupCapability{isolation.CleanupComputeInstances}, fresh(t), nil, testNow); !errors.Is(err, cleanup.ErrInvalidWipeInput) {
		t.Fatalf("partial capability set error = %v", err)
	}
	if _, err := cleanup.Select(testPolicy(), isolation.InitialCleanupCapabilities(), fresh(t), nil, testNow.In(time.FixedZone("x", 3600))); !errors.Is(err, cleanup.ErrInvalidWipeInput) {
		t.Fatalf("non-UTC clock error = %v", err)
	}
}

func TestSelectNeverTargetsPermanentOrForeignResources(t *testing.T) {
	t.Parallel()
	inventory := cleanup.Inventory{
		ProjectID: testProject, Revision: testRevision, ObservedAt: testNow.Add(-time.Minute), ValidUntil: testNow.Add(time.Minute), Exhaustive: true,
		Instances: []cleanup.InstanceObservation{
			{Identity: instanceIdentity(t, "ctrldb-prod-db-1"), Labels: map[string]string{config.LabelManagedBy: config.LabelManagedByValue, config.LabelEnvironment: "production"}, CreatedAt: expiredAt()},
			{Identity: instanceIdentity(t, "ctrldb-rst-rehearsal"), Labels: map[string]string{config.LabelManagedBy: config.LabelManagedByValue, config.LabelEnvironment: "production"}, CreatedAt: expiredAt()},
		},
		Firewalls: []cleanup.FirewallObservation{
			{Identity: firewallIdentity(t, isolation.TestIAPSSHFirewallName), CreatedAt: expiredAt()},
			{Identity: firewallIdentity(t, isolation.TestInternalFirewallName), CreatedAt: expiredAt()},
			{Identity: firewallIdentity(t, "ctrldb-prod-lease-abc"), CreatedAt: expiredAt()},
		},
	}
	selection, err := cleanup.Select(testPolicy(), isolation.InitialCleanupCapabilities(), inventory, nil, testNow)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if len(selection.Deletions) != 0 || len(selection.Protected) != 2 || selection.Ignored != 3 {
		t.Fatalf("selection = %+v", selection)
	}
}
