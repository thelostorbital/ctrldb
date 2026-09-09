// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package cleanup_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/cleanup"
)

const (
	testProject  = "example-test-project"
	testZone     = "us-central1-a"
	testRunID    = "run-0a1b"
	otherRunID   = "run-9z8y"
	testLifetime = 6 * time.Hour
)

var (
	testNow      = time.Date(2026, 9, 9, 20, 0, 0, 0, time.UTC)
	testRevision = strings.Repeat("d", 64)
)

func identity(t *testing.T, kind isolation.ResourceKind, scope isolation.ResourceScope, location, name string) isolation.ResourceIdentity {
	t.Helper()
	value := isolation.ResourceIdentity{
		Project: testProject, Service: isolation.ComputeServiceName, Kind: kind, Scope: scope, Location: location, Name: name,
	}
	key, err := isolation.CanonicalTargetKey(value)
	if err != nil {
		t.Fatalf("CanonicalTargetKey(%q) error = %v", name, err)
	}
	value.CanonicalKey = key
	return value
}

func instanceIdentity(t *testing.T, name string) isolation.ResourceIdentity {
	t.Helper()
	return identity(t, isolation.ComputeInstanceKind, isolation.ResourceScopeZone, testZone, name)
}

func diskIdentity(t *testing.T, name string) isolation.ResourceIdentity {
	t.Helper()
	return identity(t, isolation.ComputeDiskKind, isolation.ResourceScopeZone, testZone, name)
}

func firewallIdentity(t *testing.T, name string) isolation.ResourceIdentity {
	t.Helper()
	return identity(t, isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global", name)
}

func runLabels(runID string) map[string]string {
	return map[string]string{
		config.LabelManagedBy: config.LabelManagedByValue, config.LabelEnvironment: config.TestEnvironmentLabel,
		config.LabelPurpose: config.TestResourcePurposeLabel, isolation.LabelRunID: runID,
	}
}

func testPolicy() cleanup.WipePolicy {
	return cleanup.WipePolicy{ProjectID: testProject, MaxLifetime: testLifetime}
}

func expiredAt() time.Time { return testNow.Add(-testLifetime - time.Hour) }
func freshAt() time.Time   { return testNow.Add(-time.Hour) }

func lifetimeRecord(t *testing.T, runID string, createdAt, expiresAt time.Time) cleanup.LifetimeRecord {
	t.Helper()
	contract := isolation.RunLifetimeContract{
		ProjectID: testProject, RunID: runID,
		Plan:        isolation.PlanIdentity{ID: "plan-0123456789abcdef", Hash: strings.Repeat("b", 64)},
		OperationID: "op-0123456789abcdef", RecordID: "lifetime-0123456789abcdef", RecordGeneration: 3,
		CreatedAt: createdAt, ExpiresAt: expiresAt, RevocationWorkflowID: isolation.TestHarnessRevocationWorkflowID,
	}
	fingerprint, err := isolation.RunLifetimeContractFingerprint(contract)
	if err != nil {
		t.Fatalf("RunLifetimeContractFingerprint() error = %v", err)
	}
	return cleanup.LifetimeRecord{Contract: contract, Expected: isolation.OwnershipRecordExpectation{
		RecordID: contract.RecordID, RecordGeneration: contract.RecordGeneration, Revision: fingerprint,
		ObservedAt: testNow.Add(-time.Minute), ValidUntil: testNow.Add(time.Minute),
	}}
}

func firewallDescription(t *testing.T, record cleanup.LifetimeRecord) string {
	t.Helper()
	description, err := isolation.RunFirewallDescription(record.Expected.Revision)
	if err != nil {
		t.Fatalf("RunFirewallDescription() error = %v", err)
	}
	return description
}

func runFirewallName(t *testing.T, runID string, purpose isolation.FirewallPurpose) string {
	t.Helper()
	name, err := isolation.RunFirewallRuleName(runID, purpose)
	if err != nil {
		t.Fatalf("RunFirewallRuleName() error = %v", err)
	}
	return name
}

// fullInventory contains one expired run (instance, attached data disk, two
// firewall rules), one fresh run, one foreign instance, and both permanent
// harness firewall rules.
func fullInventory(t *testing.T) (cleanup.Inventory, []cleanup.LifetimeRecord) {
	t.Helper()
	expiredRecord := lifetimeRecord(t, testRunID, expiredAt(), expiredAt().Add(testLifetime))
	freshRecord := lifetimeRecord(t, otherRunID, freshAt(), freshAt().Add(testLifetime))
	inventory := cleanup.Inventory{
		ProjectID: testProject, Revision: testRevision, ObservedAt: testNow.Add(-time.Minute), ValidUntil: testNow.Add(time.Minute), Exhaustive: true,
		Instances: []cleanup.InstanceObservation{
			{Identity: instanceIdentity(t, "ctrldb-test-run-0a1b-node"), Labels: runLabels(testRunID), CreatedAt: expiredAt(), AttachedDisks: []string{"ctrldb-test-run-0a1b-node", "ctrldb-test-run-0a1b-data"}},
			{Identity: instanceIdentity(t, "ctrldb-test-run-9z8y-node"), Labels: runLabels(otherRunID), CreatedAt: freshAt()},
			{Identity: instanceIdentity(t, "billing-web-1"), Labels: map[string]string{"team": "web"}, CreatedAt: expiredAt()},
		},
		Disks: []cleanup.DiskObservation{
			{Identity: diskIdentity(t, "ctrldb-test-run-0a1b-node"), Labels: runLabels(testRunID), CreatedAt: expiredAt(), AttachedInstances: []string{"ctrldb-test-run-0a1b-node"}},
			{Identity: diskIdentity(t, "ctrldb-test-run-0a1b-data"), Labels: runLabels(testRunID), CreatedAt: expiredAt(), AttachedInstances: []string{"ctrldb-test-run-0a1b-node"}},
			{Identity: diskIdentity(t, "ctrldb-test-run-9z8y-node"), Labels: runLabels(otherRunID), CreatedAt: freshAt(), AttachedInstances: []string{"ctrldb-test-run-9z8y-node"}},
		},
		Firewalls: []cleanup.FirewallObservation{
			{Identity: firewallIdentity(t, isolation.TestIAPSSHFirewallName), Description: "ctrldb:permanent", CreatedAt: expiredAt()},
			{Identity: firewallIdentity(t, isolation.TestInternalFirewallName), Description: "ctrldb:permanent", CreatedAt: expiredAt()},
			{Identity: firewallIdentity(t, runFirewallName(t, testRunID, isolation.FirewallPurposeInternalMongo)), Description: firewallDescription(t, expiredRecord), CreatedAt: expiredAt()},
			{Identity: firewallIdentity(t, runFirewallName(t, testRunID, isolation.FirewallPurposeIAPSSH)), Description: firewallDescription(t, expiredRecord), CreatedAt: expiredAt()},
			{Identity: firewallIdentity(t, runFirewallName(t, otherRunID, isolation.FirewallPurposeIAPSSH)), Description: firewallDescription(t, freshRecord), CreatedAt: freshAt()},
			{Identity: firewallIdentity(t, "default-allow-internal"), Description: "", CreatedAt: expiredAt()},
		},
	}
	return inventory, []cleanup.LifetimeRecord{expiredRecord, freshRecord}
}

func harnessSeed() isolation.HarnessStateSeed {
	approvedAt := testNow.Add(-24 * time.Hour)
	return isolation.HarnessStateSeed{
		ProjectID: testProject, Environment: "disposable-test", EnvironmentClass: "disposable",
		ManifestHash: strings.Repeat("a", 64),
		ApprovedPlan: isolation.PlanIdentity{ID: "plan-0123456789abcdef", Hash: strings.Repeat("b", 64)},
		OperationID:  "op-0123456789abcdef", BootstrapEnvelopeHash: strings.Repeat("c", 64),
		ControlRecordGeneration: 1,
		Resources: isolation.HarnessResourceFingerprints{
			Network: strings.Repeat("1", 64), RoleBindings: strings.Repeat("2", 64),
			ServiceAccounts: strings.Repeat("3", 64), WipeJob: strings.Repeat("4", 64),
			Scheduler: strings.Repeat("5", 64), Image: strings.Repeat("6", 64),
		},
		CleanupCapabilities: isolation.InitialCleanupCapabilities(),
		BootstrapSteps:      []string{"k1-audit-bootstrap", "t7-nightly-wipe", "t8-isolation-gate"},
		RollbackSteps:       []string{"t7-nightly-wipe"},
		ApprovedAt:          approvedAt, ApprovalValidUntil: approvedAt.Add(48 * time.Hour),
	}
}

func pendingState(t *testing.T) isolation.HarnessStateV1 {
	t.Helper()
	state, err := isolation.NewPendingHarnessStateV1(harnessSeed())
	if err != nil {
		t.Fatalf("NewPendingHarnessStateV1() error = %v", err)
	}
	return state
}

func openState(t *testing.T) isolation.HarnessStateV1 {
	t.Helper()
	openedAt := testNow.Add(-12 * time.Hour)
	state, err := pendingState(t).OpenAfterT8(isolation.T8Evidence{
		Revision: strings.Repeat("e", 64), ObservedAt: openedAt, ValidUntil: openedAt.Add(30 * time.Minute),
	}, openedAt)
	if err != nil {
		t.Fatalf("OpenAfterT8() error = %v", err)
	}
	return state
}

func driftedState(t *testing.T) isolation.HarnessStateV1 {
	t.Helper()
	state, err := openState(t).MarkTestsUnusable(isolation.HarnessDriftEvidence{Revision: strings.Repeat("f", 64), DetectedAt: testNow.Add(-6 * time.Hour)})
	if err != nil {
		t.Fatalf("MarkTestsUnusable() error = %v", err)
	}
	return state
}

func planInput(t *testing.T, state isolation.HarnessStateV1, history cleanup.History) cleanup.PlanInput {
	t.Helper()
	inventory, records := fullInventory(t)
	return cleanup.PlanInput{Policy: testPolicy(), State: state, Inventory: inventory, LifetimeRecords: records, History: history, Now: testNow}
}

type memoryJournal struct {
	mu        sync.Mutex
	plans     []cleanup.WipeRecordV1
	deletions []cleanup.DeletionRecordV1
	failPlan  bool
}

func (journal *memoryJournal) RecordPlan(_ context.Context, record cleanup.WipeRecordV1) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.failPlan {
		return context.DeadlineExceeded
	}
	journal.plans = append(journal.plans, record)
	return nil
}

func (journal *memoryJournal) RecordDeletion(_ context.Context, record cleanup.DeletionRecordV1) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	journal.deletions = append(journal.deletions, record)
	return nil
}

type scriptedDeleter struct {
	t      *testing.T
	failAt int
	calls  []cleanup.Deletion
}

func (deleter *scriptedDeleter) Delete(_ context.Context, deletion cleanup.Deletion) error {
	deleter.t.Helper()
	if !deletion.Sealed() {
		deleter.t.Fatal("deleter received an unsealed deletion")
	}
	deleter.calls = append(deleter.calls, deletion)
	if deleter.failAt != 0 && deletion.Sequence == deleter.failAt {
		return context.DeadlineExceeded
	}
	return nil
}

type forbiddenDeleter struct{ t *testing.T }

func (deleter forbiddenDeleter) Delete(context.Context, cleanup.Deletion) error {
	deleter.t.Helper()
	deleter.t.Fatal("deleter must not be called")
	return nil
}

func fixedClock() time.Time { return testNow.Add(time.Second) }

func deletionNames(deletions []cleanup.Deletion) []string {
	names := make([]string, len(deletions))
	for index, deletion := range deletions {
		names[index] = string(deletion.Capability) + ":" + deletion.Identity.Name
	}
	return names
}
