// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package cleanup_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/cleanup"
)

func TestPlanDispositionsFailClosedUntilHarnessIsUsable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		state   isolation.HarnessStateV1
		history cleanup.History
		want    cleanup.Disposition
	}{
		{name: "first run after bootstrap", state: pendingState(t), history: cleanup.History{}, want: cleanup.DispositionFirstRunObserveOnly},
		{name: "first run even when open", state: openState(t), history: cleanup.History{}, want: cleanup.DispositionFirstRunObserveOnly},
		{name: "pending harness", state: pendingState(t), history: cleanup.History{PriorRuns: 1}, want: cleanup.DispositionHarnessNotUsable},
		{name: "drifted harness", state: driftedState(t), history: cleanup.History{PriorRuns: 1}, want: cleanup.DispositionHarnessNotUsable},
		{name: "open usable harness", state: openState(t), history: cleanup.History{PriorRuns: 1}, want: cleanup.DispositionDelete},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan, err := cleanup.Plan(planInput(t, test.state, test.history))
			if err != nil {
				t.Fatalf("Plan() error = %v", err)
			}
			if plan.Disposition != test.want || !plan.Sealed() || plan.RunNumber != test.history.PriorRuns+1 {
				t.Fatalf("plan disposition = %q run %d sealed %t, want %q", plan.Disposition, plan.RunNumber, plan.Sealed(), test.want)
			}
			if len(plan.Selection.Deletions) != 5 {
				t.Fatalf("every disposition must still record the complete selection, got %d", len(plan.Selection.Deletions))
			}
			journal := &memoryJournal{}
			var deleter cleanup.Deleter = forbiddenDeleter{t: t}
			if test.want == cleanup.DispositionDelete {
				deleter = &scriptedDeleter{t: t}
			}
			result, err := cleanup.Execute(context.Background(), plan, journal, deleter, fixedClock)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if len(journal.plans) != 1 || journal.plans[0].Disposition != test.want || journal.plans[0].RunNumber != plan.RunNumber {
				t.Fatalf("plan record = %+v", journal.plans)
			}
			wantDeleted := 0
			if test.want == cleanup.DispositionDelete {
				wantDeleted = 5
			}
			if result.Deleted != wantDeleted || result.Failed != 0 || result.Planned != 5 || result.Retained != 3 || result.Protected != 2 {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestPlanReportsNothingExpiredForCleanUsableHarness(t *testing.T) {
	t.Parallel()
	input := planInput(t, openState(t), cleanup.History{PriorRuns: 4})
	input.Inventory.Instances = input.Inventory.Instances[1:]
	input.Inventory.Disks = input.Inventory.Disks[2:]
	input.Inventory.Firewalls = append(input.Inventory.Firewalls[:2], input.Inventory.Firewalls[4:]...)
	plan, err := cleanup.Plan(input)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.Disposition != cleanup.DispositionNothingExpired || len(plan.Selection.Deletions) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestPlanRejectsForeignOrTamperedInputs(t *testing.T) {
	t.Parallel()
	input := planInput(t, openState(t), cleanup.History{PriorRuns: 1})
	input.Policy.ProjectID = "another-project-7"
	input.Inventory.ProjectID = "another-project-7"
	if _, err := cleanup.Plan(input); !errors.Is(err, cleanup.ErrInvalidWipeInput) {
		t.Fatalf("cross-project state error = %v", err)
	}
	if _, err := cleanup.Plan(cleanup.PlanInput{Policy: testPolicy(), Now: testNow}); !errors.Is(err, cleanup.ErrInvalidWipeInput) {
		t.Fatalf("zero state error = %v", err)
	}
	broken := planInput(t, openState(t), cleanup.History{PriorRuns: 1})
	broken.Inventory.Exhaustive = false
	if _, err := cleanup.Plan(broken); !errors.Is(err, cleanup.ErrInventoryRefused) {
		t.Fatalf("non-exhaustive inventory error = %v", err)
	}
	duplicated := planInput(t, openState(t), cleanup.History{PriorRuns: 1, Outstanding: []cleanup.OutstandingDeletion{{CanonicalKey: "k", Attempts: 1}, {CanonicalKey: "k", Attempts: 2}}})
	if _, err := cleanup.Plan(duplicated); !errors.Is(err, cleanup.ErrInvalidWipeInput) {
		t.Fatalf("duplicate outstanding error = %v", err)
	}

	plan, err := cleanup.Plan(planInput(t, openState(t), cleanup.History{PriorRuns: 1}))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	tampered := plan
	tampered.Disposition = cleanup.DispositionDelete
	tampered.Selection.Deletions = append([]cleanup.Deletion(nil), plan.Selection.Deletions...)
	tampered.Selection.Deletions[0].Identity.Name = "ctrldb-prod-db-1"
	if tampered.Sealed() {
		t.Fatal("tampered plan must not be sealed")
	}
	journal := &memoryJournal{}
	if _, err := cleanup.Execute(context.Background(), tampered, journal, forbiddenDeleter{t: t}, fixedClock); !errors.Is(err, cleanup.ErrInvalidWipeInput) {
		t.Fatalf("tampered Execute() error = %v", err)
	}
	if len(journal.plans) != 0 {
		t.Fatal("a tampered plan must not be recorded")
	}
	if _, err := cleanup.Execute(context.Background(), plan, journal, nil, fixedClock); !errors.Is(err, cleanup.ErrInvalidWipeInput) {
		t.Fatalf("nil deleter error = %v", err)
	}
	if _, err := cleanup.Execute(context.Background(), plan, &memoryJournal{failPlan: true}, forbiddenDeleter{t: t}, fixedClock); !errors.Is(err, cleanup.ErrWipeExecution) {
		t.Fatalf("unrecorded plan error = %v", err)
	}
}

func TestExecuteRecordsBeforeIssuingAndConvergesAfterPartialFailure(t *testing.T) {
	t.Parallel()
	plan, err := cleanup.Plan(planInput(t, openState(t), cleanup.History{PriorRuns: 2}))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	journal := &memoryJournal{}
	deleter := &scriptedDeleter{t: t, failAt: 2}
	result, err := cleanup.Execute(context.Background(), plan, journal, deleter, fixedClock)
	if !errors.Is(err, cleanup.ErrWipeExecution) {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Deleted != 1 || result.Failed != 1 || len(result.Deletions) != 2 || len(deleter.calls) != 2 {
		t.Fatalf("result = %+v calls = %d", result, len(deleter.calls))
	}
	if result.Deletions[1].Status != cleanup.DeletionFailed || result.Deletions[1].Failure.String() == "" {
		t.Fatalf("failed outcome = %+v", result.Deletions[1])
	}
	statuses := make([]string, 0, len(journal.deletions))
	for _, record := range journal.deletions {
		if record.PlanIntegrity != journal.plans[0].IntegritySHA256 || !strings.HasPrefix(record.SchemaVersion, "ctrldb.ctrlboard.dev/") || record.IntegritySHA256 == "" {
			t.Fatalf("deletion record = %+v", record)
		}
		statuses = append(statuses, string(record.Status)+":"+record.Deletion.Name)
	}
	want := []string{
		"issued:ctrldb-test-run-0a1b-node", "deleted:ctrldb-test-run-0a1b-node",
		"issued:ctrldb-test-run-0a1b-data", "failed:ctrldb-test-run-0a1b-data",
	}
	if !slices.Equal(statuses, want) {
		t.Fatalf("deletion records = %v, want %v", statuses, want)
	}

	// The next run observes the instance gone and retries the failed disk as
	// attempt two while the untouched resources start at attempt one.
	retry := planInput(t, openState(t), cleanup.History{PriorRuns: 3, Outstanding: []cleanup.OutstandingDeletion{
		{CanonicalKey: plan.Selection.Deletions[1].Identity.CanonicalKey, Attempts: 1},
	}})
	retry.Inventory.Instances = retry.Inventory.Instances[1:]
	for index := range retry.Inventory.Disks[:2] {
		retry.Inventory.Disks[index].AttachedInstances = nil
	}
	retryPlan, err := cleanup.Plan(retry)
	if err != nil {
		t.Fatalf("retry Plan() error = %v", err)
	}
	wantNames := []string{
		"compute.disks:ctrldb-test-run-0a1b-data", "compute.disks:ctrldb-test-run-0a1b-node",
		"compute.firewalls:ctrldb-test-run-0a1b-iap-ssh", "compute.firewalls:ctrldb-test-run-0a1b-internal",
	}
	if got := deletionNames(retryPlan.Selection.Deletions); !slices.Equal(got, wantNames) {
		t.Fatalf("retry deletions = %v, want %v", got, wantNames)
	}
	if retryPlan.Selection.Deletions[0].Attempt != 2 || retryPlan.Selection.Deletions[1].Attempt != 1 {
		t.Fatalf("retry attempts = %d, %d", retryPlan.Selection.Deletions[0].Attempt, retryPlan.Selection.Deletions[1].Attempt)
	}
	retryJournal := &memoryJournal{}
	retryDeleter := &scriptedDeleter{t: t}
	retryResult, err := cleanup.Execute(context.Background(), retryPlan, retryJournal, retryDeleter, fixedClock)
	if err != nil || retryResult.Deleted != 4 || retryResult.Failed != 0 {
		t.Fatalf("retry Execute() = %+v, %v", retryResult, err)
	}
}

func TestExecuteStopsWhenContextIsCanceled(t *testing.T) {
	t.Parallel()
	plan, err := cleanup.Plan(planInput(t, openState(t), cleanup.History{PriorRuns: 1}))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	journal := &memoryJournal{}
	result, err := cleanup.Execute(ctx, plan, journal, forbiddenDeleter{t: t}, fixedClock)
	if !errors.Is(err, cleanup.ErrWipeExecution) || result.Deleted != 0 || len(journal.deletions) != 0 {
		t.Fatalf("canceled Execute() = %+v, %v, records %d", result, err, len(journal.deletions))
	}
}

func TestWipeRecordRoundTripsCanonicallyAndRejectsTampering(t *testing.T) {
	t.Parallel()
	plan, err := cleanup.Plan(planInput(t, openState(t), cleanup.History{PriorRuns: 1}))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	record, err := plan.Record()
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	encoded, err := record.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	parsed, err := cleanup.ParseWipeRecordV1(encoded)
	if err != nil {
		t.Fatalf("ParseWipeRecordV1() error = %v", err)
	}
	again, err := parsed.CanonicalJSON()
	if err != nil || !bytes.Equal(again, encoded) {
		t.Fatalf("round trip changed the record: %v", err)
	}
	if bytes.Contains(encoded, []byte("seal")) {
		t.Fatal("the durable record must not carry the in-memory seal")
	}
	for name, input := range map[string][]byte{
		"tampered name":   bytes.Replace(encoded, []byte("ctrldb-test-run-0a1b-node"), []byte("ctrldb-prod-db-1"), 1),
		"trailing data":   append(append([]byte(nil), encoded...), '{', '}'),
		"unknown field":   bytes.Replace(encoded, []byte(`"mode":`), []byte(`"extra":1,"mode":`), 1),
		"blank integrity": bytes.Replace(encoded, []byte(record.IntegritySHA256), []byte(strings.Repeat("0", 64)), 1),
	} {
		if _, err := cleanup.ParseWipeRecordV1(input); !errors.Is(err, cleanup.ErrInvalidWipeRecord) {
			t.Fatalf("%s: error = %v", name, err)
		}
	}
}
